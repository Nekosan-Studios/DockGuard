# DockGuard Architecture

## Overview

DockGuard is a fullstack web application that runs as a single Docker container. The backend is a Python FastAPI service; the frontend is a SvelteKit SSR application. Both run inside the container under supervisord.

```
┌─────────────────────────────────────────────────────────┐
│  Docker container (supervisord)                         │
│                                                         │
│  ┌──────────────────┐    ┌──────────────────────────┐  │
│  │  SvelteKit SSR   │    │  FastAPI backend          │  │
│  │  :8764           │───▶│  :8765                   │  │
│  └──────────────────┘    └──────────┬───────────────┘  │
│                                     │                   │
│                          ┌──────────┼───────────────┐  │
│                          │          │               │   │
│                   [Scheduler]  [Routers]      [SQLite]  │
│                          │                             │  │
│               ┌──────────┼──────────┐                  │
│               │          │          │                   │
│        [docker_watcher] [grype]  [vex_discovery]        │
└─────────────────────────────────────────────────────────┘
         │                    │
         ▼                    ▼
  /var/run/docker.sock    Grype binary
  (host Docker daemon)    (bundled in image)
```

## Components

### Scheduler (`scheduler.py`)

The heart of DockGuard's automation. Built on APScheduler, it runs two recurring jobs:

- **Container polling** (default: every 60s) — calls `docker_watcher` to get the list of running containers, compares image digests against an in-memory set of already-seen digests, and queues a Grype scan for anything new or updated.
- **Grype DB check** (default: every hour) — runs `grype db check`. If a newer vulnerability database is available, it clears the seen-digest set so every image is rescanned against fresh data.
- **Data purge** — periodically removes old scans and tasks beyond the retention window.

On startup, the scheduler bootstraps its `seen_digests` set from the database so it doesn't rescan images that were already scanned before a restart.

### Docker Watcher (`docker_watcher.py`)

A thin wrapper around the Docker SDK. Provides two methods:

- `list_images()` — all images on the host
- `list_running_containers()` — containers currently running, with their image name, digest, and container name

Handles Docker unavailability gracefully (e.g. socket not accessible).

### Grype Scanner (`grype_scanner.py`)

Invokes the `grype` binary as a subprocess (`grype <image> -o json -q`), parses the JSON output, and persists results to the database. Each scan produces one `Scan` row and N `Vulnerability` rows.

Scan deduplication is digest-based: if the image digest hasn't changed, the image is skipped. This means updating `nginx:latest` — which changes its digest — triggers a rescan even though the tag name is the same.

After each scan, calls `vex_discovery` to check for VEX attestations and mark any suppressed vulnerabilities.

### VEX Discovery (`vex_discovery.py`)

Queries the OCI registry for VEX attestations attached to the scanned image's digest. If an image publisher has published a VEX document marking a CVE as not exploitable, DockGuard flags the matching vulnerability records so the dashboard can surface or suppress them.

Supports Docker Hub, GHCR, and any registry that supports OCI image referrers. Uses Docker credential helpers for authenticated registries.

### Routers (`routers/`)

FastAPI routers, one per domain. All read from the database and return JSON.

- `containers.py` — dashboard summary stats and recent activity feed
- `vulnerabilities.py` — vulnerability queries (per-image, across running containers, counts)
- `tasks.py` — background task status (recent + scheduled)
- `settings.py` — configuration (read + update)
- `internal.py` — raw DB table access for debugging

### Frontend (`frontend/`)

SvelteKit with server-side rendering. Server-side `load()` functions fetch from the FastAPI backend. Client-side interactions use SvelteKit API routes (`/api/*`) as a proxy to the backend. UI is built with shadcn-svelte components.

Routes: Dashboard, Containers, Vulnerabilities, Tasks, Settings.

## Data Model

```
Scan
  id
  image_name          # e.g. "nginx:latest"
  image_digest        # sha256:... — primary dedup key
  image_repository    # e.g. "nginx" (registry + repo, no tag)
  container_name      # name of the running container, if applicable
  scanned_at
  vulnerability_count
  is_distro_eol       # whether the base OS is end-of-life
    │
    └─▶ Vulnerability (one per CVE finding)
          id
          scan_id
          cve_id
          severity           # CRITICAL / HIGH / MEDIUM / LOW / NEGLIGIBLE
          cvss_base_score
          cvss_vector
          epss_score         # exploit probability (0.0–1.0)
          is_kev             # CISA Known Exploited Vulnerability
          match_type         # how Grype matched this (e.g. exact-direct-dependency)
          package_name
          package_version
          fixed_in_version
          description
          urls               # comma-separated advisory URLs
          cwes               # comma-separated CWE IDs
          locations          # comma-separated file paths where the package was found
          first_seen_at      # when this CVE was first seen across all scans
          vex_status         # VEX annotation status (not_affected, etc.)
          vex_justification

SystemTask             # background task records (scan jobs, DB updates)
Setting                # persistent key/value config (overrideable by env var)
AppState               # app-wide state (last Grype DB check, schema version)
```

## Key Design Decisions

### Single container via supervisord
Both the SvelteKit SSR server and the FastAPI backend run inside one Docker container, orchestrated by supervisord. This makes deployment a single `docker compose up -d` with no external dependencies. The tradeoff is that the two processes share a lifecycle and cannot be scaled independently.

### SQLite by default
SQLite is the only supported database. It requires zero configuration, stores data in a single file that's easy to back up, and is more than sufficient for single-host home lab workloads. The volume mount in the compose file (`./data:/app/data`) handles persistence across container restarts.

### Polling, not events
The scheduler polls the Docker API at a configurable interval rather than subscribing to Docker events. This is simpler to implement, easier to reason about, and sufficient for the target use case (home lab containers don't change frequently). The tradeoff is up to one poll interval of latency before a new container is detected.

### Grype as a subprocess
Grype is invoked as a subprocess rather than via a library. This keeps the Python codebase simple, makes it easy to upgrade Grype independently of the Python dependencies, and allows Grype to manage its own database lifecycle. The tradeoff is process spawn overhead per scan.

### Digest-based deduplication
Images are tracked by their content digest (`sha256:...`), not by name or tag. This correctly handles the common home lab pattern of pinning to `:latest` while still detecting when the image has been re-pulled to a new version.

### Two distinct digest types — never mix them
Docker images have two different digests that are hashes of different documents and are never equal for the same image: the **config digest** (`image.id` from the Docker SDK, stored in `Scan.image_digest`) identifies an image locally and is used for scan deduplication; the **manifest digest** (from Docker's `RepoDigests`, returned as `Docker-Content-Digest` by the registry) identifies an image in the registry and is the only value comparable with a remote HEAD response. `ImageUpdateCheck.running_digest` and `registry_digest` are always manifest digests. Never use one type as a fallback for the other.

### Environment variables override settings
Runtime settings (scan interval, concurrency, etc.) can be configured either through the dashboard UI (persisted in the `Setting` table) or via environment variables. Environment variables take precedence, which allows infrastructure-level overrides without touching the application.

### Vulnerability table layout guardrails

These rules are important and should be preserved unless the user explicitly asks to change them:

- The vulnerability table is used in 3 contexts:
	- Main Vulnerabilities page (`frontend/src/routes/vulnerabilities/+page.svelte`)
	- Container expanded sub-view (`frontend/src/lib/components/vuln/ContainerRow.svelte`)
	- Preview Scan dialog (`frontend/src/lib/components/preview/PreviewScannerModal.svelte` + nested `ContainerRow`)
- Prefer column rebalancing before adding new wrappers or per-view special-case hacks.
- Preserve this sizing intent:
	- Non-description columns keep readable minimums.
	- Description column absorbs remaining/free space first.
	- Horizontal scrolling is acceptable only after those minimums are reached.
- In Preview Scan dialog specifically:
	- First try fitting by allocating more dialog width and explicit outer table columns.
- Avoid brittle nested selector hacks (for example, deep `table table` CSS overrides) when a scoped structural sizing fix is possible.
- When adjusting one table context, check the other two for regressions before finalizing.
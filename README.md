# DockGuard

A tool for home labbers to understand the security vulnerabilities present in the Docker images they run. It automatically scans running containers with Grype, persists results to SQLite, and surfaces them through a SvelteKit web dashboard.

## Key Files

### Backend (`backend/`)

| File | Purpose |
|---|---|
| `backend/docker_watcher.py` | Lists local Docker images via the Docker SDK; returns name, digest, grype reference, and running state |
| `backend/grype_scanner.py` | Runs `grype -o json -q` against each image, parses output, persists to DB |
| `backend/scheduler.py` | APScheduler job that polls Docker every 60s and triggers Grype scans for new or updated images |
| `backend/models.py` | SQLModel ORM definitions — `Scan` and `Vulnerability` tables |
| `backend/database.py` | SQLite engine setup, `init()`, `get_session()` FastAPI dependency |
| `backend/api.py` | FastAPI endpoints for querying scan results |

### Frontend (`frontend/`)

| File | Purpose |
|---|---|
| `frontend/src/routes/+layout.svelte` | Root layout — ModeWatcher, SidebarProvider, top header with mode toggle |
| `frontend/src/routes/+page.svelte` | Dashboard page — stat cards and recent activity table |
| `frontend/src/routes/+page.server.ts` | Server-side load function — fetches `/activity/recent` from the API |
| `frontend/src/lib/components/app-sidebar.svelte` | Sidebar nav — Dashboard, Containers, Images, Tasks, Settings |
| `frontend/src/lib/components/mode-toggle.svelte` | Light/dark theme toggle button |
| `frontend/src/lib/components/ui/` | shadcn-svelte UI primitives (card, table, badge, button, sidebar, …) |

## Setup

```bash
brew install grype      # must be installed separately — not a Python package
uv sync                 # creates .venv and installs all Python dependencies
cd frontend && npm ci   # install frontend dependencies
```

## Running

### Backend (dev mode)
```bash
uv run uvicorn backend.api:app --reload --port 8765
```

### Frontend (dev mode)
```bash
cd frontend && npm run dev
```

Then visit http://localhost:5173. The frontend dev server proxies API calls to http://localhost:8765 via the SvelteKit server-side load function — make sure the backend is running.

## Docker

### Quick Start

The easiest way to run DockGuard is with the `docker-compose.yml` in the project root, which pulls the latest pre-built image from the GitHub Container Registry:

```bash
docker compose up -d
```

Visit http://localhost:8764 for the dashboard.

```bash
docker compose logs -f        # tail logs
docker compose down           # stop (data is preserved in ./data/)
```

Scan data is stored in `./data/dockguard.db` and persists across restarts. See `docker-compose.yml` for available environment variables.

### Notes

- **Docker socket**: The backend must be able to reach the host Docker daemon. On Linux this is `/var/run/docker.sock`. Docker Desktop for Mac/Windows exposes the same path via the VM.
- **Database persistence**: The SQLite file is written to `data/dockguard.db`. Removing or recreating containers does not delete scan history. To wipe the database, delete that file.

Starting the API server also starts the background scheduler. Every 60 seconds it checks which Docker containers are running. If a new image appears, or an existing image has been re-pulled to a new digest (e.g. `latest` was updated), a Grype scan is automatically queued and run in the background. Results are persisted to the database as scans complete.

The poll interval can be changed with the `SCAN_INTERVAL_SECONDS` environment variable (default: `60`).

Every hour the scheduler also runs `grype db check`. If a newer Grype vulnerability database is available, all previously-seen image digests are cleared so every image — including any that were stopped at the time — is rescanned against the updated database when next observed. The check interval can be changed with the `DB_CHECK_INTERVAL_SECONDS` environment variable (default: `3600`).

### Development Build

To build the container locally for development and testing, use the compose file in `docker/`:

```bash
docker compose -f docker/docker-compose.yml up --build
```

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `DATABASE_PATH` | `data/dockguard.db` | Path to the SQLite database file. The default writes to a `data/` subdirectory relative to the working directory. When running in Docker, the compose file volume-mounts this directory for persistence. |
| `SCAN_INTERVAL_SECONDS` | `60` | How often (in seconds) the scheduler polls Docker for new/updated containers. |
| `MAX_CONCURRENT_SCANS` | `1` | Maximum number of Grype scans to run in parallel. |
| `DB_CHECK_INTERVAL_SECONDS` | `3600` | How often (in seconds) to check for Grype vulnerability database updates. |
| `API_URL` | `http://localhost:8765` | URL the SvelteKit server-side load functions use to reach the backend API. |

## Database

SQLite file: `data/dockguard.db` (created automatically on first run, or at `DATABASE_PATH` if set).

Schema: `Scan` (one row per image scan) → `Vulnerability` (one row per finding).
`image_digest` on `Scan` is how version changes are tracked over time for the same image name.

## Running Tests

```bash
uv sync --group dev   # install test dependencies (first time only)
uv run pytest -v      # unit + integration tests (fast, no Docker/Grype needed)
uv run pytest -v -m e2e   # end-to-end tests (requires Docker daemon + grype on PATH)
```

The default run excludes e2e tests because they take ~45 seconds (real Grype
scan). No Docker daemon or Grype binary is needed for the default run — both
are mocked. Tests use an isolated in-memory SQLite database and are fully
independent of one another.

**Test structure:**

| File | Covers |
|---|---|
| `backend/tests/fixtures.py` | Static Grype JSON payloads and mock Docker image data |
| `backend/tests/conftest.py` | `test_db` and `api_client` fixtures, `seed_scan()` helper |
| `backend/tests/test_docker_watcher.py` | `DockerWatcher.list_images()` — tagged, untagged, running, Docker unavailable |
| `backend/tests/test_grype_scanner.py` | `GrypeScanner` — subprocess args, DB persistence, field parsing, error handling |
| `backend/tests/test_api.py` | All API endpoints including 404s, latest-scan-only logic, history ordering, and digest lookups |
| `backend/tests/test_scheduler.py` | Scheduler polling logic — new image detection, digest deduplication, DB bootstrap |

## Changing the Database Schema

Alembic manages all schema migrations. After editing `models.py`:

```bash
# 1. Generate a migration from the model changes
uv run alembic -c backend/alembic.ini revision --autogenerate -m "describe your change"

# 2. Open the generated file in backend/alembic/versions/ and verify the auto-generated
#    upgrade/downgrade — check for any missing `import sqlmodel` if SQLModel
#    string types are used (known autogenerate quirk)

# 3. Apply the migration
uv run alembic -c backend/alembic.ini upgrade head
```

The app runs `alembic upgrade head` automatically on startup,
so once the migration file is committed, it will be applied on the next run.

To roll back the last migration:
```bash
uv run alembic -c backend/alembic.ini downgrade -1
```

## API Endpoints

### Image identifiers

The API uses three ways to refer to images. Which one to use depends on context:

| Identifier | Example | Use when |
|---|---|---|
| `image_repository` | `nginx`, `ghcr.io/owner/repo` | Querying history across all tags of an image |
| `image_ref` | `nginx:latest`, `ghcr.io/owner/repo:tag` | Querying a specific tagged image (most endpoints) |
| `image_digest` | `sha256:abc123...` | Pinning an exact image version; accepted wherever `image_ref` is |

The history endpoint accepts all three forms and auto-detects which was provided.

### Routes

| Method | Path | Parameter | Description |
|---|---|---|---|
| GET | `/images/vulnerabilities` | `?image_ref=` | All vulns for the latest scan of an image |
| GET | `/images/vulnerabilities/critical` | `?image_ref=` | Critical vulns for the latest scan |
| GET | `/vulnerabilities/critical/running` | — | Critical vulns across all currently running containers |
| GET | `/vulnerabilities/count` | — | Total vuln count across the latest scan per image |
| GET | `/images/vulnerabilities/history` | `?image=` | Vuln counts over time; accepts `image_repository`, `image_ref`, or `image_digest` |
| GET | `/activity/recent` | `?limit=5` | Latest N scans with per-severity vulnerability counts (used by dashboard) |

Image parameters are passed as query strings to handle names containing forward slashes (e.g. `ghcr.io/owner/repo:latest`).

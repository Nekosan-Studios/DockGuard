# DockerSecurityWatch

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

Grype is bundled in the backend image (pinned to a specific version), so no local install is needed when running via Docker.

### Run with Docker Compose (recommended)

```bash
docker compose -f docker/docker-compose.yml up --build
```

This starts a unified container running both the backend and frontend.


| Service | Ports | Description |
|---|---|---|
| `docker-security-watch` | 3000, 8765 | SvelteKit Frontend + FastAPI Backend + Grype |

The compose file handles everything:
- Builds a single multi-stage image (see `docker/Dockerfile`)
- Uses `supervisord` to manage both the Node.js and Python processes
- Mounts `/var/run/docker.sock` so the backend can introspect the host Docker daemon
- Creates a named volume `dsw-data` at `/app/data` for database persistence
- Sets `DATABASE_URL`, `SCAN_INTERVAL_SECONDS`, and `MAX_CONCURRENT_SCANS` on the backend
- Sets `API_URL=http://localhost:8765` so the frontend can reach the backend locally

Visit http://localhost:3000 for the dashboard.

To run in the background:

```bash
docker compose -f docker/docker-compose.yml up -d
docker compose -f docker/docker-compose.yml logs -f        # tail logs
docker compose -f docker/docker-compose.yml down           # stop (data volume is preserved)
```

### Notes

- **Docker socket**: The backend must be able to reach the host Docker daemon. On Linux this is `/var/run/docker.sock`. Docker Desktop for Mac/Windows exposes the same path via the VM.
- **Database persistence**: The SQLite file lives in the named volume. Removing containers does not delete scan history; only `docker volume rm dsw-data` does.

Starting the API server also starts the background scheduler. Every 60 seconds it checks which Docker containers are running. If a new image appears, or an existing image has been re-pulled to a new digest (e.g. `latest` was updated), a Grype scan is automatically queued and run in the background. Results are persisted to the database as scans complete.

The poll interval can be changed with the `SCAN_INTERVAL_SECONDS` environment variable (default: `60`).

Every hour the scheduler also runs `grype db check`. If a newer Grype vulnerability database is available, all previously-seen image digests are cleared so every image — including any that were stopped at the time — is rescanned against the updated database when next observed. The check interval can be changed with the `DB_CHECK_INTERVAL_SECONDS` environment variable (default: `3600`).

## Database

SQLite file: `docker_security_watch.db` (created automatically on first run, or at `DATABASE_URL` if set).

Schema: `Scan` (one row per image scan) → `Vulnerability` (one row per finding).
`image_digest` on `Scan` is how version changes are tracked over time for the same image name.

## Running Tests

```bash
uv sync --group dev   # install test dependencies (first time only)
uv run pytest -v
```

No Docker daemon or Grype binary required — both are mocked. Tests use an
isolated in-memory SQLite database and are fully independent of one another.

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

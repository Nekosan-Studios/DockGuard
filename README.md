# DockerSecurityWatch

A Python tool that lets home labbers understand the security vulnerabilities present in the docker images they run.

This is an extremely early work in progress, the first iteration of the back end is all that is written at this time.  It will evolve into a fuller featured modern web app.

## Key Files

| File | Purpose |
|---|---|
| `docker_watcher.py` | Lists local Docker images via the Docker SDK; returns name, digest, grype reference, and running state |
| `grype_scanner.py` | Runs `grype -o json -q` against each image, parses output, persists to DB |
| `scheduler.py` | APScheduler job that polls Docker every 60s and triggers Grype scans for new or updated images |
| `models.py` | SQLModel ORM definitions — `Scan` and `Vulnerability` tables |
| `database.py` | SQLite engine setup, `init_db()`, `get_session()` FastAPI dependency |
| `api.py` | FastAPI endpoints for querying scan results |

## Setup

```bash
brew install grype  # must be installed separately — not a Python package
uv sync             # creates .venv and installs all dependencies
```

## Running

```bash
uv run uvicorn api:app --reload
```

Starting the API server also starts the background scheduler. Every 60 seconds it checks which Docker containers are running. If a new image appears, or an existing image has been re-pulled to a new digest (e.g. `latest` was updated), a Grype scan is automatically queued and run in the background. Results are persisted to the database as scans complete.

The poll interval can be changed with the `SCAN_INTERVAL_SECONDS` environment variable (default: `60`).

## Database

SQLite file: `docker_security_watch.db` (created automatically on first run).

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
| `tests/fixtures.py` | Static Grype JSON payloads and mock Docker image data |
| `tests/conftest.py` | `test_db` and `api_client` fixtures, `seed_scan()` helper |
| `tests/test_docker_watcher.py` | `DockerWatcher.list_images()` — tagged, untagged, running, Docker unavailable |
| `tests/test_grype_scanner.py` | `GrypeScanner` — subprocess args, DB persistence, field parsing, error handling |
| `tests/test_api.py` | All API endpoints including 404s, latest-scan-only logic, history ordering, and digest lookups |
| `tests/test_scheduler.py` | Scheduler polling logic — new image detection, digest deduplication, DB bootstrap |

## Changing the Database Schema

Alembic manages all schema migrations. After editing `models.py`:

```bash
# 1. Generate a migration from the model changes
uv run alembic revision --autogenerate -m "describe your change"

# 2. Open the generated file in alembic/versions/ and verify the auto-generated
#    upgrade/downgrade — check for any missing `import sqlmodel` if SQLModel
#    string types are used (known autogenerate quirk)

# 3. Apply the migration
uv run alembic upgrade head
```

The app runs `alembic upgrade head` automatically on startup,
so once the migration file is committed, it will be applied on the next run.

To roll back the last migration:
```bash
uv run alembic downgrade -1
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

Image parameters are passed as query strings to handle names containing forward slashes (e.g. `ghcr.io/owner/repo:latest`).

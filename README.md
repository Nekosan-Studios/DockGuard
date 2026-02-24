# DockerSecurityWatch

A Python tool that lets home labbers understand the security vulnerabilities present in the docker images they run.

This is an extremely early work in progress, the first iteration of the back end is all that is written at this time.  It will evolve into a fuller featured modern web app.

## Key Files

| File | Purpose |
|---|---|
| `docker_watcher.py` | Lists local Docker images via the Docker SDK; returns name, digest, grype reference, and running state |
| `grype_scanner.py` | Runs `grype -o json -q` against each image, parses output, persists to DB |
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
# Run scans and persist results to DB
uv run python grype_scanner.py

# Start the API
uv run uvicorn api:app --reload
```

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
| `tests/test_api.py` | All 5 API endpoints including 404s, latest-scan-only logic, and history ordering |

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

The app and scanner both run `alembic upgrade head` automatically on startup,
so once the migration file is committed, it will be applied on the next run.

To roll back the last migration:
```bash
uv run alembic downgrade -1
```

## API Endpoints

Image names are passed as a `name` query parameter to handle names containing forward slashes (e.g. `ghcr.io/owner/repo:latest`).

| Method | Path | Description |
|---|---|---|
| GET | `/images/vulnerabilities?name=<image>` | All vulns for latest scan of an image |
| GET | `/images/vulnerabilities/critical?name=<image>` | Critical vulns for latest scan |
| GET | `/vulnerabilities/critical/running` | Critical vulns across all currently running containers |
| GET | `/vulnerabilities/count` | Total vuln count across latest scan per image |
| GET | `/images/vulnerabilities/history?name=<image>` | Vuln counts over time per scan/digest |

# Developing DockGuard

This document covers everything you need to get a local development environment running, understand the project structure, run tests, and make changes to the backend or frontend.

## Prerequisites

- [uv](https://github.com/astral-sh/uv) — Python package manager
- [Node.js](https://nodejs.org/) (v20+) and npm
- [Grype](https://github.com/anchore/grype) — vulnerability scanner (`brew install grype` on Mac)
- Docker (for e2e tests and Docker dev builds)

## Setup

```bash
# Python dependencies
uv sync --group dev

# Frontend dependencies
cd frontend && npm ci
```

## Running Locally

Use the helper script ./dev.sh to quickly start both the front and back end. Or, to run each parts manually:
```bash
# Terminal 1: backend
uv run uvicorn backend.main:app --reload --port 8765

# Terminal 2: frontend
cd frontend && npm run dev
```

Then visit [http://localhost:5173](http://localhost:5173). The SvelteKit dev server proxies API calls to `http://localhost:8765` automatically.

## Code Quality & Testing

Generally follow this order of operations: Format -> Lint -> Check -> Test. Our CI runs strict lint checks and all unit tests including e2e on merges and fail on any issues.

### Backend

```bash
uv run ruff format            # 1. Format
uv run ruff check --fix       # 2. Lint (auto-fix)
uv run ruff check             # 3. Lint (strict check)

# Unit and integration tests (fast — no Docker or Grype needed)
uv run pytest -v

# With coverage
uv run pytest -v --cov=backend

# End-to-end tests (requires Docker daemon running and grype on PATH — ~45s)
uv run pytest -v -m e2e
```

### Frontend

```bash
cd frontend
npm run format      # 1. Format
npm run lint:fix    # 2. Lint (auto-fix)
npm run check       # 3. Type / Svelte checking
npm run lint        # 4. Lint (strict check)
npm run test:unit:run  # 5. Unit tests (non-watch mode)
cd ..
```

Tests use an isolated in-memory SQLite database and are fully independent. Docker and Grype are mocked in non-e2e tests.

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `DATABASE_PATH` | `data/dockguard.db` | Path to the SQLite database file. |
| `SCAN_INTERVAL_SECONDS` | `60` | How often (seconds) the scheduler polls Docker. |
| `MAX_CONCURRENT_SCANS` | `1` | Maximum parallel Grype scans. |
| `DB_CHECK_INTERVAL_SECONDS` | `3600` | How often (seconds) to check for Grype DB updates. |
| `API_URL` | `http://localhost:8765` | URL the SvelteKit SSR layer uses to reach the backend API. Override when running in a non-standard network setup. |

## API Endpoints

| Method | Path | Description |
|---|---|---|
| GET | `/dashboard/summary` | Vulnerability summary stats for the dashboard |
| GET | `/activity/recent` | Latest N scans with per-severity counts |
| GET | `/vulnerabilities` | Vulnerabilities across all running containers |
| GET | `/vulnerabilities/count` | Total vuln count across latest scan per image |
| GET | `/images/vulnerabilities` | All vulns for the latest scan of a specific image |
| GET | `/tasks` | Recent background tasks |
| GET | `/tasks/scheduled` | Scheduled job state |
| GET | `/settings` | Current settings |
| PATCH | `/settings` | Update one or more settings |
| GET | `/version` | App version |
| GET | `/table/{table_name}` | Raw DB table rows (internal/debug) |

### Image identifier formats

| Identifier | Example | Use when |
|---|---|---|
| `image_repository` | `nginx`, `ghcr.io/owner/repo` | Querying history across all tags |
| `image_ref` | `nginx:latest`, `ghcr.io/owner/repo:tag` | Querying a specific tagged image |
| `image_digest` | `sha256:abc123...` | Pinning an exact image version |

## Database Schema

Managed by [Alembic](https://alembic.sqlalchemy.org/). All schema changes go through versioned migration files — never edit the DB manually.

**After editing `models.py`:**

```bash
# Generate migration
uv run alembic -c backend/alembic.ini revision --autogenerate -m "describe your change"

# Review the generated file in backend/alembic/versions/ — check for missing `import sqlmodel`
# (a known autogenerate quirk with SQLModel string types)

# Apply
uv run alembic -c backend/alembic.ini upgrade head
```

The app runs `alembic upgrade head` automatically on startup, so committed migrations are applied on next run.

```bash
# Roll back the last migration
uv run alembic -c backend/alembic.ini downgrade -1
```

## Releasing a New Version

Releasing is a single action in the GitHub web UI — no local scripts needed.

1. Go to **GitHub → Releases → Draft a new release**
2. Under **"Choose a tag"**, type the new version (e.g. `v1.3.0`) and select **"Create new tag on publish"** targeting `master`
3. Click **"Publish release"**

CI will automatically build the Docker image with the version baked in and push it to GHCR:
- `ghcr.io/nekosan-studios/dockguard:1.3.0`
- `ghcr.io/nekosan-studios/dockguard:latest`

The Settings page in the published image will show `DockGuard v1.3.0`.

> **Note:** `pyproject.toml`, `package.json`, and lockfiles are permanently pinned to `0.0.0` and are never bumped. The git tag is the authoritative version.

## Docker Dev Build

To build and run the container locally from source:

```bash
docker compose -f docker/docker-compose.yml up --build
```

This uses the multi-stage `docker/Dockerfile` which builds the frontend, then packages everything into a single image running under supervisord.

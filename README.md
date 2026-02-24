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
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
brew install grype  # must be installed separately — not a Python package
```

## Running

```bash
# Run scans and persist results to DB
python grype_scanner.py

# Start the API
uvicorn api:app --reload
```

## Database

SQLite file: `docker_security_watch.db` (created automatically on first run).

Schema: `Scan` (one row per image scan) → `Vulnerability` (one row per finding).
`image_digest` on `Scan` is how version changes are tracked over time for the same image name.

## API Endpoints

| Method | Path | Description |
|---|---|---|
| GET | `/images/{image_name}/vulnerabilities` | All vulns for latest scan of an image |
| GET | `/images/{image_name}/vulnerabilities/critical` | Critical vulns for latest scan |
| GET | `/vulnerabilities/critical/running` | Critical vulns across all currently running containers |
| GET | `/vulnerabilities/count` | Total vuln count across latest scan per image |
| GET | `/images/{image_name}/vulnerabilities/history` | Vuln counts over time per scan/digest |

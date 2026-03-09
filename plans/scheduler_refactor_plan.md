# Priority 3: Scheduler Refactoring

Currently, `backend/scheduler.py` is a 500+ line module containing both scheduling mechanics and heavy business logic for vulnerability scanning, DB updates, VEX attestations, and database purging.

The goal is to split this logic into separate modules under `backend/jobs/` and move the actual image scanning execution directly into `backend/grype_scanner.py`.

## Proposed Changes

### 1. Extract Business Logic into Jobs
Create a `backend/jobs/` package and move the core logic from `ContainerScheduler` there:
- `backend/jobs/maintenance.py`: Will contain `purge_old_data()` to clean up `Scan` and `SystemTask` rows.
- `backend/jobs/grype_db.py`: Will contain `check_db_update()` and `fetch_grype_info()`.
- `backend/jobs/containers.py`: Will contain `check_running_containers()`.

### 2. Move Scanning Execution to `GrypeScanner`
The following methods in `scheduler.py` will be moved to `backend/grype_scanner.py`, making the scanner fully self-contained instead of a partial helper:
- `_scan_image_async`
- `_scan_image_sync`
- `_check_vex_for_latest_scan`
- `_resolve_repo_digest`

`GrypeScanner` will become the single entrypoint for launching and persisting scans, including VEX resolution.

### 3. Simplify `scheduler.py`
`backend/scheduler.py` will become a lightweight manager class (`ContainerScheduler`) that:
- Initializes `AsyncIOScheduler`.
- Reads `SCAN_INTERVAL_SECONDS`, `MAX_CONCURRENT_SCANS`, etc.
- Registers the extracted functions from `backend/jobs/` to the scheduler.
- Will likely only be ~100 lines long.

### 4. Tests Adjustment
The fixtures in `test_api.py`, `conftest.py` (like `e2e_client`), and `test_scheduler.py` will be updated to mock the new module paths (`backend.jobs.containers.DockerWatcher` or `backend.grype_scanner.DockerWatcher`) rather than mocking them on the old monolithic `scheduler.py`.

## Verification Plan

### Automated Tests
```bash
# Run standard API and Integration tests
uv run pytest backend/tests/test_api.py backend/tests/test_integration.py backend/tests/test_scheduler.py -v --tb=short

# Run E2E Test to ensure the new GrypeScanner logic works end-to-end
DOCKER_HOST=unix:///Users/mattweinecke/.docker/run/docker.sock uv run pytest backend/tests/test_e2e.py -v -m e2e --tb=short
```

### Manual Verification
1. Run `./dev.sh`.
2. Observe the console logs to ensure the APScheduler triggers the 3 background jobs normally without crashing.
3. Check the UI (`http://localhost:5173/tasks`) to see if the System Tasks are still successfully created and updated.

# Priority 3: Scheduler Refactoring Walkthrough

## Overview
We successfully dismantled the monolithic 500-line `backend/scheduler.py` into a clean, modular architecture. The core application logic governing background processing has been isolated into individual domain-specific jobs, and `GrypeScanner` was refactored to fully encapsulate image scanning orchestration.

## Key Architectural Changes

### 1. Extracted Specialized Background Jobs 
Instead of a single `ContainerScheduler` class defining the internals of DB maintenance, API interactions, and container polling, these domains were split into generic, testable helper functions housed inside the new `backend/jobs/` directory:

- [containers.py](file:///Users/mattweinecke/Documents/GitHub/DockGuard/backend/jobs/containers.py):
  Queries the Docker Daemon to identify newly booted containers, resolves their image digests, and schedules asynchronous Grype executions against them while writing state tracking to the `SystemTask` UI.
- [grype_db.py](file:///Users/mattweinecke/Documents/GitHub/DockGuard/backend/jobs/grype_db.py):
  Safely queries the locally cached Grype Vulnerability DB to enforce versioning checks, triggering rescan resets if CVE definitions are stale.
- [maintenance.py](file:///Users/mattweinecke/Documents/GitHub/DockGuard/backend/jobs/maintenance.py):
  Enforces unbounded DB growth protections by purging obsolete `SystemTask` rows, historical `Vulnerability` discoveries, and `Scan` logs older than the configurable `DATA_RETENTION_DAYS`. It smartly retains the single most-recent scan per image regardless of age.

### 2. Upgraded GrypeScanner Abstraction
We promoted `backend/grype_scanner.py` into a true self-container scanner by migrating `scan_image_async`, `resolve_repo_digest`, and `check_vex_for_latest_scan` into it. Downstream jobs now only inject an `Asyncio.Semaphore` and `DockerWatcher` dependency to initiate concurrent CLI execution without managing thread pool logistics.

### 3. Lightweight Manager Transformation
`backend/scheduler.py` was drastically simplified from 536 lines to ~110 lines. It is now explicitly a metadata manager for the `APScheduler` library that registers asynchronous callbacks to the `backend/jobs/` functions.

### 4. Rewritten Unit Test Suite
Because the integration footprints were modularized, we subsequently rewrote `backend/tests/test_scheduler.py` and updated the `conftest.py` mocking frameworks. The new test suite uses exact patching techniques against `backend.jobs.x` rather than brittle mock injection.

## Validation Strategy
- **Unit and Integration**: Triggered the complete `.venv/bin/pytest` testing matrix ensuring `test_api`, `test_integration`, and `test_scheduler` generated 0 errors.
- **End-to-End**: Passed the explicit `.venv/bin/pytest backend/tests/test_e2e.py` target with `DOCKER_HOST` mounted correctly so the application scanned a legitimate `alpine:latest` instance end-to-end utilizing the modular background loops.
- **Frontend Confidence**: Validated `frontend/src/routes/tasks/+page.svelte` ensures zero `API payloads` UI regression resulting from the backend split.

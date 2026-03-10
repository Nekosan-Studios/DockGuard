# Scheduler Refactoring Task Plan

- [x] Create `backend/jobs/` directory
- [x] Extract jobs from `scheduler.py`:
  - [x] Move `_check_running_containers` to `backend/jobs/containers.py`
  - [x] Move `_check_db_update` to `backend/jobs/grype.py`
  - [x] Move `_purge_old_data` to `backend/jobs/maintenance.py`
- [x] Extract scanner logic:
  - [x] Move `_scan_image_async`, `_scan_image_sync`, and `_check_vex_for_latest_scan` into `backend/grype_scanner.py` (or a dedicated `backend/scanner/` module).
- [x] Refactor `backend/scheduler.py` into a lightweight APScheduler manager:
  - [x] Register jobs using the newly extracted functions.
  - [x] Maintain configuration and semaphore limits.
- [x] Update frontend components (if `SystemTask` API payloads change due to refactored job names).
- [x] Run backend test suite.
- [x] Run E2E test.

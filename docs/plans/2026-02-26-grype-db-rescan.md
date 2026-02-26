# Grype DB Update Detection and Rescan Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add a scheduled job that runs `grype db check` hourly and clears `_seen_digests` when a new vulnerability database is available, causing all images to be rescanned on the next scheduler poll.

**Architecture:** A single new async method `_check_db_update()` is added to `ContainerScheduler` and registered as a second APScheduler job. When `grype db check` returns exit code `1` (update available), `_seen_digests.clear()` causes the existing `_check_running_containers` job to naturally rescan all running containers on its next tick. Stopped containers are also cleared and will be rescanned when they come back up.

**Tech Stack:** Python, APScheduler 3.x (`AsyncIOScheduler`), `subprocess`, `pytest` with `unittest.mock`

---

### Task 1: Write failing tests for `_check_db_update()`

**Files:**
- Modify: `backend/tests/test_scheduler.py`

**Step 1: Add imports at the top of the test file**

The file already imports `asyncio`, `patch`, `pytest`, and `ContainerScheduler`. Add `MagicMock` and `logging` to the existing imports:

```python
import logging
from unittest.mock import patch, MagicMock
```

**Step 2: Append the four new tests to the end of the file**

```python
# ---------------------------------------------------------------------------
# _check_db_update: clears seen_digests when grype DB update is available
# ---------------------------------------------------------------------------

@patch("backend.scheduler.subprocess.run")
def test_db_check_update_available_clears_seen_digests(mock_run, test_db):
    """returncode == 1 (update available) → _seen_digests is cleared entirely."""
    sched = ContainerScheduler(test_db)
    sched._seen_digests = {"sha256:aaaa", "sha256:bbbb"}
    mock_run.return_value = MagicMock(returncode=1)

    asyncio.run(sched._check_db_update())

    assert len(sched._seen_digests) == 0


@patch("backend.scheduler.subprocess.run")
def test_db_check_current_does_not_clear_seen_digests(mock_run, test_db):
    """returncode == 0 (DB current) → _seen_digests is unchanged."""
    sched = ContainerScheduler(test_db)
    sched._seen_digests = {"sha256:aaaa"}
    mock_run.return_value = MagicMock(returncode=0)

    asyncio.run(sched._check_db_update())

    assert "sha256:aaaa" in sched._seen_digests


@patch("backend.scheduler.subprocess.run")
def test_db_check_unexpected_returncode_does_not_clear_seen_digests(mock_run, test_db, caplog):
    """Unexpected returncode → _seen_digests unchanged, error is logged."""
    sched = ContainerScheduler(test_db)
    sched._seen_digests = {"sha256:aaaa"}
    mock_run.return_value = MagicMock(returncode=2)

    with caplog.at_level(logging.ERROR, logger="backend.scheduler"):
        asyncio.run(sched._check_db_update())

    assert "sha256:aaaa" in sched._seen_digests
    assert "2" in caplog.text


@patch("backend.scheduler.subprocess.run", side_effect=FileNotFoundError("grype not found"))
def test_db_check_subprocess_exception_does_not_clear_seen_digests(mock_run, test_db, caplog):
    """Subprocess exception → _seen_digests unchanged, error is logged."""
    sched = ContainerScheduler(test_db)
    sched._seen_digests = {"sha256:aaaa"}

    with caplog.at_level(logging.ERROR, logger="backend.scheduler"):
        asyncio.run(sched._check_db_update())

    assert "sha256:aaaa" in sched._seen_digests
    assert len(caplog.records) > 0
```

**Step 3: Run the new tests to verify they fail**

```bash
cd /Users/mattweinecke/Documents/GitHub/DockerSecurityWatch
uv run pytest backend/tests/test_scheduler.py -k "db_check" -v
```

Expected: 4 failures — `AttributeError: 'ContainerScheduler' object has no attribute '_check_db_update'`

**Step 4: Commit the failing tests**

```bash
git add backend/tests/test_scheduler.py
git commit -m "test: add failing tests for grype DB update detection"
```

---

### Task 2: Implement `_check_db_update()` in `scheduler.py`

**Files:**
- Modify: `backend/scheduler.py`

**Step 1: Add `subprocess` import**

At the top of `backend/scheduler.py`, add `subprocess` to the standard library imports:

```python
import subprocess
```

The full import block should now look like:

```python
import asyncio
import logging
import os
import subprocess
import datetime
```

**Step 2: Add the `DB_CHECK_INTERVAL_SECONDS` env var**

After the existing `MAX_CONCURRENT_SCANS` line (line 20), add:

```python
DB_CHECK_INTERVAL_SECONDS = int(os.environ.get("DB_CHECK_INTERVAL_SECONDS", "3600"))
```

**Step 3: Register the new job in `__init__`**

After the existing `add_job` call for `_check_running_containers` (and before `_active_scheduler = self`), add:

```python
        self._scheduler.add_job(
            self._check_db_update,
            IntervalTrigger(seconds=DB_CHECK_INTERVAL_SECONDS),
            id="check_db_update",
            name="Check for grype DB updates and trigger rescan if available",
            replace_existing=True,
        )
```

Note: no `next_run_time=datetime.now()` here — the DB check does not need to fire immediately on startup.

**Step 4: Add the `_check_db_update()` method**

Add this method to `ContainerScheduler`, after `_check_running_containers` and before `_scan_image_async`:

```python
    async def _check_db_update(self) -> None:
        """Scheduled job: check if a newer grype DB is available.

        Uses 'grype db check' exit codes:
          0 → DB is current, nothing to do
          1 → update available, clear _seen_digests so all images are rescanned
          other → unexpected error, log and take no action
        """
        try:
            result = subprocess.run(
                ["grype", "db", "check"],
                capture_output=True,
            )
        except Exception as e:
            logger.error("grype db check failed: %s", e)
            return

        if result.returncode == 0:
            logger.debug("Grype DB is current — no rescan needed")
        elif result.returncode == 1:
            logger.info("New grype DB available — clearing seen digests to trigger full rescan")
            self._seen_digests.clear()
        else:
            logger.error(
                "grype db check returned unexpected exit code %d", result.returncode
            )
```

**Step 5: Run the new tests to verify they pass**

```bash
uv run pytest backend/tests/test_scheduler.py -k "db_check" -v
```

Expected: 4 PASSED

**Step 6: Run the full test suite to check for regressions**

```bash
uv run pytest -v
```

Expected: all tests pass

**Step 7: Commit the implementation**

```bash
git add backend/scheduler.py
git commit -m "feat: clear seen_digests on grype DB update to trigger full rescan"
```

---

### Task 3: Update integration test to verify the new job is registered

**Files:**
- Modify: `backend/tests/test_integration.py`

**Step 1: Update `test_scheduler_job_registered` to also assert on `check_db_update`**

Find the existing test (around line 49) and extend the assertion:

```python
def test_scheduler_job_registered(integration_client):
    """APScheduler must have both scheduled jobs registered after startup."""
    _client, _db = integration_client
    assert sched_module._active_scheduler is not None, "_active_scheduler was never set"
    jobs = sched_module._active_scheduler.get_jobs()
    job_ids = [j.id for j in jobs]
    assert "check_running_containers" in job_ids, (
        f"Expected job 'check_running_containers', found: {job_ids}"
    )
    assert "check_db_update" in job_ids, (
        f"Expected job 'check_db_update', found: {job_ids}"
    )
```

**Step 2: Run the integration test to verify it passes**

```bash
uv run pytest backend/tests/test_integration.py::test_scheduler_job_registered -v
```

Expected: PASSED

**Step 3: Run the full test suite one final time**

```bash
uv run pytest -v
```

Expected: all tests pass

**Step 4: Commit**

```bash
git add backend/tests/test_integration.py
git commit -m "test: assert check_db_update job registered in integration test"
```

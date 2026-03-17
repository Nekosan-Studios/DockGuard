import asyncio
import logging
from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock, patch

from sqlmodel import Session, select

from backend.jobs.containers import check_running_containers
from backend.jobs.grype_db import check_db_update
from backend.jobs.maintenance import purge_old_data
from backend.models import Scan, ScanContainer, Vulnerability
from backend.scheduler import ContainerScheduler
from backend.tests.conftest import VULN_CRITICAL, VULN_HIGH, seed_scan

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_running_container(image_name: str, image_id: str, container_name: str = "test-container") -> dict:
    return {
        "container_name": container_name,
        "image_name": image_name,
        "grype_ref": image_name,
        "hash": image_id.replace("sha256:", "")[:12],
        "image_id": image_id,
    }


# ---------------------------------------------------------------------------
# ContainerScheduler: bootstraps seen digests from DB
# ---------------------------------------------------------------------------


def test_create_scheduler_loads_known_digests_from_db(test_db):
    seed_scan(test_db, "nginx:latest", "sha256:aaaa", [VULN_CRITICAL])
    seed_scan(test_db, "redis:7", "sha256:cccc", [VULN_CRITICAL])

    sched = ContainerScheduler(test_db)

    assert "sha256:aaaa" in sched._seen_digests
    assert "sha256:cccc" in sched._seen_digests


def test_create_scheduler_empty_db_has_no_digests(test_db):
    sched = ContainerScheduler(test_db)
    assert len(sched._seen_digests) == 0


# ---------------------------------------------------------------------------
# check_running_containers: new image triggers scan task
# ---------------------------------------------------------------------------


@patch("backend.jobs.containers.GrypeScanner.scan_image_async", new_callable=MagicMock)
@patch("backend.jobs.containers.asyncio.create_task")
@patch("backend.jobs.containers.DockerWatcher")
def test_new_image_schedules_scan(mock_watcher_cls, mock_create_task, mock_scan, test_db):
    seen_digests = set()
    semaphore = asyncio.Semaphore(1)
    mock_watcher_cls.return_value.list_running_containers.return_value = [
        _make_running_container("nginx:latest", "sha256:aaaa"),
    ]

    asyncio.run(check_running_containers(test_db, seen_digests, semaphore))

    mock_create_task.assert_called_once()
    assert "sha256:aaaa" in seen_digests


@patch("backend.jobs.containers.GrypeScanner.scan_image_async", new_callable=MagicMock)
@patch("backend.jobs.containers.asyncio.create_task")
@patch("backend.jobs.containers.DockerWatcher")
def test_known_digest_is_skipped(mock_watcher_cls, mock_create_task, mock_scan, test_db):
    seen_digests = {"sha256:aaaa"}
    semaphore = asyncio.Semaphore(1)
    mock_watcher_cls.return_value.list_running_containers.return_value = [
        _make_running_container("nginx:latest", "sha256:aaaa"),
    ]

    asyncio.run(check_running_containers(test_db, seen_digests, semaphore))

    mock_create_task.assert_not_called()


@patch("backend.jobs.containers.GrypeScanner.scan_image_async", new_callable=MagicMock)
@patch("backend.jobs.containers.asyncio.create_task")
@patch("backend.jobs.containers.DockerWatcher")
def test_updated_image_same_tag_triggers_scan(mock_watcher_cls, mock_create_task, mock_scan, test_db):
    """Same tag but different digest (e.g. latest was re-pulled) → new scan."""
    seed_scan(test_db, "nginx:latest", "sha256:aaaa", [VULN_CRITICAL])
    seen_digests = {"sha256:aaaa"}
    semaphore = asyncio.Semaphore(1)

    # New digest for the same nginx:latest tag
    mock_watcher_cls.return_value.list_running_containers.return_value = [
        _make_running_container("nginx:latest", "sha256:bbbb"),
    ]

    asyncio.run(check_running_containers(test_db, seen_digests, semaphore))

    mock_create_task.assert_called_once()
    assert "sha256:bbbb" in seen_digests


@patch("backend.jobs.containers.GrypeScanner.scan_image_async", new_callable=MagicMock)
@patch("backend.jobs.containers.asyncio.create_task")
@patch("backend.jobs.containers.DockerWatcher")
def test_known_digest_does_not_insert_retroactive_scan_container_rows(
    mock_watcher_cls, mock_create_task, mock_scan, test_db
):
    """check_running_containers must not write ScanContainer rows for already-known images.
    ScanContainer is a historical record written only at scan completion time."""
    seed_scan(test_db, "nginx:latest", "sha256:aaaa", [VULN_CRITICAL])
    seen_digests = {"sha256:aaaa"}
    semaphore = asyncio.Semaphore(1)
    mock_watcher_cls.return_value.list_running_containers.return_value = [
        _make_running_container("nginx:latest", "sha256:aaaa", "web-1"),
    ]

    asyncio.run(check_running_containers(test_db, seen_digests, semaphore))

    with Session(test_db.engine) as session:
        rows = session.exec(select(ScanContainer)).all()
    # seed_scan writes ScanContainer rows for its container_names argument; since we
    # passed none, the only way rows could exist is if check_running_containers wrote them.
    assert rows == [], "check_running_containers must not retroactively insert ScanContainer rows"


@patch("backend.jobs.containers.GrypeScanner.scan_image_async", new_callable=MagicMock)
@patch("backend.jobs.containers.asyncio.create_task")
@patch("backend.jobs.containers.DockerWatcher")
def test_no_running_containers_triggers_no_scan(mock_watcher_cls, mock_create_task, mock_scan, test_db):
    seen_digests = set()
    semaphore = asyncio.Semaphore(1)
    mock_watcher_cls.return_value.list_running_containers.return_value = []

    asyncio.run(check_running_containers(test_db, seen_digests, semaphore))

    mock_create_task.assert_not_called()


@patch("backend.jobs.containers.GrypeScanner.scan_image_async", new_callable=MagicMock)
@patch("backend.jobs.containers.asyncio.create_task")
@patch("backend.jobs.containers.DockerWatcher")
def test_docker_unavailable_does_not_crash(mock_watcher_cls, mock_create_task, mock_scan, test_db):
    seen_digests = set()
    semaphore = asyncio.Semaphore(1)
    mock_watcher_cls.return_value.list_running_containers.return_value = []

    asyncio.run(check_running_containers(test_db, seen_digests, semaphore))

    mock_create_task.assert_not_called()


# ---------------------------------------------------------------------------
# check_db_update: clears seen_digests when grype DB update is available
# ---------------------------------------------------------------------------


@patch("backend.jobs.grype_db.subprocess.run")
def test_db_check_update_available_clears_seen_digests(mock_run, test_db):
    """returncode == 100 (update available) → seen_digests is cleared entirely."""
    seen_digests = {"sha256:aaaa", "sha256:bbbb"}
    mock_run.return_value = MagicMock(returncode=100)

    asyncio.run(check_db_update(test_db, seen_digests))

    assert len(seen_digests) == 0


@patch("backend.jobs.grype_db.fetch_grype_info")
@patch("backend.jobs.grype_db.subprocess.run")
def test_db_check_missing_but_not_newer_does_not_clear_seen_digests(mock_run, mock_fetch, test_db, caplog):
    """returncode == 100 but downloaded DB is not newer → seen_digests is unchanged."""
    from backend.models import AppState

    dt = datetime(2025, 1, 1, tzinfo=UTC)
    with Session(test_db.engine) as session:
        session.add(AppState(id=1, db_built=dt))
        session.commit()

    seen_digests = {"sha256:aaaa"}
    mock_run.return_value = MagicMock(returncode=100)
    mock_fetch.return_value = ("v0.1.0", "v5", dt)

    with caplog.at_level(logging.INFO, logger="backend.jobs.grype_db"):
        asyncio.run(check_db_update(test_db, seen_digests))

    assert "sha256:aaaa" in seen_digests
    assert "Skipping rescan" in caplog.text


@patch("backend.jobs.grype_db.subprocess.run")
def test_db_check_current_does_not_clear_seen_digests(mock_run, test_db, caplog):
    """returncode == 0 (DB current) → seen_digests is unchanged."""
    seen_digests = {"sha256:aaaa"}
    mock_run.return_value = MagicMock(returncode=0)

    caplog.clear()
    with caplog.at_level(logging.ERROR, logger="backend.jobs.grype_db"):
        asyncio.run(check_db_update(test_db, seen_digests))

    assert "sha256:aaaa" in seen_digests
    assert len(caplog.records) == 0


@patch("backend.jobs.grype_db.subprocess.run")
def test_db_check_unexpected_returncode_does_not_clear_seen_digests(mock_run, test_db, caplog):
    """Unexpected returncode → seen_digests unchanged, error is logged."""
    seen_digests = {"sha256:aaaa"}
    mock_run.return_value = MagicMock(returncode=2)

    with caplog.at_level(logging.ERROR, logger="backend.jobs.grype_db"):
        asyncio.run(check_db_update(test_db, seen_digests))

    assert "sha256:aaaa" in seen_digests
    assert "exit code 2" in caplog.text
    assert any(r.levelno == logging.ERROR for r in caplog.records)


@patch("backend.jobs.grype_db.subprocess.run", side_effect=FileNotFoundError("grype not found"))
def test_db_check_subprocess_exception_does_not_clear_seen_digests(mock_run, test_db, caplog):
    """Subprocess exception → seen_digests unchanged, error is logged."""
    seen_digests = {"sha256:aaaa"}

    with caplog.at_level(logging.ERROR, logger="backend.jobs.grype_db"):
        asyncio.run(check_db_update(test_db, seen_digests))

    assert "sha256:aaaa" in seen_digests
    assert len(caplog.records) > 0
    assert "grype not found" in caplog.text
    assert any(r.levelno == logging.ERROR for r in caplog.records)


# ---------------------------------------------------------------------------
# purge_old_data: stale scan/vulnerability/task cleanup
# ---------------------------------------------------------------------------


def _days_ago(n: int) -> datetime:
    return datetime.now(UTC) - timedelta(days=n)


def test_purge_deletes_old_scans_and_vulns(test_db):
    """Old scan + its vulnerabilities are deleted; a recent scan for the same image is kept."""
    old_scan = seed_scan(test_db, "nginx:latest", "sha256:old", [VULN_CRITICAL], scanned_at=_days_ago(60))
    new_scan = seed_scan(test_db, "nginx:latest", "sha256:new", [VULN_HIGH], scanned_at=_days_ago(1))

    asyncio.run(purge_old_data(test_db, data_retention_days=30))

    with Session(test_db.engine) as session:
        assert session.get(Scan, old_scan.id) is None, "Old scan should have been purged"
        assert session.get(Scan, new_scan.id) is not None, "Recent scan must survive"
        old_vulns = session.exec(select(Vulnerability).where(Vulnerability.scan_id == old_scan.id)).all()
        assert old_vulns == [], "Vulnerability rows for old scan should be deleted"


def test_purge_keeps_newest_scan_when_all_old(test_db):
    """Even when the only scan for an image is past the retention cutoff it must not be deleted."""
    only_scan = seed_scan(test_db, "redis:7", "sha256:old", [VULN_CRITICAL], scanned_at=_days_ago(90))

    asyncio.run(purge_old_data(test_db, data_retention_days=30))

    with Session(test_db.engine) as session:
        assert session.get(Scan, only_scan.id) is not None, (
            "Newest scan per image must be preserved even when older than retention window"
        )


def test_purge_deletes_old_system_tasks(test_db):
    """SystemTask rows older than the retention window are removed; recent ones survive."""
    from backend.models import SystemTask as ST

    old_task = ST(
        task_type="scheduled_check_containers",
        task_name="Monitor Running Containers",
        status="completed",
        created_at=_days_ago(60),
        started_at=_days_ago(60),
        finished_at=_days_ago(60),
    )
    recent_task = ST(
        task_type="scheduled_check_containers",
        task_name="Monitor Running Containers",
        status="completed",
        created_at=_days_ago(1),
        started_at=_days_ago(1),
        finished_at=_days_ago(1),
    )
    with Session(test_db.engine) as session:
        session.add(old_task)
        session.add(recent_task)
        session.commit()
        old_id = old_task.id
        recent_id = recent_task.id

    asyncio.run(purge_old_data(test_db, data_retention_days=30))

    with Session(test_db.engine) as session:
        assert session.get(ST, old_id) is None, "Old system task should be purged"
        assert session.get(ST, recent_id) is not None, "Recent system task must survive"


def test_purge_creates_completed_system_task_record(test_db):
    """purge_old_data must write a 'scheduled_purge' SystemTask with status 'completed'."""
    from backend.models import SystemTask as ST

    asyncio.run(purge_old_data(test_db, data_retention_days=30))

    with Session(test_db.engine) as session:
        purge_tasks = session.exec(select(ST).where(ST.task_type == "scheduled_purge")).all()
    assert len(purge_tasks) == 1
    assert purge_tasks[0].status == "completed"
    assert purge_tasks[0].result_details is not None


# ---------------------------------------------------------------------------
# _parse_digest_hour
# ---------------------------------------------------------------------------


def test_parse_digest_hour_valid():
    from backend.scheduler import _parse_digest_hour

    assert _parse_digest_hour("8") == 8
    assert _parse_digest_hour("0") == 0
    assert _parse_digest_hour("23") == 23


def test_parse_digest_hour_invalid_string_falls_back_to_zero(caplog):
    from backend.scheduler import _parse_digest_hour

    with caplog.at_level(logging.WARNING, logger="backend.scheduler"):
        result = _parse_digest_hour("not-a-number")
    assert result == 0
    assert "not a valid integer" in caplog.text


def test_parse_digest_hour_out_of_range_falls_back_to_zero(caplog):
    from backend.scheduler import _parse_digest_hour

    with caplog.at_level(logging.WARNING, logger="backend.scheduler"):
        result = _parse_digest_hour("25")
    assert result == 0
    assert "outside the valid range" in caplog.text


# ---------------------------------------------------------------------------
# _get_digest_timezone
# ---------------------------------------------------------------------------


def test_get_digest_timezone_valid_tz(monkeypatch):
    from backend.scheduler import _get_digest_timezone

    monkeypatch.setenv("TZ", "America/New_York")
    tz = _get_digest_timezone()
    assert tz.key == "America/New_York"


def test_get_digest_timezone_invalid_tz_falls_back_to_utc(monkeypatch, caplog):
    from backend.scheduler import _get_digest_timezone

    monkeypatch.setenv("TZ", "Not/A/Real/Timezone")
    with caplog.at_level(logging.WARNING, logger="backend.scheduler"):
        tz = _get_digest_timezone()
    assert tz.key == "UTC"
    assert "not a recognised timezone" in caplog.text


def test_get_digest_timezone_no_env_returns_utc(monkeypatch):
    from backend.scheduler import _get_digest_timezone

    monkeypatch.delenv("TZ", raising=False)
    tz = _get_digest_timezone()
    assert tz.key == "UTC"


# ---------------------------------------------------------------------------
# ContainerScheduler._cleanup_stray_tasks
# ---------------------------------------------------------------------------


def test_cleanup_stray_tasks_marks_queued_and_running_as_failed(test_db):
    from backend.models import SystemTask as ST

    now = datetime.now(UTC)
    with Session(test_db.engine) as session:
        session.add(ST(task_type="scan", task_name="Scan A", status="running", created_at=now))
        session.add(ST(task_type="scan", task_name="Scan B", status="queued", created_at=now))
        session.add(ST(task_type="scan", task_name="Scan C", status="completed", created_at=now))
        session.commit()

    # Creating ContainerScheduler calls _cleanup_stray_tasks in __init__
    ContainerScheduler(test_db)

    with Session(test_db.engine) as session:
        all_tasks = session.exec(select(ST)).all()

    statuses = {t.task_name: t.status for t in all_tasks}
    assert statuses["Scan A"] == "failed"
    assert statuses["Scan B"] == "failed"
    assert statuses["Scan C"] == "completed"


def test_cleanup_stray_tasks_sets_error_message(test_db):
    from backend.models import SystemTask as ST

    with Session(test_db.engine) as session:
        session.add(ST(task_type="scan", task_name="Interrupted", status="running", created_at=datetime.now(UTC)))
        session.commit()

    ContainerScheduler(test_db)

    with Session(test_db.engine) as session:
        task = session.exec(select(ST).where(ST.task_name == "Interrupted")).first()
    assert task is not None
    assert "restart" in (task.error_message or "").lower()
    assert task.finished_at is not None


# ---------------------------------------------------------------------------
# ContainerScheduler.update_job_intervals
# ---------------------------------------------------------------------------


def test_update_job_intervals_reschedules_scan_job(test_db):
    """Changing SCAN_INTERVAL_SECONDS reschedules the check_running_containers job."""
    from backend.config import ConfigManager

    sched = ContainerScheduler(test_db)
    original_interval = sched.scan_interval

    # Change the setting in DB
    with Session(test_db.engine) as session:
        new_value = original_interval + 60
        ConfigManager.set_setting("SCAN_INTERVAL_SECONDS", str(new_value), session)
        session.commit()

    sched.update_job_intervals()

    assert sched.scan_interval == new_value


def test_update_job_intervals_reschedules_db_check_job(test_db):
    from backend.config import ConfigManager

    sched = ContainerScheduler(test_db)
    original = sched.db_check_interval

    with Session(test_db.engine) as session:
        new_value = original + 60
        ConfigManager.set_setting("DB_CHECK_INTERVAL_SECONDS", str(new_value), session)
        session.commit()

    sched.update_job_intervals()

    assert sched.db_check_interval == new_value


def test_update_job_intervals_reschedules_digest_job(test_db):
    from backend.config import ConfigManager

    sched = ContainerScheduler(test_db)
    original = sched.digest_hour
    new_hour = (original + 1) % 24

    with Session(test_db.engine) as session:
        ConfigManager.set_setting("DAILY_DIGEST_HOUR_UTC", str(new_hour), session)
        session.commit()

    sched.update_job_intervals()

    assert sched.digest_hour == new_hour

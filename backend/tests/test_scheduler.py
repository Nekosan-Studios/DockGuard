import asyncio
import logging
from datetime import datetime, timedelta, timezone
from unittest.mock import patch, MagicMock

from sqlmodel import Session, select

from backend.models import Scan, Vulnerability
from backend.scheduler import ContainerScheduler
from backend.tests.conftest import seed_scan, VULN_CRITICAL, VULN_HIGH


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
# _check_running_containers: new image triggers scan task
# ---------------------------------------------------------------------------

@patch("backend.scheduler.asyncio.create_task")
@patch("backend.scheduler.DockerWatcher")
def test_new_image_schedules_scan(mock_watcher_cls, mock_create_task, test_db):
    sched = ContainerScheduler(test_db)
    mock_watcher_cls.return_value.list_running_containers.return_value = [
        _make_running_container("nginx:latest", "sha256:aaaa"),
    ]

    asyncio.run(sched._check_running_containers())

    mock_create_task.assert_called_once()
    assert "sha256:aaaa" in sched._seen_digests


@patch("backend.scheduler.asyncio.create_task")
@patch("backend.scheduler.DockerWatcher")
def test_known_digest_is_skipped(mock_watcher_cls, mock_create_task, test_db):
    sched = ContainerScheduler(test_db)
    sched._seen_digests = {"sha256:aaaa"}
    mock_watcher_cls.return_value.list_running_containers.return_value = [
        _make_running_container("nginx:latest", "sha256:aaaa"),
    ]

    asyncio.run(sched._check_running_containers())

    mock_create_task.assert_not_called()


@patch("backend.scheduler.asyncio.create_task")
@patch("backend.scheduler.DockerWatcher")
def test_db_scanned_digest_not_rescanned_on_restart(mock_watcher_cls, mock_create_task, test_db):
    """Simulate server restart: digest is in DB; ContainerScheduler bootstraps it on init."""
    seed_scan(test_db, "nginx:latest", "sha256:aaaa", [VULN_CRITICAL])

    sched = ContainerScheduler(test_db)

    mock_watcher_cls.return_value.list_running_containers.return_value = [
        _make_running_container("nginx:latest", "sha256:aaaa"),
    ]

    asyncio.run(sched._check_running_containers())

    mock_create_task.assert_not_called()


@patch("backend.scheduler.asyncio.create_task")
@patch("backend.scheduler.DockerWatcher")
def test_updated_image_same_tag_triggers_scan(mock_watcher_cls, mock_create_task, test_db):
    """Same tag but different digest (e.g. latest was re-pulled) → new scan."""
    seed_scan(test_db, "nginx:latest", "sha256:aaaa", [VULN_CRITICAL])
    sched = ContainerScheduler(test_db)

    # New digest for the same nginx:latest tag
    mock_watcher_cls.return_value.list_running_containers.return_value = [
        _make_running_container("nginx:latest", "sha256:bbbb"),
    ]

    asyncio.run(sched._check_running_containers())

    mock_create_task.assert_called_once()
    assert "sha256:bbbb" in sched._seen_digests


@patch("backend.scheduler.asyncio.create_task")
@patch("backend.scheduler.DockerWatcher")
def test_no_running_containers_triggers_no_scan(mock_watcher_cls, mock_create_task, test_db):
    """Empty list from list_running_containers → no scan scheduled."""
    sched = ContainerScheduler(test_db)
    mock_watcher_cls.return_value.list_running_containers.return_value = []

    asyncio.run(sched._check_running_containers())

    mock_create_task.assert_not_called()


@patch("backend.scheduler.asyncio.create_task")
@patch("backend.scheduler.DockerWatcher")
def test_docker_unavailable_does_not_crash(mock_watcher_cls, mock_create_task, test_db):
    sched = ContainerScheduler(test_db)
    mock_watcher_cls.return_value.list_running_containers.return_value = []

    asyncio.run(sched._check_running_containers())

    mock_create_task.assert_not_called()


# ---------------------------------------------------------------------------
# _check_db_update: clears seen_digests when grype DB update is available
# ---------------------------------------------------------------------------

@patch("backend.scheduler.subprocess.run")
def test_db_check_update_available_clears_seen_digests(mock_run, test_db):
    """returncode == 100 (update available) → _seen_digests is cleared entirely."""
    sched = ContainerScheduler(test_db)
    sched._seen_digests = {"sha256:aaaa", "sha256:bbbb"}
    mock_run.return_value = MagicMock(returncode=100)

    asyncio.run(sched._check_db_update())

    assert len(sched._seen_digests) == 0


@patch("backend.scheduler.subprocess.run")
def test_db_check_current_does_not_clear_seen_digests(mock_run, test_db, caplog):
    """returncode == 0 (DB current) → _seen_digests is unchanged."""
    sched = ContainerScheduler(test_db)
    sched._seen_digests = {"sha256:aaaa"}
    mock_run.return_value = MagicMock(returncode=0)

    caplog.clear()
    with caplog.at_level(logging.ERROR, logger="backend.scheduler"):
        asyncio.run(sched._check_db_update())

    assert "sha256:aaaa" in sched._seen_digests
    assert len(caplog.records) == 0


@patch("backend.scheduler.subprocess.run")
def test_db_check_unexpected_returncode_does_not_clear_seen_digests(mock_run, test_db, caplog):
    """Unexpected returncode → _seen_digests unchanged, error is logged."""
    sched = ContainerScheduler(test_db)
    sched._seen_digests = {"sha256:aaaa"}
    mock_run.return_value = MagicMock(returncode=2)

    with caplog.at_level(logging.ERROR, logger="backend.scheduler"):
        asyncio.run(sched._check_db_update())

    assert "sha256:aaaa" in sched._seen_digests
    assert "exit code 2" in caplog.text
    assert any(r.levelno == logging.ERROR for r in caplog.records)


@patch("backend.scheduler.subprocess.run", side_effect=FileNotFoundError("grype not found"))
def test_db_check_subprocess_exception_does_not_clear_seen_digests(mock_run, test_db, caplog):
    """Subprocess exception → _seen_digests unchanged, error is logged."""
    sched = ContainerScheduler(test_db)
    sched._seen_digests = {"sha256:aaaa"}

    with caplog.at_level(logging.ERROR, logger="backend.scheduler"):
        asyncio.run(sched._check_db_update())

    assert "sha256:aaaa" in sched._seen_digests
    assert len(caplog.records) > 0
    assert "grype not found" in caplog.text
    assert any(r.levelno == logging.ERROR for r in caplog.records)


# ---------------------------------------------------------------------------
# _purge_old_data: stale scan/vulnerability/task cleanup
# ---------------------------------------------------------------------------

def _days_ago(n: int) -> datetime:
    return datetime.now(timezone.utc) - timedelta(days=n)


def test_purge_deletes_old_scans_and_vulns(test_db):
    """Old scan + its vulnerabilities are deleted; a recent scan for the same image is kept."""
    old_scan = seed_scan(test_db, "nginx:latest", "sha256:old", [VULN_CRITICAL], scanned_at=_days_ago(60))
    new_scan = seed_scan(test_db, "nginx:latest", "sha256:new", [VULN_HIGH], scanned_at=_days_ago(1))

    sched = ContainerScheduler(test_db)
    sched.data_retention_days = 30  # explicit; default is 30 already
    asyncio.run(sched._purge_old_data())

    with Session(test_db.engine) as session:
        assert session.get(Scan, old_scan.id) is None, "Old scan should have been purged"
        assert session.get(Scan, new_scan.id) is not None, "Recent scan must survive"
        old_vulns = session.exec(
            select(Vulnerability).where(Vulnerability.scan_id == old_scan.id)
        ).all()
        assert old_vulns == [], "Vulnerability rows for old scan should be deleted"


def test_purge_keeps_newest_scan_when_all_old(test_db):
    """Even when the only scan for an image is past the retention cutoff it must not be deleted."""
    only_scan = seed_scan(test_db, "redis:7", "sha256:old", [VULN_CRITICAL], scanned_at=_days_ago(90))

    sched = ContainerScheduler(test_db)
    sched.data_retention_days = 30
    asyncio.run(sched._purge_old_data())

    with Session(test_db.engine) as session:
        assert session.get(Scan, only_scan.id) is not None, (
            "Newest scan per image must be preserved even when older than retention window"
        )


def test_purge_deletes_old_system_tasks(test_db):
    """SystemTask rows older than the retention window are removed; recent ones survive."""
    from backend.models import SystemTask as ST

    now = datetime.now(timezone.utc)
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

    sched = ContainerScheduler(test_db)
    sched.data_retention_days = 30
    asyncio.run(sched._purge_old_data())

    with Session(test_db.engine) as session:
        assert session.get(ST, old_id) is None, "Old system task should be purged"
        assert session.get(ST, recent_id) is not None, "Recent system task must survive"


def test_purge_creates_completed_system_task_record(test_db):
    """_purge_old_data must write a 'scheduled_purge' SystemTask with status 'completed'."""
    from backend.models import SystemTask as ST

    sched = ContainerScheduler(test_db)
    sched.data_retention_days = 30
    asyncio.run(sched._purge_old_data())

    with Session(test_db.engine) as session:
        purge_tasks = session.exec(
            select(ST).where(ST.task_type == "scheduled_purge")
        ).all()
    assert len(purge_tasks) == 1
    assert purge_tasks[0].status == "completed"
    assert purge_tasks[0].result_details is not None


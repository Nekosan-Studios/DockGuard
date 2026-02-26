import asyncio
import logging
from unittest.mock import patch, MagicMock

import pytest

from backend.scheduler import ContainerScheduler
from backend.tests.conftest import seed_scan, VULN_CRITICAL


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
    """returncode == 1 (update available) → _seen_digests is cleared entirely."""
    sched = ContainerScheduler(test_db)
    sched._seen_digests = {"sha256:aaaa", "sha256:bbbb"}
    mock_run.return_value = MagicMock(returncode=1)

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

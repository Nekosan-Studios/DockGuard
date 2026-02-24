import asyncio
from unittest.mock import MagicMock, patch

import pytest

import scheduler as sched_module
from scheduler import check_running_containers, create_scheduler
from tests.conftest import seed_scan, VULN_CRITICAL


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_running_image(name: str, image_id: str) -> dict:
    return {
        "name": name,
        "grype_ref": name,
        "hash": image_id.replace("sha256:", "")[:12],
        "image_id": image_id,
        "running": True,
    }


# ---------------------------------------------------------------------------
# create_scheduler: bootstraps seen digests from DB
# ---------------------------------------------------------------------------

def test_create_scheduler_loads_known_digests_from_db(test_db):
    seed_scan(test_db, "nginx:latest", "sha256:aaaa", [VULN_CRITICAL])
    seed_scan(test_db, "redis:7", "sha256:cccc", [VULN_CRITICAL])

    create_scheduler(test_db)

    assert "sha256:aaaa" in sched_module._seen_digests
    assert "sha256:cccc" in sched_module._seen_digests


def test_create_scheduler_empty_db_has_no_digests(test_db):
    create_scheduler(test_db)
    assert len(sched_module._seen_digests) == 0


# ---------------------------------------------------------------------------
# check_running_containers: new image triggers scan task
# ---------------------------------------------------------------------------

@patch("scheduler.asyncio.create_task")
@patch("scheduler.DockerWatcher")
def test_new_image_schedules_scan(mock_watcher_cls, mock_create_task, test_db):
    sched_module._seen_digests = set()
    mock_watcher_cls.return_value.list_images.return_value = [
        _make_running_image("nginx:latest", "sha256:aaaa"),
    ]

    asyncio.run(check_running_containers(test_db))

    mock_create_task.assert_called_once()
    assert "sha256:aaaa" in sched_module._seen_digests


@patch("scheduler.asyncio.create_task")
@patch("scheduler.DockerWatcher")
def test_known_digest_is_skipped(mock_watcher_cls, mock_create_task, test_db):
    sched_module._seen_digests = {"sha256:aaaa"}
    mock_watcher_cls.return_value.list_images.return_value = [
        _make_running_image("nginx:latest", "sha256:aaaa"),
    ]

    asyncio.run(check_running_containers(test_db))

    mock_create_task.assert_not_called()


@patch("scheduler.asyncio.create_task")
@patch("scheduler.DockerWatcher")
def test_db_scanned_digest_not_rescanned_on_restart(mock_watcher_cls, mock_create_task, test_db):
    """Simulate server restart: digest is in DB but not in _seen_digests yet."""
    seed_scan(test_db, "nginx:latest", "sha256:aaaa", [VULN_CRITICAL])

    # Bootstrap (simulates create_scheduler at startup)
    create_scheduler(test_db)

    mock_watcher_cls.return_value.list_images.return_value = [
        _make_running_image("nginx:latest", "sha256:aaaa"),
    ]

    asyncio.run(check_running_containers(test_db))

    mock_create_task.assert_not_called()


@patch("scheduler.asyncio.create_task")
@patch("scheduler.DockerWatcher")
def test_updated_image_same_tag_triggers_scan(mock_watcher_cls, mock_create_task, test_db):
    """Same tag but different digest (e.g. latest was re-pulled) → new scan."""
    seed_scan(test_db, "nginx:latest", "sha256:aaaa", [VULN_CRITICAL])
    create_scheduler(test_db)

    # New digest for the same nginx:latest tag
    mock_watcher_cls.return_value.list_images.return_value = [
        _make_running_image("nginx:latest", "sha256:bbbb"),
    ]

    asyncio.run(check_running_containers(test_db))

    mock_create_task.assert_called_once()
    assert "sha256:bbbb" in sched_module._seen_digests


@patch("scheduler.asyncio.create_task")
@patch("scheduler.DockerWatcher")
def test_non_running_images_are_ignored(mock_watcher_cls, mock_create_task, test_db):
    sched_module._seen_digests = set()
    mock_watcher_cls.return_value.list_images.return_value = [
        {**_make_running_image("nginx:latest", "sha256:aaaa"), "running": False},
    ]

    asyncio.run(check_running_containers(test_db))

    mock_create_task.assert_not_called()


@patch("scheduler.asyncio.create_task")
@patch("scheduler.DockerWatcher")
def test_docker_unavailable_does_not_crash(mock_watcher_cls, mock_create_task, test_db):
    sched_module._seen_digests = set()
    mock_watcher_cls.return_value.list_images.return_value = []

    asyncio.run(check_running_containers(test_db))

    mock_create_task.assert_not_called()

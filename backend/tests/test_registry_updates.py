"""Tests for backend/jobs/registry_updates.py — focusing on the untagged-ref
normalization behaviour added to support containers whose Config.Image has no
explicit tag (e.g. ``jgraph/drawio`` instead of ``jgraph/drawio:latest``).
"""

import asyncio
from unittest.mock import patch

from sqlmodel import Session, select

from backend.jobs.registry_updates import check_registry_updates
from backend.models import ImageUpdateCheck

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_MANIFEST_RUNNING = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
_MANIFEST_REGISTRY = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
_MANIFEST_SAME = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"


def _make_container(image_name: str, config_digest: str = "sha256:localcfg") -> dict:
    return {
        "container_name": "test-container",
        "image_name": image_name,
        "grype_ref": image_name,
        "hash": config_digest.replace("sha256:", "")[:12],
        "config_digest": config_digest,
    }


def _run_check(db, running_containers, registry_digest):
    """Run check_registry_updates with mocked watcher and registry checker."""
    semaphore = asyncio.Semaphore(1)

    with (
        patch("backend.jobs.registry_updates.DockerWatcher") as mock_watcher_cls,
        patch("backend.registry_checker.get_registry_digest") as mock_get_digest,
        patch("backend.jobs.registry_updates.asyncio.create_task"),
    ):
        watcher = mock_watcher_cls.return_value
        watcher.list_running_containers.return_value = running_containers
        # get_manifest_digest always returns a stable running manifest digest
        watcher.get_manifest_digest.return_value = _MANIFEST_RUNNING
        mock_get_digest.return_value = registry_digest

        asyncio.run(check_registry_updates(db, semaphore))

        return mock_get_digest


# ---------------------------------------------------------------------------
# Filter: untagged refs are now included (digest-pinned still skipped)
# ---------------------------------------------------------------------------


def test_untagged_image_is_included(test_db):
    """An image with no tag (e.g. ``jgraph/drawio``) must not be skipped."""
    mock_get_digest = _run_check(
        test_db,
        running_containers=[_make_container("jgraph/drawio")],
        registry_digest=_MANIFEST_REGISTRY,
    )

    mock_get_digest.assert_called_once()


def test_digest_pinned_image_is_still_skipped(test_db):
    """Images referenced by digest (``image@sha256:...``) must never be checked."""
    mock_get_digest = _run_check(
        test_db,
        running_containers=[_make_container("nginx@sha256:deadbeef" + "0" * 56)],
        registry_digest=_MANIFEST_REGISTRY,
    )

    mock_get_digest.assert_not_called()


def test_tagged_image_is_still_included(test_db):
    """Existing behaviour for explicitly-tagged images must be unchanged."""
    mock_get_digest = _run_check(
        test_db,
        running_containers=[_make_container("nginx:latest")],
        registry_digest=_MANIFEST_REGISTRY,
    )

    mock_get_digest.assert_called_once()


# ---------------------------------------------------------------------------
# Normalization: registry is queried with :latest, DB stores original name
# ---------------------------------------------------------------------------


def test_untagged_ref_normalized_to_latest_for_registry_call(test_db):
    """``get_registry_digest`` must receive ``<name>:latest`` for untagged refs."""
    mock_get_digest = _run_check(
        test_db,
        running_containers=[_make_container("binwiederhier/ntfy")],
        registry_digest=_MANIFEST_REGISTRY,
    )

    mock_get_digest.assert_called_once_with("binwiederhier/ntfy:latest")


def test_tagged_ref_not_double_tagged(test_db):
    """An already-tagged image must not have ``:latest`` appended."""
    mock_get_digest = _run_check(
        test_db,
        running_containers=[_make_container("mariadb:10")],
        registry_digest=_MANIFEST_REGISTRY,
    )

    mock_get_digest.assert_called_once_with("mariadb:10")


def test_untagged_check_stored_under_original_name(test_db):
    """ImageUpdateCheck.image_name must be the original untagged string, not ``name:latest``."""
    _run_check(
        test_db,
        running_containers=[_make_container("jgraph/drawio")],
        registry_digest=_MANIFEST_REGISTRY,
    )

    with Session(test_db.engine) as session:
        checks = session.exec(select(ImageUpdateCheck)).all()

    assert len(checks) == 1
    assert checks[0].image_name == "jgraph/drawio"
    assert "latest" not in checks[0].image_name


def test_tagged_check_stored_under_tagged_name(test_db):
    """ImageUpdateCheck.image_name for a tagged image must keep the tag."""
    _run_check(
        test_db,
        running_containers=[_make_container("nginx:latest")],
        registry_digest=_MANIFEST_REGISTRY,
    )

    with Session(test_db.engine) as session:
        checks = session.exec(select(ImageUpdateCheck)).all()

    assert len(checks) == 1
    assert checks[0].image_name == "nginx:latest"


# ---------------------------------------------------------------------------
# Status outcomes for untagged refs
# ---------------------------------------------------------------------------


def test_untagged_update_detected_when_digests_differ(test_db):
    """When registry digest != running digest the check must reach scan_pending."""
    _run_check(
        test_db,
        running_containers=[_make_container("jgraph/drawio")],
        registry_digest=_MANIFEST_REGISTRY,  # differs from _MANIFEST_RUNNING
    )

    with Session(test_db.engine) as session:
        check = session.exec(select(ImageUpdateCheck).where(ImageUpdateCheck.image_name == "jgraph/drawio")).first()

    assert check is not None
    assert check.status == "scan_pending"
    assert check.running_digest == _MANIFEST_RUNNING
    assert check.registry_digest == _MANIFEST_REGISTRY


def test_untagged_up_to_date_when_digests_match(test_db):
    """When registry digest == running digest the check must be up_to_date."""
    _run_check(
        test_db,
        running_containers=[_make_container("binwiederhier/ntfy")],
        registry_digest=_MANIFEST_RUNNING,  # same as running
    )

    with Session(test_db.engine) as session:
        check = session.exec(
            select(ImageUpdateCheck).where(ImageUpdateCheck.image_name == "binwiederhier/ntfy")
        ).first()

    assert check is not None
    assert check.status == "up_to_date"


def test_untagged_check_failed_when_registry_unreachable(test_db):
    """When get_registry_digest returns None the check must be check_failed."""
    _run_check(
        test_db,
        running_containers=[_make_container("jgraph/drawio")],
        registry_digest=None,
    )

    with Session(test_db.engine) as session:
        check = session.exec(select(ImageUpdateCheck).where(ImageUpdateCheck.image_name == "jgraph/drawio")).first()

    assert check is not None
    assert check.status == "check_failed"
    assert check.registry_digest is None


def test_no_manifest_digest_skips_image(test_db):
    """Containers with no RepoDigests (locally-built) are skipped even if untagged."""
    semaphore = asyncio.Semaphore(1)

    with (
        patch("backend.jobs.registry_updates.DockerWatcher") as mock_watcher_cls,
        patch("backend.registry_checker.get_registry_digest") as mock_get_digest,
        patch("backend.jobs.registry_updates.asyncio.create_task"),
    ):
        watcher = mock_watcher_cls.return_value
        watcher.list_running_containers.return_value = [_make_container("locally/built")]
        watcher.get_manifest_digest.return_value = None  # no RepoDigests
        mock_get_digest.return_value = _MANIFEST_REGISTRY

        asyncio.run(check_registry_updates(test_db, semaphore))

    mock_get_digest.assert_not_called()

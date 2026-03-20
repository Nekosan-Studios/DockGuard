import asyncio
import logging
import time
from datetime import UTC, datetime

from sqlmodel import Session, select

from backend.api_helpers import _fmt_duration
from backend.database import Database
from backend.docker_watcher import DockerWatcher
from backend.grype_scanner import GrypeScanner
from backend.models import ImageUpdateCheck, Scan, SystemTask

logger = logging.getLogger(__name__)


async def check_registry_updates(db: Database, scan_semaphore: asyncio.Semaphore) -> None:
    """Scheduled job: check running images against their registry for updates."""
    now = datetime.now(UTC)

    with Session(db.engine) as session:
        task = SystemTask(
            task_type="scheduled_registry_check",
            task_name="Check Registry for Image Updates",
            status="running",
            created_at=now,
            started_at=now,
        )
        session.add(task)
        session.commit()
        task_id = task.id

    t0 = time.perf_counter()
    try:
        # Import here to avoid circular imports at module level
        from backend.registry_checker import get_registry_digest

        watcher = DockerWatcher()
        running = watcher.list_running_containers()

        # Collect unique image names (tagged or untagged) with their manifest digest.
        # We use the manifest digest (from Docker's RepoDigests) because the
        # registry returns the manifest digest via Docker-Content-Digest — this
        # is the only value comparable with the registry response.  The config
        # digest (image.id) is a hash of a different document and must never be
        # mixed with or used as a fallback for the manifest digest.
        # Images without a manifest digest (locally-built, never pushed/pulled)
        # are skipped entirely — they have no registry to check against.
        # Digest-pinned references (image@sha256:...) are skipped because there
        # is no mutable tag to check for updates against.
        # Untagged refs (e.g. "jgraph/drawio") are stored under the original name
        # as the ImageUpdateCheck key; ":latest" is only appended at the registry
        # call site below, matching Docker's implied-latest convention.
        images: dict[str, str] = {}  # image_name -> running manifest digest
        for item in running:
            name = item["image_name"]
            if "@" not in name:
                running_manifest_digest = watcher.get_manifest_digest(name)
                if running_manifest_digest is None:
                    logger.debug("Skipping %s: no manifest digest (locally-built image?)", name)
                    continue
                images[name] = running_manifest_digest

        checked = 0
        updates_found = 0

        for image_name, running_manifest_digest in images.items():
            # Untagged refs (e.g. "jgraph/drawio") are normalized to ":latest"
            # for the registry lookup only.  The DB key (image_name) stays as
            # the original untagged string so all downstream lookups continue
            # to match Docker's Config.Image value without further normalization.
            # Append :latest only for untagged refs. Use the same logic as
            # _parse_image_ref: find the last colon and check that nothing
            # after it looks like a port (i.e. no "/" follows it).
            last_colon = image_name.rfind(":")
            has_tag = last_colon != -1 and "/" not in image_name[last_colon + 1 :]
            registry_ref = image_name if has_tag else f"{image_name}:latest"
            registry_manifest_digest = await asyncio.to_thread(get_registry_digest, registry_ref)

            with Session(db.engine) as session:
                check = session.exec(select(ImageUpdateCheck).where(ImageUpdateCheck.image_name == image_name)).first()

                if check is None:
                    check = ImageUpdateCheck(
                        image_name=image_name,
                        running_digest=running_manifest_digest,
                        last_checked_at=datetime.now(UTC),
                        status="check_failed" if registry_manifest_digest is None else "up_to_date",
                    )
                    session.add(check)
                    session.flush()

                check.running_digest = running_manifest_digest
                check.last_checked_at = datetime.now(UTC)

                if registry_manifest_digest is None:
                    check.status = "check_failed"
                    check.registry_digest = None
                    check.error = "Could not retrieve registry digest"
                    session.add(check)
                    session.commit()
                    checked += 1
                    continue

                # Capture the previously-stored registry manifest digest BEFORE
                # overwriting it, so the "already scanned" guard below can compare
                # old vs new correctly.
                previous_registry_manifest_digest = check.registry_digest
                check.registry_digest = registry_manifest_digest
                check.error = None

                if registry_manifest_digest == running_manifest_digest:
                    check.status = "up_to_date"
                    session.add(check)
                    session.commit()
                    checked += 1
                    continue

                # Digests differ — update is available
                updates_found += 1

                # Skip if this exact registry manifest digest is already being scanned
                # (scan_pending) or was fully scanned (scan_complete).  We compare
                # against the OLD stored registry digest (before the update above) so
                # that a newly-pushed registry image (new digest) is never incorrectly
                # skipped.
                # Note: scan_pending is included to prevent a second scan being queued
                # if the check interval fires again before the in-flight scan completes.
                # This differs from the post-restart case: _cleanup_stray_tasks() resets
                # any orphaned scan_pending records to failed on startup, so a restarted
                # server will correctly re-queue here.
                already_scanned_this_digest = (
                    check.status in ("scan_pending", "scan_complete")
                    and previous_registry_manifest_digest == registry_manifest_digest
                )
                if already_scanned_this_digest:
                    session.add(check)
                    session.commit()
                    checked += 1
                    continue

                check.status = "scan_pending"
                check.update_scan_id = None

                # Find the current scan id for this image
                current_scan = session.exec(
                    select(Scan)
                    .where(Scan.image_name == image_name)
                    .where(Scan.is_update_check == False)  # noqa: E712
                    .order_by(Scan.scanned_at.desc())
                ).first()
                check.current_scan_id = current_scan.id if current_scan else None

                # Create a SystemTask so this scan is visible in the task list
                # and the frontend can poll its progress.
                now_task = datetime.now(UTC)
                scan_task = SystemTask(
                    task_type="update_scan",
                    task_name=f"Update scan: {image_name}",
                    status="queued",
                    created_at=now_task,
                )
                session.add(scan_task)
                session.flush()
                check.pending_task_id = scan_task.id
                pending_task_id = scan_task.id

                session.add(check)
                session.commit()

                scanner = GrypeScanner(watcher=None, database=db)
                asyncio.create_task(
                    _scan_and_update_check(
                        db,
                        scanner,
                        image_name,
                        scan_semaphore,
                        pending_task_id,
                    )
                )

                checked += 1

        elapsed = time.perf_counter() - t0
        with Session(db.engine) as session:
            task = session.get(SystemTask, task_id)
            if task:
                task.status = "completed"
                task.finished_at = datetime.now(UTC)
                task.result_details = (
                    f"Checked {checked} image(s); {updates_found} update(s) available. ({_fmt_duration(elapsed)})"
                )
                session.add(task)
                session.commit()

    except Exception as e:
        logger.exception("Error in check_registry_updates")
        with Session(db.engine) as session:
            task = session.get(SystemTask, task_id)
            if task:
                task.status = "failed"
                task.finished_at = datetime.now(UTC)
                task.error_message = str(e)
                session.add(task)
                session.commit()


async def _scan_and_update_check(
    db: Database,
    scanner: GrypeScanner,
    image_name: str,
    scan_semaphore: asyncio.Semaphore,
    pending_task_id: int,
) -> None:
    """Scan the registry image and update the ImageUpdateCheck record."""
    grype_ref = f"registry:{image_name}"
    try:
        await scanner.scan_image_async(
            image_name,
            grype_ref,
            scan_semaphore,
            container_names=None,
            task_id=pending_task_id,
            is_update_check=True,
        )

        # Find the newly stored update-check scan
        with Session(db.engine) as session:
            new_scan = session.exec(
                select(Scan)
                .where(Scan.image_name == image_name)
                .where(Scan.is_update_check == True)  # noqa: E712
                .order_by(Scan.scanned_at.desc())
            ).first()

            check = session.exec(select(ImageUpdateCheck).where(ImageUpdateCheck.image_name == image_name)).first()

            if check and new_scan:
                check.update_scan_id = new_scan.id
                check.status = "scan_complete"
                check.pending_task_id = None
                session.add(check)
                session.commit()
                logger.info(
                    "Registry update scan complete for %s: scan_id=%d",
                    image_name,
                    new_scan.id,
                )
            elif check:
                check.pending_task_id = None
                session.add(check)
                session.commit()

    except Exception:
        logger.exception("Error scanning registry update for %s", image_name)
        with Session(db.engine) as session:
            check = session.exec(select(ImageUpdateCheck).where(ImageUpdateCheck.image_name == image_name)).first()
            if check and check.status == "scan_pending":
                check.status = "update_available"
                check.pending_task_id = None
                session.add(check)
                session.commit()

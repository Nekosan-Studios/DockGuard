import asyncio
import logging
from datetime import UTC, datetime

from sqlmodel import Session, col, select

from backend.database import Database
from backend.docker_watcher import DockerWatcher
from backend.grype_scanner import GrypeScanner
from backend.jobs.notifications import process_scan_notifications
from backend.models import ImageUpdateCheck, Scan, SystemTask

logger = logging.getLogger(__name__)


async def _run_scans_then_notify(
    db: Database,
    scan_coros: list,
    scan_task_ids: list[int],
) -> None:
    """Run all scan coroutines, then process notifications for the batch."""
    results = await asyncio.gather(*scan_coros, return_exceptions=True)

    # Collect failures from the gather results
    failures: list[tuple[int, BaseException]] = []
    for task_id, exc in zip(scan_task_ids, results):
        if isinstance(exc, BaseException):
            failures.append((task_id, exc))

    # Find scans created by this batch by matching source_task_id.
    # This avoids a race condition where two overlapping batches share the same
    # batch_min_scan_id and each picks up the other's scans via a range query.
    with Session(db.engine) as session:
        recent_scans = session.exec(
            select(Scan).where(Scan.source_task_id.in_(scan_task_ids)).order_by(col(Scan.id))  # type: ignore[union-attr]
        ).all()
        scan_ids = [s.id for s in recent_scans if s.id is not None]

        # Build the results list: None for each successful scan, exception for failures
        result_list: list[BaseException | None] = [None] * len(scan_ids)

        # Add failures (use task_id as placeholder since there's no Scan row)
        for task_id, exc in failures:
            scan_ids.append(task_id)
            result_list.append(exc)

    try:
        await process_scan_notifications(db, scan_ids, result_list)
    except Exception:
        logger.exception("Error processing scan notifications")


async def check_running_containers(
    db: Database,
    seen_digests: set[str],
    scan_semaphore: asyncio.Semaphore,
) -> None:
    """Scheduled job: detect new/updated running containers and trigger scans."""
    now = datetime.now(UTC)

    with Session(db.engine) as session:
        task = SystemTask(
            task_type="scheduled_check_containers",
            task_name="Monitor Running Containers",
            status="running",
            created_at=now,
            started_at=now,
        )
        session.add(task)
        session.commit()
        task_id = task.id

    try:
        watcher = DockerWatcher()
        running = watcher.list_running_containers()

        # Group running containers by image digest so one scan job covers all
        # containers sharing the same underlying image.
        running_by_digest: dict[str, list[dict]] = {}
        for item in running:
            running_by_digest.setdefault(item["config_digest"], []).append(item)

        new_scans_queued = 0
        scanner = GrypeScanner(watcher=watcher, database=db)
        scan_coros: list = []
        scan_task_ids: list[int] = []

        for config_digest, image_group in running_by_digest.items():
            if config_digest in seen_digests:
                continue

            representative = image_group[0]
            image_name = representative["image_name"]
            grype_ref = representative["grype_ref"]
            container_names = [c["container_name"] for c in image_group]

            seen_digests.add(config_digest)
            logger.info(
                "New running image detected: %s (%s) — scheduling Grype scan",
                image_name,
                representative["hash"],
            )

            # Invalidate any stale update check only if the locally-running image
            # has actually changed (i.e. the user pulled a new version).  We compare
            # manifest digests on both sides — manifest digest is what
            # check_registry_updates stores in ImageUpdateCheck.running_digest, and
            # it is what get_manifest_digest returns from Docker's RepoDigests.
            #
            # We never fall back to the config digest here: config digest and manifest
            # digest are hashes of different documents and must never be compared with
            # each other.  If we cannot resolve a manifest digest (locally-built image
            # with no RepoDigests), we skip the deletion and preserve any existing
            # record rather than risk a false positive.
            with Session(db.engine) as session:
                stale_check = session.exec(
                    select(ImageUpdateCheck).where(ImageUpdateCheck.image_name == image_name)
                ).first()
                if stale_check:
                    current_manifest_digest = watcher.get_manifest_digest(image_name)
                    if current_manifest_digest is not None and stale_check.running_digest != current_manifest_digest:
                        session.delete(stale_check)
                        session.commit()
                        logger.info("Cleared stale ImageUpdateCheck for %s (manifest digest changed)", image_name)

            # Create a queued task for the scan
            with Session(db.engine) as session:
                scan_task = SystemTask(
                    task_type="scan",
                    task_name=f"Scan image {image_name}",
                    status="queued",
                    created_at=datetime.now(UTC),
                )
                session.add(scan_task)
                session.commit()
                assert scan_task.id is not None
                scan_task_id = scan_task.id

            new_scans_queued += 1
            scan_coros.append(
                scanner.scan_image_async(image_name, grype_ref, scan_semaphore, container_names, scan_task_id)
            )
            scan_task_ids.append(scan_task_id)

        # Gather scans and notify on completion instead of fire-and-forget
        if scan_coros:
            asyncio.create_task(_run_scans_then_notify(db, scan_coros, scan_task_ids))

        with Session(db.engine) as session:
            task = session.get(SystemTask, task_id)
            if task:
                task.status = "completed"
                task.finished_at = datetime.now(UTC)
                task.result_details = (
                    f"Detected {len(running)} running containers across {len(running_by_digest)} images. "
                    f"Queued {new_scans_queued} image scans."
                )
                session.add(task)
                session.commit()

    except Exception as e:
        logger.exception("Error in check_running_containers")
        with Session(db.engine) as session:
            task = session.get(SystemTask, task_id)
            if task:
                task.status = "failed"
                task.finished_at = datetime.now(UTC)
                task.error_message = str(e)
                session.add(task)
                session.commit()

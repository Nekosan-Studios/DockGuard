import asyncio
import logging
from datetime import UTC, datetime

from sqlmodel import Session, col, select

from backend.database import Database
from backend.docker_watcher import DockerWatcher
from backend.grype_scanner import GrypeScanner
from backend.jobs.notifications import process_scan_notifications
from backend.models import Scan, SystemTask

logger = logging.getLogger(__name__)


async def _run_scans_then_notify(
    db: Database,
    scan_coros: list,
    scan_task_ids: list[int],
    batch_min_scan_id: int,
) -> None:
    """Run all scan coroutines, then process notifications for the batch."""
    results = await asyncio.gather(*scan_coros, return_exceptions=True)

    # Collect failures from the gather results
    failures: list[tuple[int, BaseException]] = []
    for task_id, exc in zip(scan_task_ids, results):
        if isinstance(exc, BaseException):
            failures.append((task_id, exc))

    # Find all scans created during this batch (these are the successful ones).
    # Using ID > batch_min_scan_id avoids a race condition that could arise from
    # using a timestamp when two batches overlap.
    with Session(db.engine) as session:
        recent_scans = session.exec(select(Scan).where(Scan.id > batch_min_scan_id).order_by(col(Scan.id))).all()
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

        new_scans_queued = 0
        scanner = GrypeScanner(watcher=watcher, database=db)
        scan_coros: list = []
        scan_task_ids: list[int] = []

        with Session(db.engine) as session:
            last_scan = session.exec(select(Scan).order_by(col(Scan.id).desc()).limit(1)).first()
            batch_min_scan_id = (last_scan.id or 0) if last_scan else 0

        for img in running:
            image_id = img["image_id"]  # full sha256:...
            if image_id in seen_digests:
                continue

            seen_digests.add(image_id)
            logger.info(
                "New running image detected: %s (%s) — scheduling Grype scan",
                img["image_name"],
                img["hash"],
            )

            # Create a queued task for the scan
            with Session(db.engine) as session:
                scan_task = SystemTask(
                    task_type="scan",
                    task_name=f"Scan {img['image_name']}",
                    status="queued",
                    created_at=datetime.now(UTC),
                )
                session.add(scan_task)
                session.commit()
                assert scan_task.id is not None
                scan_task_id = scan_task.id

            new_scans_queued += 1
            scan_coros.append(
                scanner.scan_image_async(
                    img["image_name"], img["grype_ref"], scan_semaphore, img["container_name"], scan_task_id
                )
            )
            scan_task_ids.append(scan_task_id)

        # Gather scans and notify on completion instead of fire-and-forget
        if scan_coros:
            asyncio.create_task(_run_scans_then_notify(db, scan_coros, scan_task_ids, batch_min_scan_id))

        with Session(db.engine) as session:
            task = session.get(SystemTask, task_id)
            if task:
                task.status = "completed"
                task.finished_at = datetime.now(UTC)
                task.result_details = (
                    f"Detected {len(running)} running containers. Queued {new_scans_queued} new scans."
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

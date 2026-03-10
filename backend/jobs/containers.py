import asyncio
import logging
from datetime import datetime, timezone

from sqlmodel import Session

from backend.database import Database
from backend.docker_watcher import DockerWatcher
from backend.grype_scanner import GrypeScanner
from backend.models import SystemTask

logger = logging.getLogger(__name__)

async def check_running_containers(
    db: Database,
    seen_digests: set[str],
    scan_semaphore: asyncio.Semaphore,
) -> None:
    """Scheduled job: detect new/updated running containers and trigger scans."""
    now = datetime.now(timezone.utc)
    
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
        for img in running:
            image_id = img["image_id"]  # full sha256:...
            if image_id in seen_digests:
                continue

            seen_digests.add(image_id)
            logger.info(
                "New running image detected: %s (%s) — scheduling Grype scan",
                img["image_name"], img["hash"],
            )
            
            # Create a queued task for the scan
            with Session(db.engine) as session:
                scan_task = SystemTask(
                    task_type="scan",
                    task_name=f"Scan {img['image_name']}",
                    status="queued",
                    created_at=datetime.now(timezone.utc)
                )
                session.add(scan_task)
                session.commit()
                scan_task_id = scan_task.id
            
            new_scans_queued += 1
            asyncio.create_task(
                scanner.scan_image_async(
                    img["image_name"],
                    img["grype_ref"],
                    scan_semaphore,
                    img["container_name"],
                    scan_task_id
                )
            )

        with Session(db.engine) as session:
            task = session.get(SystemTask, task_id)
            if task:
                task.status = "completed"
                task.finished_at = datetime.now(timezone.utc)
                task.result_details = f"Detected {len(running)} running containers. Queued {new_scans_queued} new scans."
                session.add(task)
                session.commit()

    except Exception as e:
        logger.exception("Error in check_running_containers")
        with Session(db.engine) as session:
            task = session.get(SystemTask, task_id)
            if task:
                task.status = "failed"
                task.finished_at = datetime.now(timezone.utc)
                task.error_message = str(e)
                session.add(task)
                session.commit()

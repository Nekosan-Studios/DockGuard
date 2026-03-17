import asyncio
import logging
from datetime import UTC, datetime

from sqlmodel import Session, select

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

    try:
        # Import here to avoid circular imports at module level
        from backend.registry_checker import get_registry_digest

        watcher = DockerWatcher()
        running = watcher.list_running_containers()

        # Collect unique tagged image names with their current digest
        images: dict[str, str] = {}  # image_name -> image_id (running digest)
        for item in running:
            name = item["image_name"]
            if "@" not in name and ":" in name:
                images[name] = item["image_id"]

        checked = 0
        updates_found = 0

        for image_name, running_digest in images.items():
            registry_digest = get_registry_digest(image_name)

            with Session(db.engine) as session:
                check = session.exec(select(ImageUpdateCheck).where(ImageUpdateCheck.image_name == image_name)).first()

                if check is None:
                    check = ImageUpdateCheck(
                        image_name=image_name,
                        running_digest=running_digest,
                        last_checked_at=datetime.now(UTC),
                        status="check_failed" if registry_digest is None else "up_to_date",
                    )
                    session.add(check)
                    session.flush()

                check.running_digest = running_digest
                check.last_checked_at = datetime.now(UTC)

                if registry_digest is None:
                    check.status = "check_failed"
                    check.registry_digest = None
                    check.error = "Could not retrieve registry digest"
                    session.add(check)
                    session.commit()
                    checked += 1
                    continue

                check.registry_digest = registry_digest
                check.error = None

                if registry_digest == running_digest:
                    check.status = "up_to_date"
                    session.add(check)
                    session.commit()
                    checked += 1
                    continue

                # Digests differ — update is available
                updates_found += 1

                # Only scan if we haven't already scanned this exact registry
                # digest (covers repeated job runs and in-flight scans).
                already_scanned_this_digest = (
                    check.status in ("scan_pending", "scan_complete") and check.registry_digest == registry_digest
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

                session.add(check)
                session.commit()

                scanner = GrypeScanner(watcher=None, database=db)
                asyncio.create_task(
                    _scan_and_update_check(
                        db,
                        scanner,
                        image_name,
                        scan_semaphore,
                    )
                )

                checked += 1

        with Session(db.engine) as session:
            task = session.get(SystemTask, task_id)
            if task:
                task.status = "completed"
                task.finished_at = datetime.now(UTC)
                task.result_details = f"Checked {checked} image(s); {updates_found} update(s) available."
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
) -> None:
    """Scan the registry image and update the ImageUpdateCheck record."""
    grype_ref = f"registry:{image_name}"
    try:
        await scanner.scan_image_async(
            image_name,
            grype_ref,
            scan_semaphore,
            container_names=None,
            task_id=None,
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
                session.add(check)
                session.commit()
                logger.info(
                    "Registry update scan complete for %s: scan_id=%d",
                    image_name,
                    new_scan.id,
                )

    except Exception:
        logger.exception("Error scanning registry update for %s", image_name)
        with Session(db.engine) as session:
            check = session.exec(select(ImageUpdateCheck).where(ImageUpdateCheck.image_name == image_name)).first()
            if check and check.status == "scan_pending":
                check.status = "update_available"
                session.add(check)
                session.commit()

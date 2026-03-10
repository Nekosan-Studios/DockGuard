import logging
from datetime import datetime, timedelta, timezone

from sqlmodel import Session, delete, select

from backend.database import Database
from backend.models import Scan, SystemTask, Vulnerability

logger = logging.getLogger(__name__)

async def purge_old_data(db: Database, data_retention_days: int) -> None:
    """Scheduled job (daily): delete stale Scan/Vulnerability and SystemTask rows.

    Retention policy:
    - All ``Scan`` rows (and their child ``Vulnerability`` rows) older than
      ``DATA_RETENTION_DAYS`` are deleted, **except** the single most-recent
      scan for each ``image_name``.  This guard ensures the dashboard always
      has data for every actively-running container, even on stable images
      that haven't been rescanned within the window.
    - ``SystemTask`` rows older than ``DATA_RETENTION_DAYS`` are deleted
      (excluding the currently-running purge task itself).
    """
    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(days=data_retention_days)

    with Session(db.engine) as session:
        task = SystemTask(
            task_type="scheduled_purge",
            task_name="Purge Old Data",
            status="running",
            created_at=now,
            started_at=now,
        )
        session.add(task)
        session.commit()
        task_id = task.id

    scans_deleted = vulns_deleted = tasks_deleted = 0
    error_msg = None

    try:
        with Session(db.engine) as session:
            # -- Collect IDs of scans that are old enough to be candidates.
            old_scan_ids: list[int] = [
                row[0]
                for row in session.execute(
                    select(Scan.id).where(Scan.scanned_at < cutoff)  # type: ignore[arg-type]
                ).all()
            ]

            if old_scan_ids:
                # -- Find the newest scan per image_name so we can exempt it.
                newest_by_image: dict[str, int] = {}
                for sid, img in session.execute(
                    select(Scan.id, Scan.image_name)
                ).all():
                    if img not in newest_by_image or sid > newest_by_image[img]:
                        newest_by_image[img] = sid

                protected_ids = set(newest_by_image.values())
                purgeable_ids = [sid for sid in old_scan_ids if sid not in protected_ids]

                if purgeable_ids:
                    # Delete child vulnerability rows first (no cascade on SQLite).
                    vuln_result = session.execute(
                        delete(Vulnerability).where(Vulnerability.scan_id.in_(purgeable_ids))
                    )
                    vulns_deleted = vuln_result.rowcount

                    scan_result = session.execute(
                        delete(Scan).where(Scan.id.in_(purgeable_ids))
                    )
                    scans_deleted = scan_result.rowcount

            # -- Purge old SystemTask rows (skip the currently-running purge task).
            task_result = session.execute(
                delete(SystemTask)
                .where(SystemTask.created_at < cutoff)  # type: ignore[arg-type]
                .where(SystemTask.id != task_id)
            )
            tasks_deleted = task_result.rowcount

            session.commit()

        logger.info(
            "Purge complete — retention=%dd cutoff=%s scans=%d vulns=%d tasks=%d",
            data_retention_days, cutoff.date(), scans_deleted, vulns_deleted, tasks_deleted,
        )

    except Exception as exc:
        logger.exception("Error in purge_old_data")
        error_msg = str(exc)

    with Session(db.engine) as session:
        task = session.get(SystemTask, task_id)
        if task:
            task.status = "failed" if error_msg else "completed"
            task.finished_at = datetime.now(timezone.utc)
            task.error_message = error_msg
            task.result_details = (
                f"Deleted {scans_deleted} scan(s), {vulns_deleted} vulnerability row(s), "
                f"{tasks_deleted} task history row(s) older than {data_retention_days} days."
            )
            session.add(task)
            session.commit()

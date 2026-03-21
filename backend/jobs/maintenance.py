import logging
from datetime import UTC, datetime, timedelta

from sqlmodel import Session, delete, select

from backend.database import Database
from backend.models import NotificationLog, Scan, SystemTask, Vulnerability

logger = logging.getLogger(__name__)


async def purge_old_data(db: Database, scan_retention_days: int, task_retention_days: int) -> None:
    """Scheduled job (daily): delete stale data according to per-type retention windows.

    Retention policy:
    - ``Scan`` rows (and their child ``Vulnerability`` rows) older than
      ``scan_retention_days`` are deleted, **except** the single most-recent
      scan for each ``image_name``.  This guard ensures the dashboard always
      has data for every actively-running container, even on stable images
      that haven't been rescanned within the window.
      Set ``scan_retention_days`` to 0 to disable scan pruning entirely.
    - ``SystemTask`` and ``NotificationLog`` rows older than
      ``task_retention_days`` are deleted (excluding the currently-running
      purge task itself).
      Set ``task_retention_days`` to 0 to disable task/notification pruning.
    """
    now = datetime.now(UTC)

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

    scans_deleted = vulns_deleted = tasks_deleted = notifications_deleted = 0
    error_msg = None

    try:
        with Session(db.engine) as session:
            if scan_retention_days > 0:
                scan_cutoff = now - timedelta(days=scan_retention_days)

                # -- Collect IDs of scans that are old enough to be candidates.
                old_scan_ids: list[int] = [
                    row[0]
                    for row in session.execute(
                        select(Scan.id).where(Scan.scanned_at < scan_cutoff)  # type: ignore[arg-type]
                    ).all()
                ]

                if old_scan_ids:
                    # -- Find the newest scan per image_name so we can exempt it.
                    newest_by_image: dict[str, int] = {}
                    for sid, img in session.execute(select(Scan.id, Scan.image_name)).all():
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

                        scan_result = session.execute(delete(Scan).where(Scan.id.in_(purgeable_ids)))
                        scans_deleted = scan_result.rowcount

            if task_retention_days > 0:
                task_cutoff = now - timedelta(days=task_retention_days)

                # -- Purge old SystemTask rows (skip the currently-running purge task).
                task_result = session.execute(
                    delete(SystemTask)
                    .where(SystemTask.created_at < task_cutoff)  # type: ignore[arg-type]
                    .where(SystemTask.id != task_id)
                )
                tasks_deleted = task_result.rowcount

                # -- Purge old NotificationLog rows.
                notif_result = session.execute(
                    delete(NotificationLog).where(NotificationLog.created_at < task_cutoff)  # type: ignore[arg-type]
                )
                notifications_deleted = notif_result.rowcount

            session.commit()

        logger.info(
            "Purge complete — scan_retention=%s task_retention=%s scans=%d vulns=%d tasks=%d notifications=%d",
            f"{scan_retention_days}d" if scan_retention_days > 0 else "disabled",
            f"{task_retention_days}d" if task_retention_days > 0 else "disabled",
            scans_deleted,
            vulns_deleted,
            tasks_deleted,
            notifications_deleted,
        )

    except Exception as exc:
        logger.exception("Error in purge_old_data")
        error_msg = str(exc)

    with Session(db.engine) as session:
        task = session.get(SystemTask, task_id)
        if task:
            task.status = "failed" if error_msg else "completed"
            task.finished_at = datetime.now(UTC)
            task.error_message = error_msg
            scan_retention_label = f"{scan_retention_days}d" if scan_retention_days > 0 else "disabled"
            task_retention_label = f"{task_retention_days}d" if task_retention_days > 0 else "disabled"
            task.result_details = (
                f"Deleted {scans_deleted} scan(s), {vulns_deleted} vulnerability row(s), "
                f"{tasks_deleted} task history row(s), {notifications_deleted} notification log row(s). "
                f"Scan retention: {scan_retention_label}, task retention: {task_retention_label}."
            )
            session.add(task)
            session.commit()

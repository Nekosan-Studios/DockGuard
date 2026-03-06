import asyncio
import logging
import os
import subprocess

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.interval import IntervalTrigger
from sqlmodel import Session, delete, select
from datetime import datetime, timedelta, timezone

from .database import Database
from .docker_watcher import DockerWatcher
from .grype_scanner import GrypeScanner
from .models import AppState, Scan, SystemTask, Vulnerability


logger = logging.getLogger(__name__)

from .config import ConfigManager

# Set in ContainerScheduler.__init__; exposed for integration test introspection.
_active_scheduler: "ContainerScheduler | None" = None


class ContainerScheduler:
    """Polls the Docker daemon for new/updated running images and triggers Grype scans."""

    def __init__(self, db: Database):
        global _active_scheduler
        self.db = db
        self._seen_digests: set[str] = set()
        with Session(self.db.engine) as session:
            self.scan_interval = int(ConfigManager.get_setting("SCAN_INTERVAL_SECONDS", session)["value"])
            self.max_concurrent_scans = int(ConfigManager.get_setting("MAX_CONCURRENT_SCANS", session)["value"])
            self.db_check_interval = int(ConfigManager.get_setting("DB_CHECK_INTERVAL_SECONDS", session)["value"])
            self.data_retention_days = int(ConfigManager.get_setting("DATA_RETENTION_DAYS", session)["value"])

        self._scan_semaphore = asyncio.Semaphore(self.max_concurrent_scans)
        self._scheduler = AsyncIOScheduler()
        self._bootstrap_seen_digests()
        self._cleanup_stray_tasks()
        self._scheduler.add_job(
            self._check_running_containers,
            IntervalTrigger(seconds=self.scan_interval),
            id="check_running_containers",
            name="Monitor running containers for new/updated images",
            next_run_time=datetime.now(),
            replace_existing=True,
        )
        self._scheduler.add_job(
            self._check_db_update,
            IntervalTrigger(seconds=self.db_check_interval),
            id="check_db_update",
            name="Check for grype DB updates and trigger rescan if available",
            next_run_time=datetime.now(),
            replace_existing=True,
        )
        self._scheduler.add_job(
            self._purge_old_data,
            IntervalTrigger(hours=24),
            id="purge_old_data",
            name="Purge stale scans and task history",
            next_run_time=datetime.now(),
            replace_existing=True,
        )
        _active_scheduler = self
        logger.info("Scheduler: max concurrent Grype scans = %d", self.max_concurrent_scans)

    def start(self) -> None:
        self._scheduler.start()

    def shutdown(self) -> None:
        self._scheduler.shutdown()

    def update_job_intervals(self) -> None:
        """Called dynamically if settings are changed via the API."""
        with Session(self.db.engine) as session:
            scan_interval = int(ConfigManager.get_setting("SCAN_INTERVAL_SECONDS", session)["value"])
            db_check_interval = int(ConfigManager.get_setting("DB_CHECK_INTERVAL_SECONDS", session)["value"])
            data_retention_days = int(ConfigManager.get_setting("DATA_RETENTION_DAYS", session)["value"])

            # The semaphore for concurrency can't easily be resized cleanly while tasks are running,
            # so we only update the polling intervals dynamically.
            if scan_interval != self.scan_interval:
                self.scan_interval = scan_interval
                self._scheduler.reschedule_job("check_running_containers", trigger=IntervalTrigger(seconds=self.scan_interval))
                logger.info("Scheduler updated check_running_containers interval to %ds", self.scan_interval)

            if db_check_interval != self.db_check_interval:
                self.db_check_interval = db_check_interval
                self._scheduler.reschedule_job("check_db_update", trigger=IntervalTrigger(seconds=self.db_check_interval))
                logger.info("Scheduler updated check_db_update interval to %ds", self.db_check_interval)

            if data_retention_days != self.data_retention_days:
                self.data_retention_days = data_retention_days
                logger.info("Scheduler updated data_retention_days to %d", self.data_retention_days)

    def get_jobs(self):
        return self._scheduler.get_jobs()

    def _bootstrap_seen_digests(self) -> None:
        with Session(self.db.engine) as session:
            rows = session.exec(select(Scan.image_digest)).all()
            self._seen_digests = set(rows)
        logger.info("Scheduler: loaded %d known digest(s) from DB", len(self._seen_digests))

    def _cleanup_stray_tasks(self) -> None:
        """Mark tasks that were running/queued before a restart as failed."""
        with Session(self.db.engine) as session:
            stray_tasks = session.exec(
                select(SystemTask).where(SystemTask.status.in_(["queued", "running"]))
            ).all()
            if stray_tasks:
                now = datetime.now(timezone.utc)
                for task in stray_tasks:
                    task.status = "failed"
                    task.finished_at = now
                    task.error_message = "Task interrupted by system restart."
                    session.add(task)
                session.commit()
                logger.info("Scheduler: marked %d stray task(s) as failed", len(stray_tasks))

    async def _purge_old_data(self) -> None:
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
        cutoff = now - timedelta(days=self.data_retention_days)

        with Session(self.db.engine) as session:
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
            with Session(self.db.engine) as session:
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
                self.data_retention_days, cutoff.date(), scans_deleted, vulns_deleted, tasks_deleted,
            )

        except Exception as exc:
            logger.exception("Error in _purge_old_data")
            error_msg = str(exc)

        with Session(self.db.engine) as session:
            task = session.get(SystemTask, task_id)
            if task:
                task.status = "failed" if error_msg else "completed"
                task.finished_at = datetime.now(timezone.utc)
                task.error_message = error_msg
                task.result_details = (
                    f"Deleted {scans_deleted} scan(s), {vulns_deleted} vulnerability row(s), "
                    f"{tasks_deleted} task history row(s) older than {self.data_retention_days} days."
                )
                session.add(task)
                session.commit()

    async def _check_running_containers(self) -> None:
        """Scheduled job: detect new/updated running containers and trigger scans."""
        now = datetime.now(timezone.utc)
        
        with Session(self.db.engine) as session:
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
            for img in running:
                image_id = img["image_id"]  # full sha256:...
                if image_id in self._seen_digests:
                    continue

                self._seen_digests.add(image_id)
                logger.info(
                    "New running image detected: %s (%s) — scheduling Grype scan",
                    img["image_name"], img["hash"],
                )
                
                # Create a queued task for the scan
                with Session(self.db.engine) as session:
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
                asyncio.create_task(self._scan_image_async(img["image_name"], img["grype_ref"], img["container_name"], scan_task_id))

            with Session(self.db.engine) as session:
                task = session.get(SystemTask, task_id)
                if task:
                    task.status = "completed"
                    task.finished_at = datetime.now(timezone.utc)
                    task.result_details = f"Detected {len(running)} running containers. Queued {new_scans_queued} new scans."
                    session.add(task)
                    session.commit()

        except Exception as e:
            logger.exception("Error in _check_running_containers")
            with Session(self.db.engine) as session:
                task = session.get(SystemTask, task_id)
                if task:
                    task.status = "failed"
                    task.finished_at = datetime.now(timezone.utc)
                    task.error_message = str(e)
                    session.add(task)
                    session.commit()

    async def _check_db_update(self) -> None:
        """Scheduled job: check if a newer grype DB is available.

        Uses 'grype db check' exit codes:
          0   → DB is current, nothing to do
          100 → update available, clear _seen_digests so all images are rescanned
          other → unexpected error, log and take no action

        Always persists the check timestamp to AppState regardless of outcome.
        """
        now = datetime.now(timezone.utc)

        with Session(self.db.engine) as session:
            task = SystemTask(
                task_type="scheduled_db_update",
                task_name="Check Grype DB Update",
                status="running",
                created_at=now,
                started_at=now,
            )
            session.add(task)
            session.commit()
            task_id = task.id

        result_msg = ""
        error_msg = None
        has_error = False

        try:
            result = await asyncio.to_thread(
                subprocess.run,
                ["grype", "db", "check"],
                capture_output=True,
                text=True,
            )
        except Exception as e:
            logger.error("grype db check failed: %s", e)
            error_msg = str(e)
            has_error = True
        else:
            if result.returncode == 0:
                logger.info("Grype DB is current — no rescan needed")
                result_msg = "DB is current."
            elif result.returncode == 100:
                logger.info("New grype DB available — downloading update before rescan")
                try:
                    await asyncio.to_thread(
                        subprocess.run,
                        ["grype", "db", "update"],
                        capture_output=True,
                        text=True,
                    )
                    logger.info("grype db update completed — clearing seen digests to trigger full rescan")
                except Exception as upd_exc:
                    logger.warning("grype db update failed (will still rescan): %s", upd_exc)
                self._seen_digests.clear()
                result_msg = "New DB available. Triggered full rescan."
            else:
                err_text = result.stderr.strip()
                logger.error(
                    "grype db check returned unexpected exit code %d: %s",
                    result.returncode,
                    err_text,
                )
                error_msg = f"Exit code {result.returncode}: {err_text}"
                has_error = True

        grype_version, db_schema, db_built = await self._fetch_grype_info()

        with Session(self.db.engine) as session:
            state = session.get(AppState, 1)
            if state is None:
                session.add(AppState(id=1, last_db_checked_at=now, grype_version=grype_version, db_schema=db_schema, db_built=db_built))
            else:
                state.last_db_checked_at = now
                if grype_version:
                    state.grype_version = grype_version
                if db_schema:
                    state.db_schema = db_schema
                if db_built:
                    state.db_built = db_built
                session.add(state)
            
            # Update the task
            task = session.get(SystemTask, task_id)
            if task:
                task.status = "failed" if has_error else "completed"
                task.finished_at = datetime.now(timezone.utc)
                task.error_message = error_msg
                task.result_details = result_msg
                session.add(task)
                
            session.commit()
        logger.debug("Persisted last_db_checked_at = %s, grype_version = %s, db_built = %s", now, grype_version, db_built)

    async def _fetch_grype_info(self) -> tuple[str | None, str | None, "datetime | None"]:
        """Run grype version + grype db status to get current grype version, DB schema, and DB built date."""
        grype_version: str | None = None
        db_schema: str | None = None
        db_built: "datetime | None" = None

        try:
            ver_result = await asyncio.to_thread(
                subprocess.run, ["grype", "version"], capture_output=True, text=True,
            )
            for line in ver_result.stdout.splitlines():
                if line.startswith("Version:"):
                    grype_version = line.split(":", 1)[1].strip()
                    break
        except Exception as e:
            logger.warning("Could not determine grype version: %s", e)

        try:
            db_result = await asyncio.to_thread(
                subprocess.run, ["grype", "db", "status"], capture_output=True, text=True,
            )
            for line in db_result.stdout.splitlines():
                if line.startswith("Schema:"):
                    db_schema = line.split(":", 1)[1].strip()
                elif line.startswith("Built:"):
                    built_str = line.split(":", 1)[1].strip()
                    # grype db status emits Go time format: "2024-01-15 00:00:00 +0000 UTC"
                    # Strip the trailing " UTC" so fromisoformat can parse it.
                    if built_str.endswith(" UTC"):
                        built_str = built_str[:-4].strip()
                    dt = datetime.fromisoformat(built_str.replace("Z", "+00:00"))
                    # Ignore the Go zero time (0001-01-01) which means DB not initialised.
                    if dt.year > 1:
                        db_built = dt
        except Exception as e:
            logger.warning("Could not determine grype DB built date: %s", e)

        return grype_version, db_schema, db_built

    async def _scan_image_async(self, image_name: str, grype_ref: str, container_name: str | None = None, task_id: int | None = None) -> None:
        """Run a Grype scan in a thread so the event loop is not blocked.

        Acquires _scan_semaphore before launching so at most MAX_CONCURRENT_SCANS
        Grype processes run simultaneously.
        """
        async with self._scan_semaphore:
            # Mark scan as running once we acquire the semaphore
            if task_id:
                with Session(self.db.engine) as session:
                    task = session.get(SystemTask, task_id)
                    if task:
                        task.status = "running"
                        task.started_at = datetime.now(timezone.utc)
                        session.add(task)
                        session.commit()
            
            await asyncio.to_thread(self._scan_image_sync, image_name, grype_ref, container_name, task_id)

    def _scan_image_sync(self, image_name: str, grype_ref: str, container_name: str | None = None, task_id: int | None = None) -> None:
        try:
            GrypeScanner(watcher=None, database=self.db).scan_image(image_name, grype_ref, container_name)
            if task_id:
                with Session(self.db.engine) as session:
                    task = session.get(SystemTask, task_id)
                    if task:
                        task.status = "completed"
                        task.finished_at = datetime.now(timezone.utc)
                        task.result_details = "Scan completed successfully."
                        session.add(task)
                        session.commit()
        except Exception as e:
            logger.exception("Error scanning image %s", image_name)
            if task_id:
                with Session(self.db.engine) as session:
                    task = session.get(SystemTask, task_id)
                    if task:
                        task.status = "failed"
                        task.finished_at = datetime.now(timezone.utc)
                        task.error_message = str(e)
                        session.add(task)
                        session.commit()

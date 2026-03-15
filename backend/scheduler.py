import asyncio
import logging
from datetime import UTC, datetime

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger
from apscheduler.triggers.interval import IntervalTrigger
from sqlmodel import Session, select

from backend.jobs.containers import check_running_containers
from backend.jobs.grype_db import check_db_update
from backend.jobs.maintenance import purge_old_data
from backend.jobs.notifications import send_daily_digest
from backend.models import Scan

from .config import ConfigManager
from .database import Database
from .models import SystemTask

logger = logging.getLogger(__name__)

# Set in ContainerScheduler.__init__; exposed for integration test introspection.
_active_scheduler: "ContainerScheduler | None" = None


class ContainerScheduler:
    """Manages APScheduler and triggers background jobs for DockGuard."""

    def __init__(self, db: Database):
        global _active_scheduler
        self.db = db
        self._seen_digests: set[str] = set()

        with Session(self.db.engine) as session:
            self.scan_interval = int(ConfigManager.get_setting("SCAN_INTERVAL_SECONDS", session)["value"])
            self.max_concurrent_scans = int(ConfigManager.get_setting("MAX_CONCURRENT_SCANS", session)["value"])
            self.db_check_interval = int(ConfigManager.get_setting("DB_CHECK_INTERVAL_SECONDS", session)["value"])
            self.data_retention_days = int(ConfigManager.get_setting("DATA_RETENTION_DAYS", session)["value"])
            self.digest_hour = int(ConfigManager.get_setting("DAILY_DIGEST_HOUR_UTC", session)["value"])

        self._scan_semaphore = asyncio.Semaphore(self.max_concurrent_scans)
        self._scheduler = AsyncIOScheduler()
        self._bootstrap_seen_digests()
        self._cleanup_stray_tasks()

        self._scheduler.add_job(
            self._run_check_running_containers,
            IntervalTrigger(seconds=self.scan_interval),
            id="check_running_containers",
            name="Monitor running containers for new/updated images",
            next_run_time=datetime.now(),
            replace_existing=True,
        )
        self._scheduler.add_job(
            self._run_check_db_update,
            IntervalTrigger(seconds=self.db_check_interval),
            id="check_db_update",
            name="Check for grype DB updates and trigger rescan if available",
            next_run_time=datetime.now(),
            replace_existing=True,
        )
        self._scheduler.add_job(
            self._run_purge_old_data,
            IntervalTrigger(hours=24),
            id="purge_old_data",
            name="Purge stale scans and task history",
            next_run_time=datetime.now(),
            replace_existing=True,
        )
        self._scheduler.add_job(
            self._run_daily_digest,
            CronTrigger(hour=self.digest_hour, minute=0),
            id="daily_digest",
            name="Send daily vulnerability digest",
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

            if scan_interval != self.scan_interval:
                self.scan_interval = scan_interval
                self._scheduler.reschedule_job(
                    "check_running_containers", trigger=IntervalTrigger(seconds=self.scan_interval)
                )
                logger.info("Scheduler updated check_running_containers interval to %ds", self.scan_interval)

            if db_check_interval != self.db_check_interval:
                self.db_check_interval = db_check_interval
                self._scheduler.reschedule_job(
                    "check_db_update", trigger=IntervalTrigger(seconds=self.db_check_interval)
                )
                logger.info("Scheduler updated check_db_update interval to %ds", self.db_check_interval)

            if data_retention_days != self.data_retention_days:
                self.data_retention_days = data_retention_days
                logger.info("Scheduler updated data_retention_days to %d", self.data_retention_days)

            digest_hour = int(ConfigManager.get_setting("DAILY_DIGEST_HOUR_UTC", session)["value"])
            if digest_hour != self.digest_hour:
                self.digest_hour = digest_hour
                self._scheduler.reschedule_job("daily_digest", trigger=CronTrigger(hour=self.digest_hour, minute=0))
                logger.info("Scheduler updated daily_digest hour to %d UTC", self.digest_hour)

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
            stray_tasks = session.exec(select(SystemTask).where(SystemTask.status.in_(["queued", "running"]))).all()
            if stray_tasks:
                now = datetime.now(UTC)
                for task in stray_tasks:
                    task.status = "failed"
                    task.finished_at = now
                    task.error_message = "Task interrupted by system restart."
                    session.add(task)
                session.commit()
                logger.info("Scheduler: marked %d stray task(s) as failed", len(stray_tasks))

    async def _run_check_running_containers(self) -> None:
        await check_running_containers(self.db, self._seen_digests, self._scan_semaphore)

    async def _run_check_db_update(self) -> None:
        await check_db_update(self.db, self._seen_digests)

    async def _run_purge_old_data(self) -> None:
        await purge_old_data(self.db, self.data_retention_days)

    async def _run_daily_digest(self) -> None:
        await send_daily_digest(self.db)

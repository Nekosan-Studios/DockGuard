import asyncio
import logging
import os
import threading
from datetime import UTC, datetime
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger
from apscheduler.triggers.interval import IntervalTrigger
from sqlmodel import Session, select

from backend.docker_watcher import DockerWatcher
from backend.jobs.containers import check_running_containers
from backend.jobs.grype_db import check_db_update
from backend.jobs.maintenance import purge_old_data
from backend.jobs.notifications import send_daily_digest
from backend.jobs.registry_updates import check_registry_updates
from backend.models import Scan

from .config import ConfigManager
from .database import Database
from .models import SystemTask

logger = logging.getLogger(__name__)

# Set in ContainerScheduler.__init__; exposed for integration test introspection.
_active_scheduler: "ContainerScheduler | None" = None

_DEFAULT_DIGEST_HOUR = 0


def _parse_digest_hour(raw_value: str) -> int:
    """Parse and validate DAILY_DIGEST_HOUR, falling back to 0 on invalid input."""
    try:
        hour = int(raw_value)
    except (ValueError, TypeError):
        logger.warning(
            "DAILY_DIGEST_HOUR=%r is not a valid integer; falling back to %d",
            raw_value,
            _DEFAULT_DIGEST_HOUR,
        )
        return _DEFAULT_DIGEST_HOUR
    if not 0 <= hour <= 23:
        logger.warning(
            "DAILY_DIGEST_HOUR=%d is outside the valid range 0–23; falling back to %d",
            hour,
            _DEFAULT_DIGEST_HOUR,
        )
        return _DEFAULT_DIGEST_HOUR
    return hour


def _get_digest_timezone() -> ZoneInfo:
    """Return the timezone for digest scheduling.

    Uses the TZ environment variable if set and valid; otherwise falls back to UTC.
    """
    tz_str = os.environ.get("TZ")
    if tz_str:
        try:
            return ZoneInfo(tz_str)
        except ZoneInfoNotFoundError:
            logger.warning("TZ=%r is not a recognised timezone; falling back to UTC for digest scheduling", tz_str)
    return ZoneInfo("UTC")


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
            self.scan_retention_days = int(ConfigManager.get_setting("SCAN_RETENTION_DAYS", session)["value"])
            self.digest_hour = _parse_digest_hour(ConfigManager.get_setting("DAILY_DIGEST_HOUR", session)["value"])
        self.task_retention_days = int(os.environ.get("TASK_RETENTION_DAYS", "7"))

        self.digest_timezone = _get_digest_timezone()
        self._scan_semaphore = asyncio.Semaphore(self.max_concurrent_scans)
        self._scheduler = AsyncIOScheduler()
        self._event_listener_task: asyncio.Task | None = None
        self._event_stop = asyncio.Event()
        self._bootstrap_seen_digests()
        self._cleanup_stray_tasks()

        self._scheduler.add_job(
            self._run_check_registry_updates,
            IntervalTrigger(seconds=self.scan_interval),
            id="check_registry_updates",
            name="Check for Registry Updates",
            max_instances=1,
            coalesce=True,
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
            CronTrigger(hour=self.digest_hour, minute=0, timezone=self.digest_timezone),
            id="daily_digest",
            name="Send daily vulnerability digest",
            replace_existing=True,
        )
        _active_scheduler = self
        logger.info("Scheduler: max concurrent Grype scans = %d", self.max_concurrent_scans)

    def start(self) -> None:
        self._scheduler.start()
        self._event_listener_task = asyncio.get_event_loop().create_task(self._run_event_listener())
        logger.info("Scheduler: Docker event listener started")

    def shutdown(self) -> None:
        self._event_stop.set()
        if self._event_listener_task:
            self._event_listener_task.cancel()
        self._scheduler.shutdown()

    def update_job_intervals(self) -> None:
        """Called dynamically if settings are changed via the API."""
        with Session(self.db.engine) as session:
            scan_interval = int(ConfigManager.get_setting("SCAN_INTERVAL_SECONDS", session)["value"])
            db_check_interval = int(ConfigManager.get_setting("DB_CHECK_INTERVAL_SECONDS", session)["value"])
            scan_retention_days = int(ConfigManager.get_setting("SCAN_RETENTION_DAYS", session)["value"])

            if scan_interval != self.scan_interval:
                self.scan_interval = scan_interval
                self._scheduler.reschedule_job(
                    "check_registry_updates", trigger=IntervalTrigger(seconds=self.scan_interval)
                )
                logger.info("Scheduler updated check_registry_updates interval to %ds", self.scan_interval)

            if db_check_interval != self.db_check_interval:
                self.db_check_interval = db_check_interval
                self._scheduler.reschedule_job(
                    "check_db_update", trigger=IntervalTrigger(seconds=self.db_check_interval)
                )
                logger.info("Scheduler updated check_db_update interval to %ds", self.db_check_interval)

            if scan_retention_days != self.scan_retention_days:
                self.scan_retention_days = scan_retention_days
                logger.info("Scheduler updated scan_retention_days to %d", self.scan_retention_days)

            digest_hour = _parse_digest_hour(ConfigManager.get_setting("DAILY_DIGEST_HOUR", session)["value"])
            if digest_hour != self.digest_hour:
                self.digest_hour = digest_hour
                self._scheduler.reschedule_job(
                    "daily_digest", trigger=CronTrigger(hour=self.digest_hour, minute=0, timezone=self.digest_timezone)
                )
                logger.info(
                    "Scheduler updated daily_digest hour to %d (%s)", self.digest_hour, self.digest_timezone.key
                )

    def get_jobs(self):
        return self._scheduler.get_jobs()

    def _bootstrap_seen_digests(self) -> None:
        with Session(self.db.engine) as session:
            rows = session.exec(
                select(Scan.image_digest).where(
                    (Scan.is_update_check == False) & (Scan.is_preview == False)  # noqa: E712
                )
            ).all()
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

    async def _run_check_registry_updates(self) -> None:
        await check_registry_updates(self.db, self._scan_semaphore)

    async def _run_event_listener(self) -> None:
        """Persistent asyncio task that listens for Docker container start events.

        Reconciles container state on each connect/reconnect, then streams events.
        Reconnects automatically after Docker daemon restarts.

        The blocking Docker event stream runs in a daemon thread so it never
        prevents Python from exiting at test teardown or shutdown. Events are
        forwarded to the asyncio coroutine via an asyncio.Queue.
        """
        RECONNECT_DELAY = 5
        stop_threading: threading.Event | None = None
        while not self._event_stop.is_set():
            try:
                watcher = DockerWatcher()
                if not watcher.client:
                    await asyncio.sleep(RECONNECT_DELAY)
                    continue

                # Reconcile on connect/reconnect: catches containers started during
                # any gap (initial startup or while disconnected after daemon restart).
                await check_running_containers(self.db, self._seen_digests, self._scan_semaphore)

                stop_threading = threading.Event()
                gen = watcher.stream_container_events(stop_threading)
                loop = asyncio.get_running_loop()
                _SENTINEL = object()
                event_queue: asyncio.Queue = asyncio.Queue()

                def _stream_worker() -> None:
                    try:
                        for event in gen:
                            try:
                                loop.call_soon_threadsafe(event_queue.put_nowait, event)
                            except RuntimeError:
                                break  # event loop closed
                            if stop_threading.is_set():
                                break
                    except Exception:
                        logger.exception("Docker event stream worker error; sentinel will notify async side")
                    finally:
                        try:
                            loop.call_soon_threadsafe(event_queue.put_nowait, _SENTINEL)
                        except RuntimeError:
                            pass  # event loop already closed

                # daemon=True: this thread will not block Python exit even if it
                # is stuck waiting for the next Docker event.
                threading.Thread(target=_stream_worker, daemon=True).start()

                while not self._event_stop.is_set():
                    try:
                        event = await asyncio.wait_for(event_queue.get(), timeout=1.0)
                    except TimeoutError:
                        continue
                    if event is _SENTINEL:
                        break  # Docker disconnected; outer loop will reconnect
                    logger.debug("Docker event: container start — triggering immediate scan check")
                    await check_running_containers(self.db, self._seen_digests, self._scan_semaphore)

            except asyncio.CancelledError:
                break
            except Exception:
                logger.exception("Event listener error; reconnecting in %ds", RECONNECT_DELAY)
            finally:
                if stop_threading is not None:
                    stop_threading.set()

            if not self._event_stop.is_set():
                await asyncio.sleep(RECONNECT_DELAY)

    async def _run_check_db_update(self) -> None:
        await check_db_update(self.db, self._seen_digests)

    async def _run_purge_old_data(self) -> None:
        await purge_old_data(self.db, self.scan_retention_days, self.task_retention_days)

    async def _run_daily_digest(self) -> None:
        await send_daily_digest(self.db)

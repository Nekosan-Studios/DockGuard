import asyncio
import logging
import os
import subprocess

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.interval import IntervalTrigger
from sqlmodel import Session, select
from datetime import datetime, timezone

from .database import Database
from .docker_watcher import DockerWatcher
from .grype_scanner import GrypeScanner
from .models import AppState, Scan


logger = logging.getLogger(__name__)

SCAN_INTERVAL_SECONDS = int(os.environ.get("SCAN_INTERVAL_SECONDS", "60"))
MAX_CONCURRENT_SCANS = int(os.environ.get("MAX_CONCURRENT_SCANS", "1"))
DB_CHECK_INTERVAL_SECONDS = int(os.environ.get("DB_CHECK_INTERVAL_SECONDS", "3600"))

# Set in ContainerScheduler.__init__; exposed for integration test introspection.
_active_scheduler: "ContainerScheduler | None" = None


class ContainerScheduler:
    """Polls the Docker daemon for new/updated running images and triggers Grype scans."""

    def __init__(self, db: Database):
        global _active_scheduler
        self.db = db
        self._seen_digests: set[str] = set()
        self._scan_semaphore = asyncio.Semaphore(MAX_CONCURRENT_SCANS)
        self._scheduler = AsyncIOScheduler()
        self._bootstrap_seen_digests()
        self._scheduler.add_job(
            self._check_running_containers,
            IntervalTrigger(seconds=SCAN_INTERVAL_SECONDS),
            id="check_running_containers",
            name="Monitor running containers for new/updated images",
            next_run_time=datetime.now(),
            replace_existing=True,
        )
        self._scheduler.add_job(
            self._check_db_update,
            IntervalTrigger(seconds=DB_CHECK_INTERVAL_SECONDS),
            id="check_db_update",
            name="Check for grype DB updates and trigger rescan if available",
            next_run_time=datetime.now(),
            replace_existing=True,
        )
        _active_scheduler = self
        logger.info("Scheduler: max concurrent Grype scans = %d", MAX_CONCURRENT_SCANS)

    def start(self) -> None:
        self._scheduler.start()

    def shutdown(self) -> None:
        self._scheduler.shutdown()

    def get_jobs(self):
        return self._scheduler.get_jobs()

    def _bootstrap_seen_digests(self) -> None:
        with Session(self.db.engine) as session:
            rows = session.exec(select(Scan.image_digest)).all()
            self._seen_digests = set(rows)
        logger.info("Scheduler: loaded %d known digest(s) from DB", len(self._seen_digests))

    async def _check_running_containers(self) -> None:
        """Scheduled job: detect new/updated running containers and trigger scans."""
        watcher = DockerWatcher()
        running = watcher.list_running_containers()

        for img in running:
            image_id = img["image_id"]  # full sha256:...
            if image_id in self._seen_digests:
                continue

            self._seen_digests.add(image_id)
            logger.info(
                "New running image detected: %s (%s) — scheduling Grype scan",
                img["image_name"], img["hash"],
            )
            asyncio.create_task(self._scan_image_async(img["image_name"], img["grype_ref"], img["container_name"]))

    async def _check_db_update(self) -> None:
        """Scheduled job: check if a newer grype DB is available.

        Uses 'grype db check' exit codes:
          0   → DB is current, nothing to do
          100 → update available, clear _seen_digests so all images are rescanned
          other → unexpected error, log and take no action

        Always persists the check timestamp to AppState regardless of outcome.
        """
        now = datetime.now(timezone.utc)

        try:
            result = await asyncio.to_thread(
                subprocess.run,
                ["grype", "db", "check"],
                capture_output=True,
                text=True,
            )
        except Exception as e:
            logger.error("grype db check failed: %s", e)
        else:
            if result.returncode == 0:
                logger.info("Grype DB is current — no rescan needed")
            elif result.returncode == 100:
                logger.info("New grype DB available — clearing seen digests to trigger full rescan")
                self._seen_digests.clear()
            else:
                logger.error(
                    "grype db check returned unexpected exit code %d: %s",
                    result.returncode,
                    result.stderr.strip(),
                )

        with Session(self.db.engine) as session:
            state = session.get(AppState, 1)
            if state is None:
                session.add(AppState(id=1, last_db_checked_at=now))
            else:
                state.last_db_checked_at = now
                session.add(state)
            session.commit()
        logger.debug("Persisted last_db_checked_at = %s", now)

    async def _scan_image_async(self, image_name: str, grype_ref: str, container_name: str | None = None) -> None:
        """Run a Grype scan in a thread so the event loop is not blocked.

        Acquires _scan_semaphore before launching so at most MAX_CONCURRENT_SCANS
        Grype processes run simultaneously.
        """
        async with self._scan_semaphore:
            await asyncio.to_thread(self._scan_image_sync, image_name, grype_ref, container_name)

    def _scan_image_sync(self, image_name: str, grype_ref: str, container_name: str | None = None) -> None:
        GrypeScanner(watcher=None, database=self.db).scan_image(image_name, grype_ref, container_name)

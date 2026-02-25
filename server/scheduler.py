import asyncio
import logging
import os
import datetime

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.interval import IntervalTrigger
from sqlmodel import Session, select
from datetime import datetime

from .database import Database
from .docker_watcher import DockerWatcher
from .grype_scanner import GrypeScanner
from .models import Scan


logger = logging.getLogger(__name__)

SCAN_INTERVAL_SECONDS = int(os.environ.get("SCAN_INTERVAL_SECONDS", "60"))
MAX_CONCURRENT_SCANS = int(os.environ.get("MAX_CONCURRENT_SCANS", "1"))

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
        images = watcher.list_images()
        running = [img for img in images if img["running"]]

        for img in running:
            image_id = img["image_id"]  # full sha256:...
            if image_id in self._seen_digests:
                continue

            self._seen_digests.add(image_id)
            logger.info(
                "New running image detected: %s (%s) — scheduling Grype scan",
                img["name"], img["hash"],
            )
            asyncio.create_task(self._scan_image_async(img["name"], img["grype_ref"]))

    async def _scan_image_async(self, image_name: str, grype_ref: str) -> None:
        """Run a Grype scan in a thread so the event loop is not blocked.

        Acquires _scan_semaphore before launching so at most MAX_CONCURRENT_SCANS
        Grype processes run simultaneously.
        """
        async with self._scan_semaphore:
            await asyncio.to_thread(self._scan_image_sync, image_name, grype_ref)

    def _scan_image_sync(self, image_name: str, grype_ref: str) -> None:
        GrypeScanner(watcher=None, database=self.db).scan_image(image_name, grype_ref)

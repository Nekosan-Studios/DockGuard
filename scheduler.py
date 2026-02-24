import asyncio
import logging
import os

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.interval import IntervalTrigger
from sqlmodel import Session, select

from database import Database
from docker_watcher import DockerWatcher
from grype_scanner import GrypeScanner
from models import Scan

logger = logging.getLogger(__name__)

SCAN_INTERVAL_SECONDS = int(os.environ.get("SCAN_INTERVAL_SECONDS", "60"))

# In-memory set of image_ids (sha256:...) we have already scanned or scheduled.
# Bootstrapped from DB on startup so restarts don't re-scan known images.
_seen_digests: set[str] = set()


async def check_running_containers(db: Database) -> None:
    """Scheduled job: detect new/updated running containers and trigger scans."""
    watcher = DockerWatcher()
    images = watcher.list_images()
    running = [img for img in images if img["running"]]

    for img in running:
        image_id = img["image_id"]  # full sha256:...
        if image_id in _seen_digests:
            continue

        _seen_digests.add(image_id)
        logger.info(
            "New running image detected: %s (%s) — scheduling Grype scan",
            img["name"], img["hash"],
        )
        asyncio.create_task(_scan_image_async(img["name"], img["grype_ref"], db))


async def _scan_image_async(image_name: str, grype_ref: str, db: Database) -> None:
    """Run a Grype scan in a thread so the event loop is not blocked."""
    await asyncio.to_thread(_scan_image_sync, image_name, grype_ref, db)


def _scan_image_sync(image_name: str, grype_ref: str, db: Database) -> None:
    GrypeScanner(watcher=None, database=db).scan_image(image_name, grype_ref)


def create_scheduler(db: Database) -> AsyncIOScheduler:
    """Create and configure the scheduler, bootstrapping seen digests from DB."""
    global _seen_digests
    with Session(db.engine) as session:
        rows = session.exec(select(Scan.image_digest)).all()
        _seen_digests = set(rows)
    logger.info("Scheduler: loaded %d known digest(s) from DB", len(_seen_digests))

    scheduler = AsyncIOScheduler()
    scheduler.add_job(
        check_running_containers,
        IntervalTrigger(seconds=SCAN_INTERVAL_SECONDS),
        args=[db],
        id="check_running_containers",
        name="Monitor running containers for new/updated images",
        replace_existing=True,
    )
    return scheduler

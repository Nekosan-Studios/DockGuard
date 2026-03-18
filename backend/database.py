import logging
import os

from sqlmodel import Session, create_engine, select

logger = logging.getLogger(__name__)

DATABASE_PATH = os.environ.get("DATABASE_PATH", "data/dockguard.db")
DATABASE_URL = f"sqlite:///{DATABASE_PATH}"


class Database:
    def __init__(self, url: str = DATABASE_URL):
        self.engine = create_engine(url)

    def init(self):
        from pathlib import Path

        from alembic import command
        from alembic.config import Config

        alembic_cfg = Config(str(Path(__file__).parent / "alembic.ini"))
        command.upgrade(alembic_cfg, "head")

    def startup_cleanup(self):
        """Clean up transient state that should not persist across restarts."""
        from .models import Scan, ScanContainer, SystemTask, Vulnerability

        with Session(self.engine) as session:
            # Remove orphaned preview scans (created by PreviewScannerModal but never cleaned
            # up if the user closed the browser or the app was stopped mid-scan).
            preview_scans = session.exec(select(Scan).where(Scan.is_preview == True)).all()  # noqa: E712
            if preview_scans:
                scan_ids = [s.id for s in preview_scans]
                for vuln in session.exec(select(Vulnerability).where(Vulnerability.scan_id.in_(scan_ids))).all():
                    session.delete(vuln)
                for sc in session.exec(select(ScanContainer).where(ScanContainer.scan_id.in_(scan_ids))).all():
                    session.delete(sc)
                for scan in preview_scans:
                    session.delete(scan)
                logger.info("startup_cleanup: removed %d orphaned preview scan(s)", len(preview_scans))

            # Remove preview tasks that were queued or running and will never complete.
            stuck_tasks = session.exec(
                select(SystemTask)
                .where(SystemTask.task_type == "preview_scan")
                .where(SystemTask.status.in_(["queued", "running"]))
            ).all()
            if stuck_tasks:
                for task in stuck_tasks:
                    session.delete(task)
                logger.info("startup_cleanup: removed %d stuck preview task(s)", len(stuck_tasks))

            session.commit()

    def get_session(self):
        with Session(self.engine) as session:
            yield session


db = Database()

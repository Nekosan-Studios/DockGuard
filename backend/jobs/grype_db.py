import asyncio
import logging
import subprocess
from datetime import datetime, timezone

from sqlmodel import Session

from backend.database import Database
from backend.models import AppState, SystemTask

logger = logging.getLogger(__name__)

async def fetch_grype_info() -> tuple[str | None, str | None, "datetime | None"]:
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
                if built_str.endswith(" UTC"):
                    built_str = built_str[:-4].strip()
                dt = datetime.fromisoformat(built_str.replace("Z", "+00:00"))
                if dt.year > 1:
                    db_built = dt
    except Exception as e:
        logger.warning("Could not determine grype DB built date: %s", e)

    return grype_version, db_schema, db_built


async def check_db_update(db: Database, seen_digests: set[str]) -> None:
    """Scheduled job: check if a newer grype DB is available.

    Uses 'grype db check' exit codes:
      0   → DB is current, nothing to do
      100 → update available, clear _seen_digests so all images are rescanned
      other → unexpected error, log and take no action

    Always persists the check timestamp to AppState regardless of outcome.
    """
    now = datetime.now(timezone.utc)

    with Session(db.engine) as session:
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
            seen_digests.clear()
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

    grype_version, db_schema, db_built = await fetch_grype_info()

    with Session(db.engine) as session:
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

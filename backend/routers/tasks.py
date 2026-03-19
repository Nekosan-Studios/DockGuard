from datetime import timedelta

from fastapi import APIRouter, Depends, Query
from sqlmodel import Session, func, select

from .. import scheduler as b_scheduler
from ..api_helpers import _as_utc
from ..database import db
from ..models import SystemTask

router = APIRouter(tags=["Tasks"])


@router.get("/tasks")
def get_recent_tasks(
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, le=100),
    session: Session = Depends(db.get_session),
):
    """Get the recent history of background tasks (scheduled jobs, scans)."""
    total = session.exec(select(func.count(SystemTask.id))).one()
    tasks = session.exec(
        select(SystemTask).order_by(SystemTask.created_at.desc()).offset((page - 1) * page_size).limit(page_size)
    ).all()

    result = []
    for t in tasks:
        tdict = t.model_dump()
        tdict["created_at"] = _as_utc(t.created_at)
        tdict["started_at"] = _as_utc(t.started_at)
        tdict["finished_at"] = _as_utc(t.finished_at)
        result.append(tdict)

    return {"tasks": result, "total": total}


@router.get("/tasks/scheduled")
def get_scheduled_tasks():
    """Get the currently scheduled periodic jobs."""
    if b_scheduler._active_scheduler is None:
        return {"jobs": []}

    jobs = b_scheduler._active_scheduler.get_jobs()
    result = []
    for job in jobs:
        result.append(
            {
                "id": job.id,
                "name": job.name,
                "next_run_time": _as_utc(job.next_run_time),
                "interval_seconds": getattr(job.trigger, "interval", timedelta()).total_seconds()
                if hasattr(job.trigger, "interval")
                else None,
            }
        )

    return {"jobs": result}

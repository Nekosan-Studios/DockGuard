from datetime import timedelta
from fastapi import APIRouter, Depends, Query
from sqlmodel import Session, select

from ..database import db
from ..models import SystemTask
from ..api_helpers import _as_utc
from .. import scheduler as b_scheduler

router = APIRouter(tags=["Tasks"])

@router.get("/tasks")
def get_recent_tasks(
    limit: int = Query(default=100, le=500),
    session: Session = Depends(db.get_session)
):
    """Get the recent history of background tasks (scheduled jobs, scans)."""
    tasks = session.exec(
        select(SystemTask).order_by(SystemTask.created_at.desc()).limit(limit)
    ).all()
    
    result = []
    for t in tasks:
        tdict = t.model_dump()
        tdict["created_at"] = _as_utc(t.created_at)
        tdict["started_at"] = _as_utc(t.started_at)
        tdict["finished_at"] = _as_utc(t.finished_at)
        result.append(tdict)
        
    return {"tasks": result}


@router.get("/tasks/scheduled")
def get_scheduled_tasks():
    """Get the currently scheduled periodic jobs."""
    if b_scheduler._active_scheduler is None:
        return {"jobs": []}
        
    jobs = b_scheduler._active_scheduler.get_jobs()
    result = []
    for job in jobs:
        result.append({
            "id": job.id,
            "name": job.name,
            "next_run_time": _as_utc(job.next_run_time),
            "interval_seconds": getattr(job.trigger, "interval", timedelta()).total_seconds() if hasattr(job.trigger, "interval") else None
        })
        
    return {"jobs": result}

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlmodel import Session

from .. import scheduler as b_scheduler
from ..config import ConfigManager
from ..database import db

router = APIRouter(tags=["Settings"])


class SettingsUpdate(BaseModel):
    settings: dict[str, str]


@router.get("/settings")
def get_settings(session: Session = Depends(db.get_session)):
    """Get all configurable settings."""
    return ConfigManager.get_all_settings(session)


@router.patch("/settings")
def update_settings(
    update_data: SettingsUpdate,
    session: Session = Depends(db.get_session),
):
    """Update one or more settings."""
    for key, value in update_data.settings.items():
        try:
            success = ConfigManager.set_setting(key, value, session)
            if not success:
                raise HTTPException(
                    status_code=400,
                    detail=f"Setting '{key}' is overridden by an environment variable"
                    " and cannot be modified via the API.",
                )
        except KeyError:
            raise HTTPException(status_code=400, detail=f"Unknown setting: '{key}'")

    if b_scheduler._active_scheduler is not None:
        b_scheduler._active_scheduler.update_job_intervals()

    return {"status": "success"}

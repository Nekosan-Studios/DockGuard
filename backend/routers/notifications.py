import logging
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlmodel import Session, col, func, select

from ..database import db
from ..models import NotificationChannel, NotificationLog
from ..services import notifier

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/notifications", tags=["Notifications"])


class ChannelCreate(BaseModel):
    name: str
    apprise_url: str
    enabled: bool = True
    notify_urgent: bool = False
    notify_kev: bool = False
    notify_all_new: bool = False
    notify_digest: bool = False
    notify_eol: bool = False
    notify_scan_failure: bool = False


class ChannelUpdate(BaseModel):
    name: str | None = None
    apprise_url: str | None = None
    enabled: bool | None = None
    notify_urgent: bool | None = None
    notify_kev: bool | None = None
    notify_all_new: bool | None = None
    notify_digest: bool | None = None
    notify_eol: bool | None = None
    notify_scan_failure: bool | None = None


@router.get("/channels")
def list_channels(session: Session = Depends(db.get_session)):
    channels = session.exec(select(NotificationChannel).order_by(NotificationChannel.id)).all()
    return [_channel_dict(c) for c in channels]


@router.post("/channels", status_code=201)
def create_channel(data: ChannelCreate, session: Session = Depends(db.get_session)):
    if not notifier.validate_url(data.apprise_url):
        raise HTTPException(status_code=400, detail="Invalid Apprise URL format.")

    now = datetime.now(UTC)
    channel = NotificationChannel(
        name=data.name,
        apprise_url=data.apprise_url,
        enabled=data.enabled,
        notify_urgent=data.notify_urgent,
        notify_kev=data.notify_kev,
        notify_all_new=data.notify_all_new,
        notify_digest=data.notify_digest,
        notify_eol=data.notify_eol,
        notify_scan_failure=data.notify_scan_failure,
        created_at=now,
        updated_at=now,
    )
    session.add(channel)
    session.commit()
    session.refresh(channel)
    return _channel_dict(channel)


@router.patch("/channels/{channel_id}")
def update_channel(channel_id: int, data: ChannelUpdate, session: Session = Depends(db.get_session)):
    channel = session.get(NotificationChannel, channel_id)
    if not channel:
        raise HTTPException(status_code=404, detail="Channel not found.")

    update_data = data.model_dump(exclude_unset=True)
    if "apprise_url" in update_data and not notifier.validate_url(update_data["apprise_url"]):
        raise HTTPException(status_code=400, detail="Invalid Apprise URL format.")

    for field, value in update_data.items():
        setattr(channel, field, value)
    channel.updated_at = datetime.now(UTC)

    session.add(channel)
    session.commit()
    session.refresh(channel)
    return _channel_dict(channel)


@router.delete("/channels/{channel_id}")
def delete_channel(channel_id: int, session: Session = Depends(db.get_session)):
    channel = session.get(NotificationChannel, channel_id)
    if not channel:
        raise HTTPException(status_code=404, detail="Channel not found.")

    # Delete associated logs first (SQLite has no cascade by default)
    logs = session.exec(select(NotificationLog).where(NotificationLog.channel_id == channel_id)).all()
    for log in logs:
        session.delete(log)

    session.delete(channel)
    session.commit()
    return {"status": "deleted"}


@router.post("/channels/{channel_id}/test")
async def test_channel(channel_id: int, session: Session = Depends(db.get_session)):
    channel = session.get(NotificationChannel, channel_id)
    if not channel:
        raise HTTPException(status_code=404, detail="Channel not found.")

    ok, error = await notifier.test(channel.apprise_url)
    log = NotificationLog(
        channel_id=channel_id,
        notification_type="test",
        title="DockGuard Test Notification",
        body="Test notification sent from DockGuard.",
        status="sent" if ok else "failed",
        error_message=error,
        created_at=datetime.now(UTC),
    )
    session.add(log)
    session.commit()

    if not ok:
        raise HTTPException(status_code=502, detail=f"Test notification failed: {error}")
    return {"status": "sent"}


@router.get("/log")
def get_log(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    session: Session = Depends(db.get_session),
):
    total = session.exec(select(func.count(NotificationLog.id))).one()
    offset = (page - 1) * page_size
    logs = session.exec(
        select(NotificationLog).order_by(col(NotificationLog.created_at).desc()).offset(offset).limit(page_size)
    ).all()

    # Attach channel names
    channel_ids = {log.channel_id for log in logs}
    channels = (
        {
            c.id: c.name
            for c in session.exec(select(NotificationChannel).where(NotificationChannel.id.in_(channel_ids))).all()
        }
        if channel_ids
        else {}
    )  # type: ignore[union-attr]

    return {
        "entries": [
            {
                "id": log.id,
                "channel_id": log.channel_id,
                "channel_name": channels.get(log.channel_id, "Deleted"),
                "notification_type": log.notification_type,
                "title": log.title,
                "body": log.body,
                "status": log.status,
                "error_message": log.error_message,
                "created_at": log.created_at.isoformat() if log.created_at else None,
            }
            for log in logs
        ],
        "total": total,
    }


def _channel_dict(channel: NotificationChannel) -> dict:
    return {
        "id": channel.id,
        "name": channel.name,
        "apprise_url": channel.apprise_url,
        "body_maxlen": notifier.get_body_maxlen(channel.apprise_url),
        "enabled": channel.enabled,
        "notify_urgent": channel.notify_urgent,
        "notify_kev": channel.notify_kev,
        "notify_all_new": channel.notify_all_new,
        "notify_digest": channel.notify_digest,
        "notify_eol": channel.notify_eol,
        "notify_scan_failure": channel.notify_scan_failure,
        "created_at": channel.created_at.isoformat() if channel.created_at else None,
        "updated_at": channel.updated_at.isoformat() if channel.updated_at else None,
    }

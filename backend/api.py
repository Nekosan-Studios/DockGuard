import colorlog
import logging
import time
from collections import defaultdict
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone

from fastapi import Depends, FastAPI, HTTPException, Query
from sqlalchemy import case as sa_case, text as sa_text
from sqlmodel import Session, func, select

from typing import Dict, Any
from pydantic import BaseModel

from .database import db
from .docker_watcher import DockerWatcher
from .models import AppState, Scan, Vulnerability, SystemTask
from . import scheduler as b_scheduler
from .scheduler import ContainerScheduler
from .config import ConfigManager

logger = logging.getLogger(__name__)

_DESC_LIMIT = 250
_LOC_LIMIT = 5


def _serialise_vuln(v: Vulnerability) -> dict:
    """Convert a Vulnerability ORM object to a dict, truncating large text fields."""
    d = v.model_dump()
    if d.get("description") and len(d["description"]) > _DESC_LIMIT:
        d["description"] = d["description"][:_DESC_LIMIT] + "…"
    if d.get("locations"):
        paths = d["locations"].split("\n")
        if len(paths) > _LOC_LIMIT:
            d["locations"] = "\n".join(paths[:_LOC_LIMIT])
    return d


@asynccontextmanager
async def lifespan(_: FastAPI):
    db.init()
    # alembic.ini's fileConfig sets root logger to WARNING; restore to INFO
    # so app loggers (scheduler, grype_scanner, docker_watcher) are visible.
    colorlog.basicConfig(
        level=colorlog.INFO,
        format="%(asctime)s %(log_color)s%(levelname)-8s%(reset)s %(name)s - %(message)s",
        force=True,
    )
    scheduler = ContainerScheduler(db)
    scheduler.start()
    yield
    scheduler.shutdown()


app = FastAPI(lifespan=lifespan)
router = app.router


# ---------------------------------------------------------------------------
# Tasks endpoints
# ---------------------------------------------------------------------------

@app.get("/tasks")
def get_recent_tasks(
    limit: int = Query(default=100, le=500),
    session: Session = Depends(db.get_session)
):
    """Get the recent history of background tasks (scheduled jobs, scans)."""
    tasks = session.exec(
        select(SystemTask).order_by(SystemTask.created_at.desc()).limit(limit)
    ).all()
    
    # Return as-is, just making sure datetimes are formatted nicely by FastAPI
    # SQLite datetimes are naive, attach UTC like we do for Scans.
    result = []
    for t in tasks:
        tdict = t.model_dump()
        tdict["created_at"] = _as_utc(t.created_at)
        tdict["started_at"] = _as_utc(t.started_at)
        tdict["finished_at"] = _as_utc(t.finished_at)
        result.append(tdict)
        
    return {"tasks": result}


@app.get("/tasks/scheduled")
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
            # Extract interval in seconds from the trigger if it's an IntervalTrigger
            "interval_seconds": getattr(job.trigger, "interval", timedelta()).total_seconds() if hasattr(job.trigger, "interval") else None
        })
        
    return {"jobs": result}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _as_utc(dt: datetime | None) -> datetime | None:
    """SQLite drops timezone info on storage; re-attach UTC before serializing.

    Without this, FastAPI emits '2024-01-15T10:30:00' (no Z). Browsers then
    treat that as *local* time instead of UTC, showing times shifted by the
    local UTC offset in the wrong direction.
    """
    if dt is None or dt.tzinfo is not None:
        return dt
    return dt.replace(tzinfo=timezone.utc)


def _latest_scan_for_ref(image_ref: str, session: Session) -> Scan:
    """Resolve the most recent scan by image_ref (name+tag) or image_digest."""
    if image_ref.startswith("sha256:"):
        stmt = select(Scan).where(Scan.image_digest == image_ref)
    else:
        stmt = select(Scan).where(Scan.image_name == image_ref)
    scan = session.exec(stmt.order_by(Scan.scanned_at.desc())).first()
    if not scan:
        raise HTTPException(status_code=404, detail=f"No scans found for '{image_ref}'")
    return scan


def _parse_image_query(image: str) -> tuple[str, str]:
    """Detect whether image is a digest, image_ref, or image_repository.

    Returns (filter_type, value) where filter_type is one of:
      "digest"           — sha256:...
      "image_ref"        — nginx:latest, ghcr.io/owner/repo:tag
      "image_repository" — nginx, ghcr.io/owner/repo
    """
    if image.startswith("sha256:"):
        return "digest", image
    last_colon = image.rfind(":")
    if last_colon != -1 and "/" not in image[last_colon + 1:]:
        return "image_ref", image
    return "image_repository", image


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

class SettingsUpdate(BaseModel):
    settings: Dict[str, str]

@app.get("/settings")
def get_settings(session: Session = Depends(db.get_session)):
    """Get all configurable settings."""
    return ConfigManager.get_all_settings(session)

@app.patch("/settings")
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
                    detail=f"Setting '{key}' is overridden by an environment variable and cannot be modified via the API."
                )
        except KeyError:
            raise HTTPException(status_code=400, detail=f"Unknown setting: '{key}'")

    # If the active scheduler is running, tell it to pick up the new intervals.
    if b_scheduler._active_scheduler is not None:
        b_scheduler._active_scheduler.update_job_intervals()

    return {"status": "success"}


@app.get("/images/vulnerabilities")
def get_vulnerabilities(
    image_ref: str = Query(..., description="Image reference: name+tag (nginx:latest) or digest (sha256:...)"),
    severity: str | None = Query(None, description="Filter by severity (e.g. Critical, High)"),
    session: Session = Depends(db.get_session),
):
    """Vulnerabilities for the most recent scan of an image, optionally filtered by severity."""
    t0 = time.perf_counter()
    scan = _latest_scan_for_ref(image_ref, session)
    q = select(Vulnerability).where(Vulnerability.scan_id == scan.id)
    if severity:
        q = q.where(Vulnerability.severity == severity)
    vulns = session.exec(q).all()
    serialised = [_serialise_vuln(v) for v in vulns]
    elapsed_ms = (time.perf_counter() - t0) * 1000
    payload_est = sum(len(d.get("description") or "") + len(d.get("locations") or "") for d in serialised)
    logger.info(
        "GET /images/vulnerabilities image_ref=%s severity=%s count=%d payload_est=%dB db_ms=%.1f",
        image_ref, severity, len(serialised), payload_est, elapsed_ms,
    )
    return {"scan_id": scan.id, "scanned_at": _as_utc(scan.scanned_at), "count": len(serialised), "vulnerabilities": serialised}


@app.get("/images/vulnerabilities/critical")
def get_critical_vulnerabilities(
    image_ref: str = Query(..., description="Image reference: name+tag (nginx:latest) or digest (sha256:...)"),
    session: Session = Depends(db.get_session),
):
    """Critical vulnerabilities for the most recent scan of an image."""
    scan = _latest_scan_for_ref(image_ref, session)
    vulns = session.exec(
        select(Vulnerability)
        .where(Vulnerability.scan_id == scan.id)
        .where(Vulnerability.severity == "Critical")
    ).all()
    serialised = [_serialise_vuln(v) for v in vulns]
    return {"scan_id": scan.id, "scanned_at": _as_utc(scan.scanned_at), "count": len(serialised), "vulnerabilities": serialised}


@app.get("/vulnerabilities/critical/running")
def get_critical_vulnerabilities_running(session: Session = Depends(db.get_session)):
    """Critical vulnerabilities across all currently running containers."""
    watcher = DockerWatcher()
    running_images = {img["image_name"] for img in watcher.list_running_containers()}
    if not running_images:
        return {"running_images": [], "count": 0, "vulnerabilities": []}

    results = []
    for image_name in running_images:
        try:
            scan = _latest_scan_for_ref(image_name, session)
        except HTTPException:
            continue
        vulns = session.exec(
            select(Vulnerability)
            .where(Vulnerability.scan_id == scan.id)
            .where(Vulnerability.severity == "Critical")
        ).all()
        results.extend(vulns)

    return {"running_images": list(running_images), "count": len(results), "vulnerabilities": results}


@app.get("/vulnerabilities/count")
def get_total_vulnerability_count(session: Session = Depends(db.get_session)):
    """Total vulnerability count across the latest scan of every image."""
    latest_scan_ids = select(func.max(Scan.id)).group_by(Scan.image_name)
    count = session.exec(
        select(func.count(Vulnerability.id))
        .where(Vulnerability.scan_id.in_(latest_scan_ids))
    ).one()
    return {"total_vulnerability_count": count}


@app.get("/vulnerabilities")
def get_vulnerabilities_across_running(
    report: str = Query(
        "all", 
        description="Filter report type. Options: 'critical', 'kev', 'new', 'all'"
    ),
    session: Session = Depends(db.get_session)
):
    """Vulnerabilities across all running containers, grouped by vulnerability."""
    watcher = DockerWatcher()
    running = watcher.list_running_containers()
    if not running:
        return {"report": report, "count": 0, "vulnerabilities": []}

    image_names = {img["image_name"] for img in running}
    
    # Get the latest scan for each running image
    latest_scan_id_subq = (
        select(func.max(Scan.id))
        .where(Scan.image_name.in_(image_names))
        .group_by(Scan.image_name)
    )
    scans = session.exec(select(Scan).where(Scan.id.in_(latest_scan_id_subq))).all()
    
    scan_id_to_images = {s.id: s.image_name for s in scans}
    
    if not scan_id_to_images:
        return {"report": report, "count": 0, "vulnerabilities": []}

    # Map image_name -> list of container names
    image_to_containers = defaultdict(list)
    for c in running:
        image_to_containers[c["image_name"]].append(c["container_name"])

    # Base query for vulnerabilities
    q = select(Vulnerability).where(Vulnerability.scan_id.in_(scan_id_to_images.keys()))

    # Apply report filters
    if report == "critical":
        q = q.where(Vulnerability.severity == "Critical")
    elif report == "kev":
        q = q.where(Vulnerability.is_kev == True)
    elif report == "new":
        cutoff_24h = datetime.now(timezone.utc) - timedelta(hours=24)
        q = q.where(Vulnerability.first_seen_at >= cutoff_24h)
        
    vulns = session.exec(q).all()

    # Group identical vulnerabilities across different containers
    # Grouping key: vuln_id + package_name + installed_version
    grouped_vulns = {}
    
    for v in vulns:
        img_name = scan_id_to_images[v.scan_id]
        containers_for_img = image_to_containers[img_name]
        
        # Unique key for a specific vulnerability in a specific package version
        key = f"{v.vuln_id}|{v.package_name}|{v.installed_version}"
        
        if key not in grouped_vulns:
            # First time seeing this vuln, initialize its data
            vd = _serialise_vuln(v)
            vd["containers"] = [{"image_name": img_name, "container_name": c} for c in containers_for_img]
            grouped_vulns[key] = vd
        else:
            # We've seen this vuln before, just add the new containers to the list
            existing_containers = grouped_vulns[key]["containers"]
            # To avoid duplicates if multiple scans report the same vuln for the same image
            for c in containers_for_img:
                c_data = {"image_name": img_name, "container_name": c}
                if c_data not in existing_containers:
                    existing_containers.append(c_data)
                    
            # Merge locations if they differ
            if v.locations and grouped_vulns[key].get("locations"):
                if v.locations not in grouped_vulns[key]["locations"]:
                    grouped_vulns[key]["locations"] += f"\n{v.locations}"
                    # Re-apply the truncation logic from _serialise_vuln
                    paths = grouped_vulns[key]["locations"].split("\n")
                    if len(paths) > _LOC_LIMIT:
                        grouped_vulns[key]["locations"] = "\n".join(paths[:_LOC_LIMIT])
            elif v.locations and not grouped_vulns[key].get("locations"):
                grouped_vulns[key]["locations"] = v.locations

    # Sort results to match container view: Severity then CVSS
    severity_order = {'Critical': 0, 'High': 1, 'Medium': 2, 'Low': 3, 'Negligible': 4, 'Unknown': 5}
    
    sorted_vulns = sorted(
        grouped_vulns.values(), 
        key=lambda x: (
            severity_order.get(x["severity"], 99),
            -(x.get("cvss_base_score") or 0)
        )
    )

    # Re-apply _DESC_LIMIT and _LOC_LIMIT as needed if we merged strings
    for vd in sorted_vulns:
        if vd.get("description") and len(vd["description"]) > _DESC_LIMIT:
            if not vd["description"].endswith("…"):
                vd["description"] = vd["description"][:_DESC_LIMIT] + "…"

    return {
        "report": report,
        "count": len(sorted_vulns), 
        "vulnerabilities": sorted_vulns
    }


@app.get("/images/vulnerabilities/history")
def get_vulnerability_count_history(
    image: str = Query(
        ...,
        description=(
            "Image identifier — one of: "
            "image_repository (nginx), "
            "image_ref (nginx:latest), "
            "or image_digest (sha256:...)"
        ),
    ),
    session: Session = Depends(db.get_session),
):
    """Vulnerability counts over time for an image.

    Query by image_repository to get history across all tags, by image_ref for a
    specific tag, or by image_digest for an exact image version.
    Each history entry includes image_ref so you can see which tag was scanned.
    """
    filter_type, value = _parse_image_query(image)

    stmt = select(Scan)
    if filter_type == "digest":
        stmt = stmt.where(Scan.image_digest == value)
    elif filter_type == "image_ref":
        stmt = stmt.where(Scan.image_name == value)
    else:
        stmt = stmt.where(Scan.image_repository == value)

    scans = session.exec(stmt.order_by(Scan.scanned_at.asc())).all()
    if not scans:
        raise HTTPException(status_code=404, detail=f"No scans found for '{image}'")

    history = []
    for scan in scans:
        count = session.exec(
            select(func.count(Vulnerability.id))
            .where(Vulnerability.scan_id == scan.id)
        ).one()
        history.append({
            "scan_id": scan.id,
            "scanned_at": _as_utc(scan.scanned_at),
            "image_ref": scan.image_name,
            "image_digest": scan.image_digest,
            "total": count,
        })

    return {"image": image, "history": history}


@app.get("/containers/running")
def get_running_containers(session: Session = Depends(db.get_session)):
    """Running containers with their latest scan's vulnerability breakdown."""
    watcher = DockerWatcher()
    running = watcher.list_running_containers()
    if not running:
        return {"containers": []}

    image_names = [img["image_name"] for img in running]
    latest_scan_id_subq = (
        select(func.max(Scan.id))
        .where(Scan.image_name.in_(image_names))
        .group_by(Scan.image_name)
    )
    scans_by_image = {
        s.image_name: s
        for s in session.exec(select(Scan).where(Scan.id.in_(latest_scan_id_subq))).all()
    }

    scan_ids = [s.id for s in scans_by_image.values()]
    severity_by_scan: dict[int, dict[str, int]] = defaultdict(dict)
    if scan_ids:
        for scan_id, severity, cnt in session.exec(
            select(Vulnerability.scan_id, Vulnerability.severity, func.count(Vulnerability.id))
            .where(Vulnerability.scan_id.in_(scan_ids))
            .group_by(Vulnerability.scan_id, Vulnerability.severity)
        ).all():
            severity_by_scan[scan_id][severity] = cnt

    containers = []
    for img in running:
        scan = scans_by_image.get(img["image_name"])
        if not scan:
            containers.append({
                "container_name": img["container_name"],
                "image_name": img["image_name"],
                "image_repository": None,
                "image_digest": None,
                "scan_id": None,
                "scanned_at": None,
                "vulns_by_severity": {},
                "total": 0,
                "has_scan": False,
            })
            continue

        vulns_by_severity = severity_by_scan.get(scan.id, {})
        containers.append({
            "container_name": img["container_name"],
            "image_name": scan.image_name,
            "image_repository": scan.image_repository,
            "image_digest": scan.image_digest,
            "scan_id": scan.id,
            "scanned_at": _as_utc(scan.scanned_at),
            "vulns_by_severity": vulns_by_severity,
            "total": sum(vulns_by_severity.values()),
            "has_scan": True,
        })

    return {"containers": containers}


@app.get("/dashboard/summary")
def get_dashboard_summary(session: Session = Depends(db.get_session)):
    """Single-call summary for the dashboard: running containers, images scanned,
    critical/KEV counts across running containers, and a 30-day critical vuln trend."""
    try:
        watcher = DockerWatcher()
        running = watcher.list_running_containers()
        docker_connected = True
    except Exception:
        running = []
        docker_connected = False
    running_images = {img["image_name"] for img in running}

    images_scanned = session.exec(
        select(func.count(func.distinct(Scan.image_name)))
    ).one()

    if running_images:
        latest_scan_id_subq = (
            select(func.max(Scan.id))
            .where(Scan.image_name.in_(running_images))
            .group_by(Scan.image_name)
        )
        row = session.exec(
            select(
                func.coalesce(func.sum(sa_case((Vulnerability.severity == "Critical", 1), else_=0)), 0),
                func.coalesce(func.sum(sa_case((Vulnerability.is_kev == True, 1), else_=0)), 0),  # noqa: E712
            ).where(Vulnerability.scan_id.in_(latest_scan_id_subq))
        ).one()
        critical_count, kev_count = int(row[0]), int(row[1])
    else:
        critical_count, kev_count = 0, 0

    # 30-day trend: critical vulns per day, deduped to latest scan per image per day
    cutoff = datetime.now(timezone.utc) - timedelta(days=30)
    recent_scans = session.exec(
        select(Scan).where(Scan.scanned_at >= cutoff).order_by(Scan.scanned_at.asc())
    ).all()

    day_image_scan: dict[str, dict[str, Scan]] = defaultdict(dict)
    for scan in recent_scans:
        day = scan.scanned_at.date().isoformat()
        day_image_scan[day][scan.image_name] = scan  # later scan overwrites earlier

    trend_scan_ids = [s.id for day_scans in day_image_scan.values() for s in day_scans.values()]
    if trend_scan_ids:
        crit_rows = session.exec(
            select(Vulnerability.scan_id, func.count(Vulnerability.id))
            .where(Vulnerability.scan_id.in_(trend_scan_ids))
            .where(Vulnerability.severity == "Critical")
            .group_by(Vulnerability.scan_id)
        ).all()
        critical_by_scan = dict(crit_rows)
    else:
        critical_by_scan = {}

    trend = [
        {"date": day, "critical": sum(critical_by_scan.get(s.id, 0) for s in day_image_scan[day].values())}
        for day in sorted(day_image_scan.keys())
    ]

    # Status bar fields: prefer AppState (updated each hourly DB check) so values
    # are always current; fall back to latest scan for installs that haven't
    # yet run a DB check with the updated scheduler.
    app_state = session.get(AppState, 1)
    last_db_checked_at = _as_utc(app_state.last_db_checked_at) if app_state else None
    grype_version = (app_state.grype_version if app_state else None)
    db_built = _as_utc(app_state.db_built) if app_state else None

    if not grype_version or not db_built:
        latest_scan = session.exec(select(Scan).order_by(Scan.scanned_at.desc()).limit(1)).first()
        grype_version = grype_version or (latest_scan.grype_version if latest_scan else None)
        db_built = db_built or (_as_utc(latest_scan.db_built) if latest_scan else None)

    cutoff_24h = datetime.now(timezone.utc) - timedelta(hours=24)
    new_vulns_24h = session.exec(
        select(func.count(Vulnerability.id))
        .where(Vulnerability.first_seen_at >= cutoff_24h)
    ).one()

    return {
        "running_containers": len(running),
        "images_scanned": images_scanned,
        "critical_count": critical_count,
        "kev_count": kev_count,
        "new_vulns_24h": int(new_vulns_24h),
        "trend": trend,
        "docker_connected": docker_connected,
        "grype_version": grype_version,
        "db_built": db_built,
        "last_db_checked_at": last_db_checked_at,
    }


@app.get("/activity/recent")
def get_recent_activity(
    limit: int = Query(default=5, le=20),
    session: Session = Depends(db.get_session),
):
    """Most recent scans with per-severity vulnerability counts."""
    scans = session.exec(
        select(Scan).order_by(Scan.scanned_at.desc()).limit(limit)
    ).all()

    scan_ids = [s.id for s in scans]
    severity_by_scan: dict[int, dict[str, int]] = defaultdict(dict)
    if scan_ids:
        for scan_id, severity, cnt in session.exec(
            select(Vulnerability.scan_id, Vulnerability.severity, func.count(Vulnerability.id))
            .where(Vulnerability.scan_id.in_(scan_ids))
            .group_by(Vulnerability.scan_id, Vulnerability.severity)
        ).all():
            severity_by_scan[scan_id][severity] = cnt

    result = []
    for scan in scans:
        vulns_by_severity = severity_by_scan.get(scan.id, {})
        result.append({
            "scan_id": scan.id,
            "scanned_at": _as_utc(scan.scanned_at),
            "image_name": scan.image_name,
            "image_digest": scan.image_digest,
            "container_name": scan.container_name,
            "vulns_by_severity": vulns_by_severity,
            "total": sum(vulns_by_severity.values()),
        })

    return {"activities": result}


@app.get("/db/tables")
def get_db_tables(session: Session = Depends(db.get_session)):
    """List application database tables (excludes alembic internals)."""
    rows = session.execute(
        sa_text("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'alembic%' ORDER BY name")
    ).fetchall()
    return {"tables": [r[0] for r in rows]}


@app.get("/db/table/{table_name}")
def get_db_table_rows(
    table_name: str,
    limit: int = Query(default=100, le=100),
    session: Session = Depends(db.get_session),
):
    """Return up to `limit` rows from a table (read-only)."""
    valid_tables = {
        r[0] for r in session.execute(
            sa_text("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'alembic%'")
        ).fetchall()
    }
    if table_name not in valid_tables:
        raise HTTPException(status_code=404, detail=f"Table '{table_name}' not found")

    col_rows = session.execute(sa_text(f'PRAGMA table_info("{table_name}")')).fetchall()
    columns = [r[1] for r in col_rows]

    rows = session.execute(
        sa_text(f'SELECT * FROM "{table_name}" LIMIT :limit'),
        {"limit": limit},
    ).fetchall()

    return {
        "table": table_name,
        "columns": columns,
        "rows": [dict(zip(columns, row)) for row in rows],
        "count": len(rows),
    }

import colorlog
import logging
from pathlib import Path
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

_DESC_LIMIT = 1000
_LOC_LIMIT = 5

# Allowed values for the sort_by query parameter across vulnerability endpoints.
_VALID_SORT_COLS = {
    "severity", "cvss_base_score", "epss_score", "is_kev",
    "first_seen_at", "vuln_id", "package_name",
}
_SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Negligible", "Unknown"]


def _severity_rank(s: str) -> int:
    try:
        return _SEVERITY_ORDER.index(s)
    except ValueError:
        return 99


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
    t_start = time.perf_counter()
    logger.info("Startup: beginning lifespan init")

    db.init()
    logger.info("Startup: db.init() done (%.2fs)", time.perf_counter() - t_start)

    # alembic.ini's fileConfig sets root logger to WARNING; restore to INFO
    # so app loggers (scheduler, grype_scanner, docker_watcher) are visible.
    colorlog.basicConfig(
        level=colorlog.INFO,
        format="%(asctime)s %(log_color)s%(levelname)-8s%(reset)s %(name)s - %(message)s",
        force=True,
    )

    scheduler = ContainerScheduler(db)
    logger.info("Startup: ContainerScheduler created (%.2fs)", time.perf_counter() - t_start)

    scheduler.start()
    logger.info("Startup: scheduler started — ready in %.2fs total", time.perf_counter() - t_start)
    yield
    scheduler.shutdown()


app = FastAPI(lifespan=lifespan)
router = app.router

_APP_VERSION = (Path(__file__).resolve().parent.parent / "VERSION").read_text().strip()


@app.get("/version")
def get_version():
    return {"version": _APP_VERSION}


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
    sort_by: str = Query("severity", description="Column to sort by"),
    sort_dir: str = Query("asc", description="Sort direction: asc or desc"),
    limit: int = Query(default=200, le=500, description="Max rows per page"),
    offset: int = Query(default=0, ge=0, description="Row offset for pagination"),
    session: Session = Depends(db.get_session),
):
    """Vulnerabilities for the most recent scan of an image, with server-side sort and pagination."""
    if sort_by not in _VALID_SORT_COLS:
        from fastapi import HTTPException as _HTTPException
        raise _HTTPException(status_code=422, detail=f"Invalid sort_by value: '{sort_by}'")

    t0 = time.perf_counter()
    scan = _latest_scan_for_ref(image_ref, session)
    q = select(Vulnerability).where(Vulnerability.scan_id == scan.id)
    if severity:
        q = q.where(Vulnerability.severity == severity)

    # Apply server-side ORDER BY where SQL can handle it efficiently.
    # Severity uses a Python sort below since SQL doesn't know our severity order.
    desc = sort_dir == "desc"
    if sort_by == "cvss_base_score":
        q = q.order_by(Vulnerability.cvss_base_score.desc() if desc else Vulnerability.cvss_base_score.asc(),
                       Vulnerability.id.asc())
    elif sort_by == "epss_score":
        q = q.order_by(Vulnerability.epss_score.desc() if desc else Vulnerability.epss_score.asc(),
                       Vulnerability.id.asc())
    elif sort_by == "is_kev":
        q = q.order_by(Vulnerability.is_kev.desc() if desc else Vulnerability.is_kev.asc(),
                       Vulnerability.id.asc())
    elif sort_by == "first_seen_at":
        q = q.order_by(Vulnerability.first_seen_at.desc() if desc else Vulnerability.first_seen_at.asc(),
                       Vulnerability.id.asc())
    elif sort_by == "vuln_id":
        q = q.order_by(Vulnerability.vuln_id.desc() if desc else Vulnerability.vuln_id.asc())
    elif sort_by == "package_name":
        q = q.order_by(Vulnerability.package_name.desc() if desc else Vulnerability.package_name.asc())
    # severity: fetch all and sort in Python (non-lexicographic order)

    vulns = session.exec(q).all()

    # For severity sort, apply Python ordering after fetch.
    if sort_by == "severity":
        m = -1 if desc else 1
        vulns = sorted(vulns, key=lambda v: (m * _severity_rank(v.severity), -(v.cvss_base_score or 0)))

    total_count = len(vulns)
    page_vulns = vulns[offset: offset + limit]
    serialised = [_serialise_vuln(v) for v in page_vulns]
    has_more = (offset + limit) < total_count

    elapsed_ms = (time.perf_counter() - t0) * 1000
    logger.info(
        "GET /images/vulnerabilities image_ref=%s severity=%s sort=%s%s offset=%d limit=%d "
        "total=%d page=%d db_ms=%.1f",
        image_ref, severity, sort_by, f":{sort_dir}", offset, limit,
        total_count, len(serialised), elapsed_ms,
    )
    return {
        "scan_id": scan.id,
        "scanned_at": _as_utc(scan.scanned_at),
        "is_distro_eol": scan.is_distro_eol,
        "distro_display": f"{scan.distro_name} {scan.distro_version}" if scan.distro_name and scan.distro_version else scan.distro_name,
        "has_vex": scan.vex_status == "found",
        "total_count": total_count,
        "count": len(serialised),
        "has_more": has_more,
        "vulnerabilities": serialised,
    }


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
        description="Filter report type. Options: 'critical', 'kev', 'new', 'vex_annotated', 'all'"
    ),
    new_hours: int = Query(default=24, ge=1, le=336, description="Hours lookback for 'new' report (default 24)"),
    sort_by: str = Query("severity", description="Column to sort by"),
    sort_dir: str = Query("asc", description="Sort direction: asc or desc"),
    limit: int = Query(default=100, le=500, description="Max rows per page"),
    offset: int = Query(default=0, ge=0, description="Row offset for pagination"),
    session: Session = Depends(db.get_session)
):
    """Vulnerabilities across all running containers, grouped by vulnerability, with server-side sort and pagination."""
    if sort_by not in _VALID_SORT_COLS:
        from fastapi import HTTPException as _HTTPException
        raise _HTTPException(status_code=422, detail=f"Invalid sort_by value: '{sort_by}'")

    watcher = DockerWatcher()
    running = watcher.list_running_containers()
    if not running:
        return {"report": report, "total_count": 0, "count": 0, "has_more": False, "eol_images": [], "vulnerabilities": []}

    image_names = {img["image_name"] for img in running}

    # Get the latest scan for each running image
    latest_scan_id_subq = (
        select(func.max(Scan.id))
        .where(Scan.image_name.in_(image_names))
        .group_by(Scan.image_name)
    )
    scans = session.exec(select(Scan).where(Scan.id.in_(latest_scan_id_subq))).all()

    # Map image_name -> list of container names
    image_to_containers = defaultdict(list)
    for c in running:
        image_to_containers[c["image_name"]].append(c["container_name"])

    scan_id_to_images = {s.id: s.image_name for s in scans}
    
    eol_images = []
    for s in scans:
        if s.is_distro_eol:
            for c_name in image_to_containers[s.image_name]:
                eol_images.append({
                    "container_name": c_name,
                    "distro": f"{s.distro_name} {s.distro_version}" if s.distro_name and s.distro_version else s.distro_name,
                })

    if not scan_id_to_images:
        return {"report": report, "total_count": 0, "count": 0, "has_more": False, "eol_images": [], "vulnerabilities": []}

    # Base query for vulnerabilities
    q = select(Vulnerability).where(Vulnerability.scan_id.in_(scan_id_to_images.keys()))

    # Apply report filters
    if report == "critical":
        q = q.where(Vulnerability.severity == "Critical")
    elif report == "kev":
        q = q.where(Vulnerability.is_kev == True)
    elif report == "new":
        cutoff = datetime.now(timezone.utc) - timedelta(hours=new_hours)
        q = q.where(Vulnerability.first_seen_at >= cutoff)
    elif report == "vex_annotated":
        q = q.where(Vulnerability.vex_status.isnot(None))

    vulns = session.exec(q).all()

    # Group vulnerabilities by CVE ID across all containers/packages
    grouped_vulns: dict[str, dict] = {}

    total_instances = 0

    for v in vulns:
        img_name = scan_id_to_images[v.scan_id]
        containers_for_img = image_to_containers[img_name]
        total_instances += len(containers_for_img)

        key = v.vuln_id

        pkg_entry = {
            "package_name": v.package_name,
            "installed_version": v.installed_version,
            "fixed_version": v.fixed_version,
            "package_type": v.package_type,
            "locations": v.locations,
            "severity": v.severity,
            "cvss_base_score": v.cvss_base_score,
        }

        if key not in grouped_vulns:
            vd = _serialise_vuln(v)
            vd["containers"] = [{"image_name": img_name, "container_name": c} for c in containers_for_img]
            vd["packages"] = [pkg_entry]
            grouped_vulns[key] = vd
        else:
            gv = grouped_vulns[key]

            # Add new containers
            existing_containers = gv["containers"]
            for c in containers_for_img:
                c_data = {"image_name": img_name, "container_name": c}
                if c_data not in existing_containers:
                    existing_containers.append(c_data)

            # Add package if not already present (by name + version)
            existing_pkgs = gv["packages"]
            pkg_key = (v.package_name, v.installed_version)
            if not any((p["package_name"], p["installed_version"]) == pkg_key for p in existing_pkgs):
                existing_pkgs.append(pkg_entry)

            # Promote row-level severity/CVSS to the worst values
            if _severity_rank(v.severity) < _severity_rank(gv.get("severity", "Unknown")):
                gv["severity"] = v.severity
            v_cvss = v.cvss_base_score or 0
            if v_cvss > (gv.get("cvss_base_score") or 0):
                gv["cvss_base_score"] = v.cvss_base_score

    # Sort packages within each group: worst severity, then highest CVSS, then alphabetical
    for vd in grouped_vulns.values():
        vd["packages"].sort(key=lambda p: (
            _severity_rank(p.get("severity", "Unknown")),
            -(p.get("cvss_base_score") or 0),
            p.get("package_name", ""),
        ))
        # Set representative package fields for sorting and display
        rep = vd["packages"][0]
        vd["package_name"] = rep["package_name"]
        vd["installed_version"] = rep["installed_version"]
        vd["fixed_version"] = rep["fixed_version"]
        vd["package_type"] = rep["package_type"]
        vd["locations"] = rep["locations"]

    # Sort the fully-grouped result set in Python.
    desc = sort_dir == "desc"
    m = -1 if desc else 1

    def _clean_sort_key(vd: dict):
        if sort_by == "severity":
            rank = _severity_rank(vd.get("severity", "Unknown"))
            cvss = vd.get("cvss_base_score") or 0
            return (rank if not desc else -rank, -cvss)
        if sort_by == "cvss_base_score":
            score = vd.get("cvss_base_score")
            null_last = 1 if score is None else 0
            val = -(score or 0) if not desc else (score or 0)
            return (null_last, val)
        if sort_by == "epss_score":
            score = vd.get("epss_score")
            null_last = 1 if score is None else 0
            val = -(score or 0) if not desc else (score or 0)
            return (null_last, val)
        if sort_by == "is_kev":
            # True first when desc, False first when asc
            kev_val = 0 if vd.get("is_kev") else 1
            return (kev_val if not desc else -kev_val, 0)
        if sort_by == "first_seen_at":
            ts_raw = vd.get("first_seen_at")
            # model_dump() returns datetime objects; convert to ISO string for comparison
            ts = ts_raw.isoformat() if hasattr(ts_raw, "isoformat") else (ts_raw or "")
            null_last = 1 if not ts else 0
            return (null_last, ts if not desc else ("" if not ts else "".join(chr(0xFFFF - min(ord(c), 0xFFFE)) for c in ts[:20])))
        if sort_by == "vuln_id":
            s = vd.get("vuln_id", "")
            return s if not desc else "".join(chr(0xFFFF - min(ord(c), 0xFFFE)) for c in s)
        if sort_by == "package_name":
            s = vd.get("package_name", "")
            return s if not desc else "".join(chr(0xFFFF - min(ord(c), 0xFFFE)) for c in s)
        return 0

    all_vulns = sorted(grouped_vulns.values(), key=_clean_sort_key)

    # Re-apply description truncation (may have been merged)
    for vd in all_vulns:
        if vd.get("description") and len(vd["description"]) > _DESC_LIMIT:
            if not vd["description"].endswith("…"):
                vd["description"] = vd["description"][:_DESC_LIMIT] + "…"

    total_count = len(all_vulns)
    page_vulns = all_vulns[offset: offset + limit]
    has_more = (offset + limit) < total_count

    return {
        "report": report,
        "total_count": total_count,
        "total_instances": total_instances,
        "count": len(page_vulns),
        "has_more": has_more,
        "eol_images": eol_images,
        "vulnerabilities": page_vulns,
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
                "is_distro_eol": False,
                "distro_display": None,
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
            "is_distro_eol": scan.is_distro_eol,
            "distro_display": f"{scan.distro_name} {scan.distro_version}" if scan.distro_name and scan.distro_version else scan.distro_name,
            "vulns_by_severity": vulns_by_severity,
            "total": sum(vulns_by_severity.values()),
            "has_scan": True,
            "has_vex": scan.vex_status == "found",
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

        eol_count = session.exec(
            select(func.count(Scan.id))
            .where(Scan.id.in_(latest_scan_id_subq))
            .where(Scan.is_distro_eol == True)  # noqa: E712
        ).one()
    else:
        critical_count, kev_count, eol_count = 0, 0, 0

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
    db_schema = (app_state.db_schema if app_state else None)
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

    active_tasks = session.exec(
        select(func.count(SystemTask.id))
        .where(SystemTask.status == "running")
    ).one()

    queued_tasks = session.exec(
        select(func.count(SystemTask.id))
        .where(SystemTask.status == "queued")
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
        "db_schema": db_schema,
        "db_built": db_built,
        "last_db_checked_at": last_db_checked_at,
        "active_tasks": int(active_tasks),
        "queued_tasks": int(queued_tasks),
        "eol_count": int(eol_count),
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

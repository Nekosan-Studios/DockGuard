import colorlog
from collections import defaultdict
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone

from fastapi import Depends, FastAPI, HTTPException, Query
from sqlmodel import Session, func, select

from .database import db
from .docker_watcher import DockerWatcher
from .models import AppState, Scan, Vulnerability
from .scheduler import ContainerScheduler


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

@app.get("/images/vulnerabilities")
def get_vulnerabilities(
    image_ref: str = Query(..., description="Image reference: name+tag (nginx:latest) or digest (sha256:...)"),
    session: Session = Depends(db.get_session),
):
    """All vulnerabilities for the most recent scan of an image."""
    scan = _latest_scan_for_ref(image_ref, session)
    vulns = session.exec(
        select(Vulnerability).where(Vulnerability.scan_id == scan.id)
    ).all()
    return {"scan_id": scan.id, "scanned_at": _as_utc(scan.scanned_at), "count": len(vulns), "vulnerabilities": vulns}


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
    return {"scan_id": scan.id, "scanned_at": _as_utc(scan.scanned_at), "count": len(vulns), "vulnerabilities": vulns}


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

    containers = []
    for img in running:
        try:
            scan = _latest_scan_for_ref(img["image_name"], session)
        except HTTPException:
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

        severity_rows = session.exec(
            select(Vulnerability.severity, func.count(Vulnerability.id))
            .where(Vulnerability.scan_id == scan.id)
            .group_by(Vulnerability.severity)
        ).all()
        vulns_by_severity = {sev: cnt for sev, cnt in severity_rows}
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

    critical_count = 0
    kev_count = 0
    for image_name in running_images:
        try:
            scan = _latest_scan_for_ref(image_name, session)
        except HTTPException:
            continue
        critical_count += session.exec(
            select(func.count(Vulnerability.id))
            .where(Vulnerability.scan_id == scan.id)
            .where(Vulnerability.severity == "Critical")
        ).one()
        kev_count += session.exec(
            select(func.count(Vulnerability.id))
            .where(Vulnerability.scan_id == scan.id)
            .where(Vulnerability.is_kev == True)  # noqa: E712
        ).one()

    # 30-day trend: critical vulns per day, deduped to latest scan per image per day
    cutoff = datetime.now(timezone.utc) - timedelta(days=30)
    recent_scans = session.exec(
        select(Scan).where(Scan.scanned_at >= cutoff).order_by(Scan.scanned_at.asc())
    ).all()

    day_image_scan: dict[str, dict[str, Scan]] = defaultdict(dict)
    for scan in recent_scans:
        day = scan.scanned_at.date().isoformat()
        day_image_scan[day][scan.image_name] = scan  # later scan overwrites earlier

    trend = []
    for day in sorted(day_image_scan.keys()):
        day_critical = sum(
            session.exec(
                select(func.count(Vulnerability.id))
                .where(Vulnerability.scan_id == s.id)
                .where(Vulnerability.severity == "Critical")
            ).one()
            for s in day_image_scan[day].values()
        )
        trend.append({"date": day, "critical": day_critical})

    # Status bar fields: grype version, vuln DB built date, last db check time
    latest_scan = session.exec(select(Scan).order_by(Scan.scanned_at.desc())).first()
    grype_version = latest_scan.grype_version if latest_scan else None
    db_built = _as_utc(latest_scan.db_built) if latest_scan else None

    app_state = session.get(AppState, 1)
    last_db_checked_at = _as_utc(app_state.last_db_checked_at) if app_state else None

    return {
        "running_containers": len(running),
        "images_scanned": images_scanned,
        "critical_count": critical_count,
        "kev_count": kev_count,
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

    result = []
    for scan in scans:
        severity_rows = session.exec(
            select(Vulnerability.severity, func.count(Vulnerability.id))
            .where(Vulnerability.scan_id == scan.id)
            .group_by(Vulnerability.severity)
        ).all()
        vulns_by_severity = {sev: cnt for sev, cnt in severity_rows}
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

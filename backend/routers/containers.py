from collections import defaultdict
from datetime import datetime, timedelta, timezone
from fastapi import APIRouter, Depends
from sqlalchemy import case as sa_case
from sqlmodel import Session, func, select

from ..database import db
from ..docker_watcher import DockerWatcher
from ..models import AppState, Scan, Vulnerability, SystemTask
from ..api_helpers import _severity_rank, _as_utc

router = APIRouter(tags=["Containers"])

@router.get("/containers/running")
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
        rows = session.exec(
            select(Vulnerability.scan_id, Vulnerability.vuln_id, Vulnerability.severity)
            .where(Vulnerability.scan_id.in_(scan_ids))
        ).all()
        best_severity: dict[tuple, str] = {}
        for scan_id, vuln_id, severity in rows:
            key = (scan_id, vuln_id)
            if key not in best_severity or _severity_rank(severity) < _severity_rank(best_severity[key]):
                best_severity[key] = severity
        for (scan_id, _vuln_id), severity in best_severity.items():
            severity_by_scan[scan_id][severity] = severity_by_scan[scan_id].get(severity, 0) + 1

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

@router.get("/dashboard/summary")
def get_dashboard_summary(session: Session = Depends(db.get_session)):
    """Single-call summary for the dashboard."""
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
                func.coalesce(func.sum(sa_case((Vulnerability.is_kev == True, 1), else_=0)), 0),
            ).where(Vulnerability.scan_id.in_(latest_scan_id_subq))
        ).one()
        critical_count, kev_count = int(row[0]), int(row[1])

        eol_count = session.exec(
            select(func.count(Scan.id))
            .where(Scan.id.in_(latest_scan_id_subq))
            .where(Scan.is_distro_eol == True)
        ).one()
    else:
        critical_count, kev_count, eol_count = 0, 0, 0

    cutoff = datetime.now(timezone.utc) - timedelta(days=30)
    recent_scans = session.exec(
        select(Scan).where(Scan.scanned_at >= cutoff).order_by(Scan.scanned_at.asc())
    ).all()

    day_image_scan: dict[str, dict[str, Scan]] = defaultdict(dict)
    for scan in recent_scans:
        day = scan.scanned_at.date().isoformat()
        day_image_scan[day][scan.image_name] = scan

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
    if running_images:
        new_vulns_24h = session.exec(
            select(func.count(Vulnerability.id))
            .where(Vulnerability.scan_id.in_(latest_scan_id_subq))
            .where(Vulnerability.first_seen_at >= cutoff_24h)
        ).one()
    else:
        new_vulns_24h = 0

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

@router.get("/activity/recent")
def get_recent_activity(
    limit: int = 5,
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

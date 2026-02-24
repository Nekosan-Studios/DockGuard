from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, HTTPException, Query
from sqlmodel import Session, func, select

from database import db
from docker_watcher import DockerWatcher
from models import Scan, Vulnerability


@asynccontextmanager
async def lifespan(app: FastAPI):
    db.init()
    # everything before yield runs at startup, after yield at shutdown
    yield


app = FastAPI(lifespan=lifespan)
router = app.router


# ---------------------------------------------------------------------------
# Helper: resolve the most recent scan for a given image name
# ---------------------------------------------------------------------------

def _latest_scan_for(image_name: str, session: Session) -> Scan:
    scan = session.exec(
        select(Scan)
        .where(Scan.image_name == image_name)
        .order_by(Scan.scanned_at.desc())
    ).first()
    if not scan:
        raise HTTPException(status_code=404, detail=f"No scans found for image '{image_name}'")
    return scan


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.get("/images/vulnerabilities")
def get_vulnerabilities(
    name: str = Query(..., description="Full image name, e.g. ghcr.io/owner/repo:latest"),
    session: Session = Depends(db.get_session),
):
    """All vulnerabilities for the most recent scan of an image."""
    scan = _latest_scan_for(name, session)
    vulns = session.exec(
        select(Vulnerability).where(Vulnerability.scan_id == scan.id)
    ).all()
    return {"scan_id": scan.id, "scanned_at": scan.scanned_at, "count": len(vulns), "vulnerabilities": vulns}


@app.get("/images/vulnerabilities/critical")
def get_critical_vulnerabilities(
    name: str = Query(..., description="Full image name, e.g. ghcr.io/owner/repo:latest"),
    session: Session = Depends(db.get_session),
):
    """Critical vulnerabilities for the most recent scan of an image."""
    scan = _latest_scan_for(name, session)
    vulns = session.exec(
        select(Vulnerability)
        .where(Vulnerability.scan_id == scan.id)
        .where(Vulnerability.severity == "Critical")
    ).all()
    return {"scan_id": scan.id, "scanned_at": scan.scanned_at, "count": len(vulns), "vulnerabilities": vulns}


@app.get("/vulnerabilities/critical/running")
def get_critical_vulnerabilities_running(session: Session = Depends(db.get_session)):
    """Critical vulnerabilities across all currently running containers."""
    watcher = DockerWatcher()
    running_images = {img["name"] for img in watcher.list_images() if img["running"]}
    if not running_images:
        return {"running_images": [], "count": 0, "vulnerabilities": []}

    results = []
    for image_name in running_images:
        try:
            scan = _latest_scan_for(image_name, session)
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
    name: str = Query(..., description="Full image name, e.g. ghcr.io/owner/repo:latest"),
    session: Session = Depends(db.get_session),
):
    """Vulnerability counts over time for an image, grouped by scan (digest version)."""
    scans = session.exec(
        select(Scan)
        .where(Scan.image_name == name)
        .order_by(Scan.scanned_at.asc())
    ).all()
    if not scans:
        raise HTTPException(status_code=404, detail=f"No scans found for image '{name}'")

    history = []
    for scan in scans:
        count = session.exec(
            select(func.count(Vulnerability.id))
            .where(Vulnerability.scan_id == scan.id)
        ).one()
        history.append({
            "scan_id": scan.id,
            "scanned_at": scan.scanned_at,
            "image_digest": scan.image_digest,
            "total": count,
        })

    return {"image_name": name, "history": history}

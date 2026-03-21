import logging
import time
from collections import defaultdict

from fastapi import APIRouter, Depends, Query
from sqlmodel import Session, func, select

from ..api_helpers import (
    _DESC_LIMIT,
    _VALID_SORT_COLS,
    _as_utc,
    _latest_scan_for_ref,
    _new_vuln_keys_for_scans,
    _parse_image_query,
    _serialise_vuln,
    _severity_rank,
    _vex_sort_rank,
)
from ..database import db
from ..docker_watcher import DockerWatcher
from ..models import Scan, Vulnerability

router = APIRouter(tags=["Vulnerabilities"])
logger = logging.getLogger(__name__)


@router.get("/images/vulnerabilities")
def get_vulnerabilities(
    image_ref: str = Query(..., description="Image reference: name+tag (nginx:latest) or digest (sha256:...)"),
    severity: str | None = Query(None, description="Filter by severity (e.g. Critical, High)"),
    priority: str | None = Query(None, description="Filter by priority bucket (Urgent, High, Medium, Low)"),
    hide_vex: bool = Query(False, description="Hide vulnerabilities resolved by VEX"),
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

    t_total = time.perf_counter()

    t0 = time.perf_counter()
    scan = _latest_scan_for_ref(image_ref, session)
    logger.info("[VulnLoad /images/vulnerabilities] latest_scan_for_ref: %.3fs", time.perf_counter() - t0)

    t0 = time.perf_counter()
    new_keys = _new_vuln_keys_for_scans(session, [scan]).get(scan.id, set())
    logger.info("[VulnLoad /images/vulnerabilities] new_vuln_keys: %.3fs", time.perf_counter() - t0)

    q = select(Vulnerability).where(Vulnerability.scan_id == scan.id)
    if hide_vex:
        q = q.where((Vulnerability.vex_status.is_(None)) | (~Vulnerability.vex_status.in_(["not_affected", "fixed"])))
    if severity:
        q = q.where(Vulnerability.severity == severity)
    if priority:
        if priority == "Urgent":
            q = q.where(Vulnerability.risk_score >= 80)
        elif priority == "High":
            q = q.where(Vulnerability.risk_score >= 50, Vulnerability.risk_score < 80)
        elif priority == "Medium":
            q = q.where(Vulnerability.risk_score >= 20, Vulnerability.risk_score < 50)
        elif priority == "Low":
            q = q.where((Vulnerability.risk_score < 20) | (Vulnerability.risk_score.is_(None)))

    t0 = time.perf_counter()
    vulns = session.exec(q).all()
    logger.info(
        "[VulnLoad /images/vulnerabilities] db fetch vulns: %.3fs (%d rows)", time.perf_counter() - t0, len(vulns)
    )

    # Group by vuln_id
    grouped_vulns: dict[str, dict] = {}
    t0 = time.perf_counter()
    for v in vulns:
        vuln_id = v.vuln_id
        new_key = (v.vuln_id, v.package_name, v.installed_version)
        pkg_entry = {
            "package_name": v.package_name,
            "installed_version": v.installed_version,
            "fixed_version": v.fixed_version,
            "package_type": v.package_type,
            "locations": v.locations,
            "severity": v.severity,
            "cvss_base_score": v.cvss_base_score,
        }
        if vuln_id not in grouped_vulns:
            vd = _serialise_vuln(v)
            vd["packages"] = [pkg_entry]
            vd["is_new"] = new_key in new_keys
            grouped_vulns[vuln_id] = vd
        else:
            gv = grouped_vulns[vuln_id]
            pkg_key = (v.package_name, v.installed_version)
            if not any((p["package_name"], p["installed_version"]) == pkg_key for p in gv["packages"]):
                gv["packages"].append(pkg_entry)
            if new_key in new_keys:
                gv["is_new"] = True
            if _severity_rank(v.severity) < _severity_rank(gv.get("severity", "Unknown")):
                gv["severity"] = v.severity
            v_cvss = v.cvss_base_score or 0
            if v_cvss > (gv.get("cvss_base_score") or 0):
                gv["cvss_base_score"] = v.cvss_base_score
            v_risk = v.risk_score or 0
            if v_risk > (gv.get("risk_score") or 0):
                gv["risk_score"] = v.risk_score

    logger.info(
        "[VulnLoad /images/vulnerabilities] python group+aggregate: %.3fs (%d unique CVEs)",
        time.perf_counter() - t0,
        len(grouped_vulns),
    )

    # Sort packages within each group
    for vd in grouped_vulns.values():
        vd["packages"].sort(
            key=lambda p: (
                _severity_rank(p.get("severity", "Unknown")),
                -(p.get("cvss_base_score") or 0),
                p.get("package_name", ""),
            )
        )
        rep = vd["packages"][0]
        vd["package_name"] = rep["package_name"]
        vd["installed_version"] = rep["installed_version"]
        vd["fixed_version"] = rep["fixed_version"]
        vd["package_type"] = rep["package_type"]
        vd["locations"] = rep["locations"]

    desc = sort_dir == "desc"

    def _image_sort_key(vd: dict):
        if sort_by == "severity":
            risk = vd.get("risk_score") or 0
            return -risk if not desc else risk
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
            kev_val = 0 if vd.get("is_kev") else 1
            return (kev_val if not desc else -kev_val, 0)
        if sort_by == "first_seen_at":
            ts_raw = vd.get("first_seen_at")
            ts = ts_raw.isoformat() if hasattr(ts_raw, "isoformat") else (ts_raw or "")
            null_last = 1 if not ts else 0
            return (
                null_last,
                ts if not desc else ("" if not ts else "".join(chr(0xFFFF - min(ord(c), 0xFFFE)) for c in ts[:20])),
            )
        if sort_by == "vuln_id":
            s = vd.get("vuln_id", "")
            return s if not desc else "".join(chr(0xFFFF - min(ord(c), 0xFFFE)) for c in s)
        if sort_by == "package_name":
            s = vd.get("package_name", "")
            return s if not desc else "".join(chr(0xFFFF - min(ord(c), 0xFFFE)) for c in s)
        if sort_by == "vex_status":
            rank = _vex_sort_rank(vd.get("vex_status"))
            null_last = 1 if vd.get("vex_status") is None else 0
            return (null_last, rank if not desc else -rank)
        return 0

    t0 = time.perf_counter()
    all_vulns = sorted(grouped_vulns.values(), key=_image_sort_key)
    logger.info("[VulnLoad /images/vulnerabilities] python sort: %.3fs", time.perf_counter() - t0)

    total_count = len(all_vulns)
    page_vulns = all_vulns[offset : offset + limit]
    has_more = (offset + limit) < total_count

    logger.info(
        "[VulnLoad /images/vulnerabilities] total: %.3fs (image=%s offset=%d limit=%d returning=%d of %d)",
        time.perf_counter() - t_total,
        image_ref,
        offset,
        limit,
        len(page_vulns),
        total_count,
    )

    return {
        "scan_id": scan.id,
        "scanned_at": _as_utc(scan.scanned_at),
        "is_distro_eol": scan.is_distro_eol,
        "distro_display": f"{scan.distro_name} {scan.distro_version}"
        if scan.distro_name and scan.distro_version
        else scan.distro_name,
        "has_vex": scan.vex_status == "found",
        "vex_status": scan.vex_status,
        "vex_error": scan.vex_error,
        "total_count": total_count,
        "count": len(page_vulns),
        "has_more": has_more,
        "vulnerabilities": page_vulns,
    }


@router.get("/vulnerabilities/count")
def get_total_vulnerability_count(session: Session = Depends(db.get_session)):
    """Total vulnerability count across the latest scan of every image."""
    latest_scan_ids = select(func.max(Scan.id)).group_by(Scan.image_name)
    count = session.exec(select(func.count(Vulnerability.id)).where(Vulnerability.scan_id.in_(latest_scan_ids))).one()
    return {"total_vulnerability_count": count}


@router.get("/images/vulnerabilities/critical")
def get_critical_vulnerabilities(
    image_ref: str = Query(..., description="Image reference: name+tag (nginx:latest) or digest (sha256:...)"),
    session: Session = Depends(db.get_session),
):
    """Critical vulnerabilities for the most recent scan of an image."""
    scan = _latest_scan_for_ref(image_ref, session)
    vulns = session.exec(
        select(Vulnerability).where(Vulnerability.scan_id == scan.id).where(Vulnerability.severity == "Critical")
    ).all()
    serialised = [_serialise_vuln(v) for v in vulns]
    return {
        "scan_id": scan.id,
        "scanned_at": _as_utc(scan.scanned_at),
        "count": len(serialised),
        "vulnerabilities": serialised,
    }


@router.get("/vulnerabilities/critical/running")
def get_critical_vulnerabilities_running(session: Session = Depends(db.get_session)):
    """Critical vulnerabilities across all currently running containers."""
    watcher = DockerWatcher()
    from fastapi import HTTPException as _HTTPException

    running_images = {img["image_name"] for img in watcher.list_running_containers()}
    if not running_images:
        return {"running_images": [], "count": 0, "vulnerabilities": []}

    results = []
    for image_name in running_images:
        try:
            scan = _latest_scan_for_ref(image_name, session)
        except _HTTPException:
            continue
        vulns = session.exec(
            select(Vulnerability).where(Vulnerability.scan_id == scan.id).where(Vulnerability.severity == "Critical")
        ).all()
        results.extend(vulns)

    return {"running_images": list(running_images), "count": len(results), "vulnerabilities": results}


@router.get("/vulnerabilities")
def get_vulnerabilities_across_running(
    report: str = Query(
        "all",
        description=(
            "Filter report type. Options: 'urgent', 'kev', 'new', 'vex_annotated', 'all'. "
            "The legacy value 'critical' is still accepted as an alias for 'urgent'."
        ),
    ),
    hide_vex: bool = Query(False, description="Hide vulnerabilities resolved by VEX"),
    sort_by: str = Query("severity", description="Column to sort by"),
    sort_dir: str = Query("asc", description="Sort direction: asc or desc"),
    limit: int = Query(default=100, le=500, description="Max rows per page"),
    offset: int = Query(default=0, ge=0, description="Row offset for pagination"),
    session: Session = Depends(db.get_session),
):
    """Vulnerabilities across all running containers, grouped by vulnerability, with server-side sort and pagination."""
    if sort_by not in _VALID_SORT_COLS:
        from fastapi import HTTPException as _HTTPException

        raise _HTTPException(status_code=422, detail=f"Invalid sort_by value: '{sort_by}'")

    t_total = time.perf_counter()

    t0 = time.perf_counter()
    watcher = DockerWatcher()
    running = watcher.list_running_containers()
    logger.info(
        "[VulnLoad /vulnerabilities] list_running_containers: %.3fs (%d containers)",
        time.perf_counter() - t0,
        len(running),
    )

    if not running:
        return {
            "report": report,
            "total_count": 0,
            "count": 0,
            "has_more": False,
            "has_any_vex": False,
            "eol_images": [],
            "vulnerabilities": [],
        }

    image_names = {img["image_name"] for img in running}

    t0 = time.perf_counter()
    latest_scan_id_subq = select(func.max(Scan.id)).where(Scan.image_name.in_(image_names)).group_by(Scan.image_name)
    scans = session.exec(select(Scan).where(Scan.id.in_(latest_scan_id_subq))).all()
    logger.info(
        "[VulnLoad /vulnerabilities] latest scans query: %.3fs (%d scans)", time.perf_counter() - t0, len(scans)
    )

    image_to_containers = defaultdict(list)
    for c in running:
        image_to_containers[c["image_name"]].append(c["container_name"])

    scan_id_to_images = {s.id: s.image_name for s in scans}

    eol_images = []
    for s in scans:
        if s.is_distro_eol:
            for c_name in image_to_containers[s.image_name]:
                eol_images.append(
                    {
                        "container_name": c_name,
                        "distro": f"{s.distro_name} {s.distro_version}"
                        if s.distro_name and s.distro_version
                        else s.distro_name,
                    }
                )

    if not scan_id_to_images:
        return {
            "report": report,
            "total_count": 0,
            "count": 0,
            "has_more": False,
            "has_any_vex": False,
            "eol_images": [],
            "vulnerabilities": [],
        }

    q = select(Vulnerability).where(Vulnerability.scan_id.in_(scan_id_to_images.keys()))

    if hide_vex:
        q = q.where((Vulnerability.vex_status.is_(None)) | (~Vulnerability.vex_status.in_(["not_affected", "fixed"])))

    t0 = time.perf_counter()
    new_keys_by_scan = _new_vuln_keys_for_scans(session, scans)
    logger.info("[VulnLoad /vulnerabilities] new_vuln_keys: %.3fs", time.perf_counter() - t0)

    if report == "critical":
        q = q.where(Vulnerability.severity == "Critical")
    elif report == "urgent":
        q = q.where(Vulnerability.risk_score >= 80)
    elif report == "kev":
        q = q.where(Vulnerability.is_kev)
    elif report == "new":
        q = q.where(Vulnerability.scan_id.in_(list(new_keys_by_scan.keys())))
    elif report == "vex_annotated":
        q = q.where(Vulnerability.vex_status.isnot(None))

    t0 = time.perf_counter()
    vulns = session.exec(q).all()
    logger.info("[VulnLoad /vulnerabilities] db fetch vulns: %.3fs (%d rows)", time.perf_counter() - t0, len(vulns))

    if report == "new":
        vulns = [
            v
            for v in vulns
            if (v.vuln_id, v.package_name, v.installed_version) in new_keys_by_scan.get(v.scan_id, set())
        ]

    # Reflect VEX presence only in the report-filtered result set
    has_any_vex = any(v.vex_status for v in vulns)

    grouped_vulns: dict[str, dict] = {}
    total_instances = 0

    t0 = time.perf_counter()
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

        v_is_new = (v.vuln_id, v.package_name, v.installed_version) in new_keys_by_scan.get(v.scan_id, set())

        if key not in grouped_vulns:
            vd = _serialise_vuln(v)
            vd["containers"] = [{"image_name": img_name, "container_name": c} for c in containers_for_img]
            vd["packages"] = [pkg_entry]
            vd["is_new"] = v_is_new
            grouped_vulns[key] = vd
        else:
            gv = grouped_vulns[key]

            existing_containers = gv["containers"]
            for c in containers_for_img:
                c_data = {"image_name": img_name, "container_name": c}
                if c_data not in existing_containers:
                    existing_containers.append(c_data)

            existing_pkgs = gv["packages"]
            pkg_key = (v.package_name, v.installed_version)
            if not any((p["package_name"], p["installed_version"]) == pkg_key for p in existing_pkgs):
                existing_pkgs.append(pkg_entry)

            if v_is_new:
                gv["is_new"] = True
            if _severity_rank(v.severity) < _severity_rank(gv.get("severity", "Unknown")):
                gv["severity"] = v.severity
            v_cvss = v.cvss_base_score or 0
            if v_cvss > (gv.get("cvss_base_score") or 0):
                gv["cvss_base_score"] = v.cvss_base_score
            v_risk = v.risk_score or 0
            if v_risk > (gv.get("risk_score") or 0):
                gv["risk_score"] = v.risk_score

    logger.info(
        "[VulnLoad /vulnerabilities] python group+aggregate: %.3fs (%d unique CVEs)",
        time.perf_counter() - t0,
        len(grouped_vulns),
    )

    for vd in grouped_vulns.values():
        vd["packages"].sort(
            key=lambda p: (
                _severity_rank(p.get("severity", "Unknown")),
                -(p.get("cvss_base_score") or 0),
                p.get("package_name", ""),
            )
        )
        rep = vd["packages"][0]
        vd["package_name"] = rep["package_name"]
        vd["installed_version"] = rep["installed_version"]
        vd["fixed_version"] = rep["fixed_version"]
        vd["package_type"] = rep["package_type"]
        vd["locations"] = rep["locations"]

    desc = sort_dir == "desc"

    def _clean_sort_key(vd: dict):
        if sort_by == "severity":
            risk = vd.get("risk_score") or 0
            return -risk if not desc else risk
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
            kev_val = 0 if vd.get("is_kev") else 1
            return (kev_val if not desc else -kev_val, 0)
        if sort_by == "first_seen_at":
            ts_raw = vd.get("first_seen_at")
            ts = ts_raw.isoformat() if hasattr(ts_raw, "isoformat") else (ts_raw or "")
            null_last = 1 if not ts else 0
            return (
                null_last,
                ts if not desc else ("" if not ts else "".join(chr(0xFFFF - min(ord(c), 0xFFFE)) for c in ts[:20])),
            )
        if sort_by == "vuln_id":
            s = vd.get("vuln_id", "")
            return s if not desc else "".join(chr(0xFFFF - min(ord(c), 0xFFFE)) for c in s)
        if sort_by == "package_name":
            s = vd.get("package_name", "")
            return s if not desc else "".join(chr(0xFFFF - min(ord(c), 0xFFFE)) for c in s)
        if sort_by == "containers":
            containers = vd.get("containers") or []
            s = containers[0]["container_name"] if containers else ""
            return s if not desc else "".join(chr(0xFFFF - min(ord(c), 0xFFFE)) for c in s)
        if sort_by == "vex_status":
            rank = _vex_sort_rank(vd.get("vex_status"))
            null_last = 1 if vd.get("vex_status") is None else 0
            return (null_last, rank if not desc else -rank)
        return 0

    t0 = time.perf_counter()
    all_vulns = sorted(grouped_vulns.values(), key=_clean_sort_key)
    logger.info("[VulnLoad /vulnerabilities] python sort: %.3fs", time.perf_counter() - t0)

    for vd in all_vulns:
        if vd.get("description") and len(vd["description"]) > _DESC_LIMIT:
            if not vd["description"].endswith("…"):
                vd["description"] = vd["description"][:_DESC_LIMIT] + "…"

    total_count = len(all_vulns)
    page_vulns = all_vulns[offset : offset + limit]
    has_more = (offset + limit) < total_count

    logger.info(
        "[VulnLoad /vulnerabilities] total: %.3fs (offset=%d limit=%d returning=%d of %d)",
        time.perf_counter() - t_total,
        offset,
        limit,
        len(page_vulns),
        total_count,
    )

    return {
        "report": report,
        "total_count": total_count,
        "total_instances": total_instances,
        "count": len(page_vulns),
        "has_more": has_more,
        "has_any_vex": has_any_vex,
        "eol_images": eol_images,
        "vulnerabilities": page_vulns,
    }


@router.get("/images/vulnerabilities/history")
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
    """Vulnerability counts over time for an image."""
    from fastapi import HTTPException as _HTTPException

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
        raise _HTTPException(status_code=404, detail=f"No scans found for '{image}'")

    history = []
    for scan in scans:
        count = session.exec(select(func.count(Vulnerability.id)).where(Vulnerability.scan_id == scan.id)).one()
        history.append(
            {
                "scan_id": scan.id,
                "scanned_at": _as_utc(scan.scanned_at),
                "image_ref": scan.image_name,
                "image_digest": scan.image_digest,
                "total": count,
            }
        )

    return {"image": image, "history": history}

from collections import defaultdict
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import case as sa_case
from sqlmodel import Session, func, select

from ..api_helpers import (
    _as_utc,
    _compute_vuln_diff,
    _latest_vuln_scan_ids_for_images,
    _new_vuln_keys_for_scans,
    _priority_bucket,
    _severity_rank,
)
from ..database import db
from ..docker_watcher import DockerWatcher
from ..models import AppState, EnvironmentSnapshot, ImageUpdateCheck, Scan, ScanContainer, SystemTask, Vulnerability
from ..vex_discovery import check_vex_for_image

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
        .where(Scan.is_update_check == False)  # noqa: E712
        .where(Scan.is_preview == False)  # noqa: E712
        .group_by(Scan.image_name)
    )
    scans_by_image = {s.image_name: s for s in session.exec(select(Scan).where(Scan.id.in_(latest_scan_id_subq))).all()}

    # Fallback: for containers whose image_name doesn't match any scan (e.g. the
    # same image was previously scanned under a different tag or registry prefix),
    # look up by image digest so they don't appear as "not yet scanned".
    unmatched_digests = [img["config_digest"] for img in running if img["image_name"] not in scans_by_image]
    scans_by_digest: dict[str, Scan] = {}
    if unmatched_digests:
        digest_scan_id_subq = (
            select(func.max(Scan.id))
            .where(Scan.image_digest.in_(unmatched_digests))
            .where(Scan.is_update_check == False)  # noqa: E712
            .where(Scan.is_preview == False)  # noqa: E712
            .group_by(Scan.image_digest)
        )
        scans_by_digest = {
            s.image_digest: s for s in session.exec(select(Scan).where(Scan.id.in_(digest_scan_id_subq))).all()
        }

    # Batch-load update check status for running images
    update_checks_by_image: dict[str, ImageUpdateCheck] = {}
    if image_names:
        update_checks = session.exec(select(ImageUpdateCheck).where(ImageUpdateCheck.image_name.in_(image_names))).all()
        update_checks_by_image = {uc.image_name: uc for uc in update_checks}

    scan_ids = [s.id for s in scans_by_image.values()] + [s.id for s in scans_by_digest.values()]
    severity_by_scan: dict[int, dict[str, int]] = defaultdict(dict)
    priority_by_scan: dict[int, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    severity_by_scan_no_vex: dict[int, dict[str, int]] = defaultdict(dict)
    priority_by_scan_no_vex: dict[int, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    if scan_ids:
        rows = session.exec(
            select(
                Vulnerability.scan_id,
                Vulnerability.vuln_id,
                Vulnerability.severity,
                Vulnerability.risk_score,
                Vulnerability.vex_status,
            ).where(Vulnerability.scan_id.in_(scan_ids))
        ).all()
        best_severity: dict[tuple, str] = {}
        best_risk: dict[tuple, float | None] = {}
        is_vex_resolved: dict[tuple, bool] = {}
        for scan_id, vuln_id, severity, risk_score, vex_status in rows:
            key = (scan_id, vuln_id)
            if key not in best_severity or _severity_rank(severity) < _severity_rank(best_severity[key]):
                best_severity[key] = severity
            cur_risk = best_risk.get(key)
            if cur_risk is None or (risk_score is not None and risk_score > (cur_risk or 0)):
                best_risk[key] = risk_score

            resolved = vex_status in ("not_affected", "fixed")
            if key not in is_vex_resolved:
                is_vex_resolved[key] = resolved
            else:
                is_vex_resolved[key] = is_vex_resolved[key] and resolved

        for (scan_id, vuln_id), severity in best_severity.items():
            severity_by_scan[scan_id][severity] = severity_by_scan[scan_id].get(severity, 0) + 1
            if not is_vex_resolved.get((scan_id, vuln_id)):
                severity_by_scan_no_vex[scan_id][severity] = severity_by_scan_no_vex[scan_id].get(severity, 0) + 1

        for (scan_id, vuln_id), risk_score in best_risk.items():
            bucket = _priority_bucket(risk_score)
            priority_by_scan[scan_id][bucket] += 1
            if not is_vex_resolved.get((scan_id, vuln_id)):
                priority_by_scan_no_vex[scan_id][bucket] += 1

    containers = []
    for img in running:
        scan = scans_by_image.get(img["image_name"]) or scans_by_digest.get(img["config_digest"])
        update_check = update_checks_by_image.get(img["image_name"])
        _UPDATE_STATUSES = {"scan_pending", "scan_complete", "update_available"}
        has_update = update_check is not None and update_check.status in _UPDATE_STATUSES
        update_scan_id = (
            update_check.update_scan_id
            if (update_check is not None and update_check.status == "scan_complete")
            else None
        )
        pending_task_id = (
            update_check.pending_task_id
            if (update_check is not None and update_check.status == "scan_pending")
            else None
        )

        if not scan:
            containers.append(
                {
                    "container_name": img["container_name"],
                    "image_name": img["image_name"],
                    "image_repository": None,
                    "image_digest": None,
                    "scan_id": None,
                    "scanned_at": None,
                    "is_distro_eol": False,
                    "distro_display": None,
                    "vulns_by_severity": {},
                    "vulns_by_priority": {},
                    "vulns_by_severity_no_vex": {},
                    "vulns_by_priority_no_vex": {},
                    "total": 0,
                    "has_scan": False,
                    "has_update": has_update,
                    "update_scan_id": update_scan_id,
                    "update_status": update_check.status if update_check else None,
                    "pending_task_id": pending_task_id,
                }
            )
            continue

        vulns_by_severity = severity_by_scan.get(scan.id, {})
        vulns_by_priority = dict(priority_by_scan.get(scan.id, {}))
        vulns_by_severity_no_vex = severity_by_scan_no_vex.get(scan.id, {})
        vulns_by_priority_no_vex = dict(priority_by_scan_no_vex.get(scan.id, {}))
        containers.append(
            {
                "container_name": img["container_name"],
                "image_name": scan.image_name,
                "image_repository": scan.image_repository,
                "image_digest": scan.image_digest,
                "scan_id": scan.id,
                "scanned_at": _as_utc(scan.scanned_at),
                "is_distro_eol": scan.is_distro_eol,
                "distro_display": f"{scan.distro_name} {scan.distro_version}"
                if scan.distro_name and scan.distro_version
                else scan.distro_name,
                "vulns_by_severity": vulns_by_severity,
                "vulns_by_priority": vulns_by_priority,
                "vulns_by_severity_no_vex": vulns_by_severity_no_vex,
                "vulns_by_priority_no_vex": vulns_by_priority_no_vex,
                "total": sum(vulns_by_severity.values()),
                "has_scan": True,
                "has_vex": scan.vex_status == "found",
                "vex_status": scan.vex_status,
                "vex_error": scan.vex_error,
                "has_update": has_update,
                "update_scan_id": update_scan_id,
                "update_status": update_check.status if update_check else None,
                "pending_task_id": pending_task_id,
            }
        )

    return {"containers": containers}


@router.post("/scans/{scan_id}/recheck-vex")
def recheck_vex(scan_id: int, session: Session = Depends(db.get_session)):
    """Re-run the VEX attestation check for a specific scan."""
    scan = session.get(Scan, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    # OCI Referrers API requires the manifest digest, not the config digest that
    # Grype stores in image_digest (source.target.imageID).  Resolve via
    # Docker's RepoDigests; fall back to the stored digest on failure.
    config_digest = scan.image_digest or ""
    watcher = DockerWatcher()
    manifest_digest = watcher.get_manifest_digest(scan.image_name) if scan.image_name else None
    digest_for_vex = manifest_digest or config_digest

    vex_result = check_vex_for_image(scan.image_name, digest_for_vex)
    now = datetime.now(UTC)

    if vex_result.error:
        scan.vex_status = "error"
        scan.vex_error = vex_result.error
        scan.vex_checked_at = now
    elif vex_result.found:
        scan.vex_status = "found"
        scan.vex_source = vex_result.source
        scan.vex_error = None
        scan.vex_checked_at = now
        vulns = session.exec(select(Vulnerability).where(Vulnerability.scan_id == scan.id)).all()
        stmt_map = {s.vuln_id: s for s in vex_result.statements}
        for v in vulns:
            vex_stmt = stmt_map.get(v.vuln_id)
            if vex_stmt:
                v.vex_status = vex_stmt.status
                v.vex_justification = vex_stmt.justification
                v.vex_statement = vex_stmt.notes
                session.add(v)
    else:
        scan.vex_status = "none"
        scan.vex_error = None
        scan.vex_checked_at = now

    session.add(scan)
    session.commit()
    return {
        "vex_status": scan.vex_status,
        "has_vex": scan.vex_status == "found",
        "vex_error": scan.vex_error,
    }


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
    unique_running_images = len({img["config_digest"] for img in running})

    if running_images:
        latest_scan_id_subq = _latest_vuln_scan_ids_for_images(running_images)
        row = session.exec(
            select(
                func.coalesce(func.sum(sa_case((Vulnerability.risk_score >= 80, 1), else_=0)), 0),
                func.coalesce(func.sum(sa_case((Vulnerability.is_kev, 1), else_=0)), 0),
            ).where(Vulnerability.scan_id.in_(latest_scan_id_subq))
        ).one()
        urgent_count, kev_count = int(row[0]), int(row[1])

        eol_count = session.exec(
            select(func.count(Scan.id)).where(Scan.id.in_(latest_scan_id_subq)).where(Scan.is_distro_eol)
        ).one()
    else:
        urgent_count, kev_count, eol_count = 0, 0, 0

    days = 30  # default; will become a query parameter when configurable range ships
    cutoff = datetime.now(UTC) - timedelta(days=days)
    snapshots = session.exec(
        select(EnvironmentSnapshot)
        .where(EnvironmentSnapshot.created_at >= cutoff)
        .order_by(EnvironmentSnapshot.created_at.asc())
    ).all()

    # Pure historical snapshots — no mutation, no override.
    # Explicit +00:00 suffix so JS parses each timestamp as UTC.
    trend = [
        {"date": _as_utc(s.created_at).isoformat(), "urgent": s.urgent_count, "kev": s.kev_count} for s in snapshots
    ]

    # Separate live "now" point — always freshly computed, never stored in trend.
    # Only present when containers are actually running.
    now_point = (
        {"date": datetime.now(UTC).isoformat(), "urgent": urgent_count, "kev": kev_count} if running_images else None
    )

    app_state = session.get(AppState, 1)
    last_db_checked_at = _as_utc(app_state.last_db_checked_at) if app_state else None
    grype_version = app_state.grype_version if app_state else None
    db_schema = app_state.db_schema if app_state else None
    db_built = _as_utc(app_state.db_built) if app_state else None

    if not grype_version or not db_built:
        latest_scan = session.exec(select(Scan).order_by(Scan.scanned_at.desc()).limit(1)).first()
        grype_version = grype_version or (latest_scan.grype_version if latest_scan else None)
        db_built = db_built or (_as_utc(latest_scan.db_built) if latest_scan else None)

    new_findings = 0
    if running_images:
        latest_scans_for_running = session.exec(select(Scan).where(Scan.id.in_(latest_scan_id_subq))).all()
        new_keys_by_scan = _new_vuln_keys_for_scans(session, latest_scans_for_running)
        new_findings = sum(len(keys) for keys in new_keys_by_scan.values())

    active_tasks = session.exec(select(func.count(SystemTask.id)).where(SystemTask.status == "running")).one()

    queued_tasks = session.exec(select(func.count(SystemTask.id)).where(SystemTask.status == "queued")).one()

    db_updating = (
        session.exec(
            select(func.count(SystemTask.id))
            .where(SystemTask.task_type == "scheduled_db_update")
            .where(SystemTask.status == "running")
        ).one()
        > 0
    )

    return {
        "running_containers": len(running),
        "unique_running_images": unique_running_images,
        "critical_count": urgent_count,
        "urgent_count": urgent_count,
        "kev_count": kev_count,
        "new_findings": int(new_findings),
        "trend": trend,
        "now_point": now_point,
        "docker_connected": docker_connected,
        "grype_version": grype_version,
        "db_schema": db_schema,
        "db_built": db_built,
        "last_db_checked_at": last_db_checked_at,
        "active_tasks": int(active_tasks),
        "queued_tasks": int(queued_tasks),
        "db_updating": db_updating,
        "eol_count": int(eol_count),
    }


@router.get("/activity/recent")
def get_recent_activity(
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=10, ge=1, le=50),
    session: Session = Depends(db.get_session),
):
    """Most recent scans with per-severity and per-priority vulnerability counts."""
    total = session.exec(
        select(func.count(Scan.id))
        .where(Scan.is_update_check == False)  # noqa: E712
        .where(Scan.is_preview == False)  # noqa: E712
    ).one()
    scans = session.exec(
        select(Scan)
        .where(Scan.is_update_check == False)  # noqa: E712
        .where(Scan.is_preview == False)  # noqa: E712
        .order_by(Scan.scanned_at.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
    ).all()

    scan_ids = [s.id for s in scans]
    scan_containers_by_scan: dict[int, list[str]] = defaultdict(list)
    severity_by_scan: dict[int, dict[str, int]] = defaultdict(dict)
    priority_by_scan: dict[int, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    if scan_ids:
        for scan_id, container_name in session.exec(
            select(ScanContainer.scan_id, ScanContainer.container_name).where(ScanContainer.scan_id.in_(scan_ids))
        ).all():
            scan_containers_by_scan[scan_id].append(container_name)

        for scan_id, severity, risk_score, cnt in session.exec(
            select(
                Vulnerability.scan_id,
                Vulnerability.severity,
                Vulnerability.risk_score,
                func.count(Vulnerability.id),
            )
            .where(Vulnerability.scan_id.in_(scan_ids))
            .group_by(Vulnerability.scan_id, Vulnerability.severity, Vulnerability.risk_score)
        ).all():
            severity_by_scan[scan_id][severity] = severity_by_scan[scan_id].get(severity, 0) + cnt
            bucket = _priority_bucket(risk_score)
            priority_by_scan[scan_id][bucket] += cnt

    result = []
    for scan in scans:
        vulns_by_severity = severity_by_scan.get(scan.id, {})
        vulns_by_priority = dict(priority_by_scan.get(scan.id, {}))
        result.append(
            {
                "scan_id": scan.id,
                "scanned_at": _as_utc(scan.scanned_at),
                "image_name": scan.image_name,
                "image_digest": scan.image_digest,
                "affected_containers_at_scan": sorted(set(scan_containers_by_scan.get(scan.id, []))),
                "affected_container_count_at_scan": len(set(scan_containers_by_scan.get(scan.id, []))),
                "vulns_by_severity": vulns_by_severity,
                "vulns_by_priority": vulns_by_priority,
                "total": sum(vulns_by_severity.values()),
            }
        )

    return {"activities": result, "total": total}


@router.get("/containers/{container_name}/scan-history")
def get_container_scan_history(
    container_name: str,
    offset: int = Query(default=0, ge=0),
    limit: int = Query(default=10, ge=1, le=100),
    session: Session = Depends(db.get_session),
):
    """Paginated scan history for a container, with per-entry diffs vs predecessor."""
    # 1. Load all scans ever linked to this container, in chronological order.
    #    ScanContainer rows are the authoritative lineage — we deliberately do NOT
    #    broaden to "all scans for those image_names", which would include scans for
    #    other containers running the same image and produce spurious extra baselines.
    linked_scan_ids = session.exec(
        select(ScanContainer.scan_id).where(ScanContainer.container_name == container_name)
    ).all()

    if not linked_scan_ids:
        raise HTTPException(status_code=404, detail=f"No scans found for container '{container_name}'")

    all_scans_asc = session.exec(
        select(Scan)
        .where(Scan.id.in_(linked_scan_ids))
        .where(Scan.is_update_check == False)  # noqa: E712
        .where(Scan.is_preview == False)  # noqa: E712
        .order_by(Scan.scanned_at.asc())
    ).all()

    # Paginate descending (most recent first)
    scans_desc = list(reversed(all_scans_asc))
    total_scans = len(scans_desc)
    has_more = (offset + limit) < total_scans
    paginated = scans_desc[offset : offset + limit]

    # 2. Global predecessor lookup: the scan immediately before each paginated scan
    #    in the container's unified chronological history, regardless of image_name.
    #    This means there is exactly one baseline (the very first scan ever), and
    #    diffs span across image/tag changes — the image_changed flag marks those.
    scan_index = {s.id: i for i, s in enumerate(all_scans_asc)}
    prev_by_scan: dict[int, Scan | None] = {}
    for scan in paginated:
        idx = scan_index[scan.id]
        prev_by_scan[scan.id] = all_scans_asc[idx - 1] if idx > 0 else None

    # 4. Batch load vuln details for paginated scans + their predecessors
    all_scan_ids: list[int] = [s.id for s in paginated]
    for prev in prev_by_scan.values():
        if prev is not None and prev.id not in all_scan_ids:
            all_scan_ids.append(prev.id)

    keys_by_scan: dict[int, set[tuple[str, str, str]]] = defaultdict(set)
    vuln_details: dict[tuple, dict] = {}

    if all_scan_ids:
        rows = session.exec(
            select(
                Vulnerability.scan_id,
                Vulnerability.vuln_id,
                Vulnerability.package_name,
                Vulnerability.installed_version,
                Vulnerability.severity,
                Vulnerability.risk_score,
                Vulnerability.is_kev,
                Vulnerability.data_source,
            ).where(Vulnerability.scan_id.in_(all_scan_ids))
        ).all()
        for scan_id, vuln_id, pkg_name, inst_ver, severity, risk_score, is_kev, data_source in rows:
            key = (vuln_id, pkg_name, inst_ver)
            keys_by_scan[scan_id].add(key)
            detail_key = (scan_id, key)
            existing = vuln_details.get(detail_key)
            if existing is None or (risk_score is not None and risk_score > (existing["risk_score"] or 0)):
                vuln_details[detail_key] = {
                    "vuln_id": vuln_id,
                    "package_name": pkg_name,
                    "installed_version": inst_ver,
                    "severity": severity,
                    "risk_score": risk_score,
                    "is_kev": is_kev or (existing["is_kev"] if existing else False),
                    "data_source": data_source,
                }

    # 5. Build entries
    entries = []
    for scan in paginated:
        current_keys = keys_by_scan.get(scan.id, set())
        # Count unique CVE IDs (matches the container view's deduplication)
        current_cves = {k[0] for k in current_keys}
        prev = prev_by_scan[scan.id]
        is_baseline = prev is None

        if is_baseline:
            # Priority counts by unique CVE, using the best (highest) risk score per CVE
            cve_best_risk: dict[str, float | None] = {}
            for key in current_keys:
                d = vuln_details.get((scan.id, key))
                risk = d["risk_score"] if d else None
                cve_id = key[0]
                cur = cve_best_risk.get(cve_id)
                if cve_id not in cve_best_risk or (risk is not None and risk > (cur or 0)):
                    cve_best_risk[cve_id] = risk
            priority_counts: dict[str, int] = defaultdict(int)
            for risk in cve_best_risk.values():
                priority_counts[_priority_bucket(risk)] += 1
            entries.append(
                {
                    "scan_id": scan.id,
                    "scanned_at": _as_utc(scan.scanned_at),
                    "image_name": scan.image_name,
                    "total": len(current_cves),
                    "is_baseline": True,
                    "image_changed": None,
                    "added": [],
                    "removed": [],
                    "vulns_by_priority": dict(priority_counts),
                }
            )
        else:
            prev_keys = keys_by_scan.get(prev.id, set())
            added_keys, removed_keys = _compute_vuln_diff(current_keys, prev_keys)
            added_items = [vuln_details[(scan.id, k)] for k in added_keys if (scan.id, k) in vuln_details]
            removed_items = [vuln_details[(prev.id, k)] for k in removed_keys if (prev.id, k) in vuln_details]
            entries.append(
                {
                    "scan_id": scan.id,
                    "scanned_at": _as_utc(scan.scanned_at),
                    "image_name": scan.image_name,
                    "total": len(current_cves),
                    "is_baseline": False,
                    "image_changed": scan.image_digest != prev.image_digest,
                    "added": added_items,
                    "removed": removed_items,
                    "vulns_by_priority": None,
                }
            )

    return {
        "container_name": container_name,
        "total_scans": total_scans,
        "has_more": has_more,
        "entries": entries,
    }


@router.get("/update-scans/status")
def get_update_scan_statuses(session: Session = Depends(db.get_session)):
    """Current status of all in-progress or recently completed update scans."""
    checks = session.exec(
        select(ImageUpdateCheck).where(ImageUpdateCheck.status.in_(["scan_pending", "scan_complete"]))
    ).all()
    return [
        {
            "image_name": c.image_name,
            "status": c.status,
            "update_scan_id": c.update_scan_id,
            "pending_task_id": c.pending_task_id,
        }
        for c in checks
    ]


@router.get("/update-scans/{scan_id}/diff")
def get_update_scan_diff(scan_id: int, session: Session = Depends(db.get_session)):
    """Vulnerability diff between a registry update scan and the current running scan."""
    check = session.exec(select(ImageUpdateCheck).where(ImageUpdateCheck.update_scan_id == scan_id)).first()
    if not check:
        raise HTTPException(status_code=404, detail="No update check found for this scan")

    update_scan = session.get(Scan, check.update_scan_id)
    current_scan = session.get(Scan, check.current_scan_id) if check.current_scan_id else None

    if not update_scan:
        raise HTTPException(status_code=404, detail="Update scan not found")

    def _vuln_keys(s: Scan) -> dict[tuple, dict]:
        rows = session.exec(
            select(
                Vulnerability.vuln_id,
                Vulnerability.package_name,
                Vulnerability.installed_version,
                Vulnerability.severity,
                Vulnerability.risk_score,
                Vulnerability.is_kev,
                Vulnerability.data_source,
            ).where(Vulnerability.scan_id == s.id)
        ).all()
        result: dict[tuple, dict] = {}
        for vuln_id, pkg_name, inst_ver, severity, risk_score, is_kev, data_source in rows:
            key = (vuln_id, pkg_name, inst_ver)
            existing = result.get(key)
            if existing is None or (risk_score is not None and risk_score > (existing["risk_score"] or 0)):
                result[key] = {
                    "vuln_id": vuln_id,
                    "package_name": pkg_name,
                    "installed_version": inst_ver,
                    "severity": severity,
                    "risk_score": risk_score,
                    "is_kev": is_kev,
                    "data_source": data_source,
                }
        return result

    update_keys = _vuln_keys(update_scan)
    current_keys = _vuln_keys(current_scan) if current_scan else {}

    added_keys, removed_keys = _compute_vuln_diff(set(update_keys.keys()), set(current_keys.keys()))

    added = [update_keys[k] for k in added_keys if k in update_keys]
    removed = [current_keys[k] for k in removed_keys if k in current_keys]

    return {
        "image_name": check.image_name,
        "running_digest": check.running_digest,
        "registry_digest": check.registry_digest,
        "current_scan_id": check.current_scan_id,
        "update_scan_id": check.update_scan_id,
        "added": added,
        "removed": removed,
        "added_count": len({v["vuln_id"] for v in added}),
        "removed_count": len({v["vuln_id"] for v in removed}),
    }

import json
from collections import defaultdict
from collections.abc import Collection
from datetime import UTC, datetime

from fastapi import HTTPException
from sqlmodel import Session, func, select

from .models import Scan, ScanContainer, Vulnerability

_DESC_LIMIT = 1000
_LOC_LIMIT = 5

_VALID_SORT_COLS = {
    "severity",
    "cvss_base_score",
    "epss_score",
    "is_kev",
    "first_seen_at",
    "vuln_id",
    "package_name",
    "containers",
    "vex_status",
}
_SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Negligible", "Unknown"]
_VEX_STATUS_RANK = {
    "not_affected": 0,
    "fixed": 1,
    "under_investigation": 2,
    "affected": 3,
}


def _severity_rank(s: str) -> int:
    try:
        return _SEVERITY_ORDER.index(s)
    except ValueError:
        return 99


def _vex_sort_rank(status: str | None) -> int:
    """Numeric rank for VEX status sorting. Nulls sort last (rank 99)."""
    if status is None:
        return 99
    return _VEX_STATUS_RANK.get(status, 50)


def _priority_bucket(risk_score: float | None) -> str:
    if risk_score is None:
        return "Low"
    if risk_score >= 80:
        return "Urgent"
    if risk_score >= 50:
        return "High"
    if risk_score >= 20:
        return "Medium"
    return "Low"


def _serialise_vuln(v: Vulnerability) -> dict:
    d = v.model_dump()
    for key in ("urls_titles", "cwe_titles"):
        raw = d.get(key)
        if raw:
            try:
                parsed = json.loads(raw)
                d[key] = parsed if isinstance(parsed, dict) else None
            except (TypeError, ValueError):
                d[key] = None
    if d.get("description") and len(d["description"]) > _DESC_LIMIT:
        d["description"] = d["description"][:_DESC_LIMIT] + "…"
    if d.get("locations"):
        paths = d["locations"].split("\n")
        if len(paths) > _LOC_LIMIT:
            d["locations"] = "\n".join(paths[:_LOC_LIMIT])
    return d


def _as_utc(dt: datetime | None) -> datetime | None:
    if dt is None or dt.tzinfo is not None:
        return dt
    return dt.replace(tzinfo=UTC)


def _latest_vuln_scan_ids_for_images(image_names: Collection[str]):
    """Subquery: MAX(scan.id) per image_name, excluding update-check and preview scans.

    Update-check scans scan the *latest available registry image*, not what is
    currently running. Including them as "latest" causes the vulnerability report
    to show findings for an image you haven't deployed yet and mis-calculates the
    new-since-previous-scan delta. Always use this subquery when you need the
    most recent vulnerability scan for running containers.
    """
    return (
        select(func.max(Scan.id))
        .where(Scan.image_name.in_(image_names))
        .where(Scan.is_update_check == False)  # noqa: E712
        .where(Scan.is_preview == False)  # noqa: E712
        .group_by(Scan.image_name)
    )


def _latest_scan_for_ref(image_ref: str, session: Session) -> Scan:
    if image_ref.startswith("sha256:"):
        stmt = select(Scan).where(Scan.image_digest == image_ref)
    else:
        stmt = select(Scan).where(Scan.image_name == image_ref)
    scan = session.exec(stmt.order_by(Scan.scanned_at.desc())).first()
    if not scan:
        raise HTTPException(status_code=404, detail=f"No scans found for '{image_ref}'")
    return scan


def _previous_scan(session: Session, scan: Scan) -> Scan | None:
    """Find the most recent scan before `scan` for the same image_name lineage."""
    return session.exec(
        select(Scan)
        .where(Scan.image_name == scan.image_name, Scan.id != scan.id, Scan.scanned_at < scan.scanned_at)
        .order_by(Scan.scanned_at.desc())
    ).first()


def _compute_vuln_diff(
    current_keys: set[tuple[str, str, str]],
    prev_keys: set[tuple[str, str, str]],
) -> tuple[set[tuple[str, str, str]], set[tuple[str, str, str]]]:
    """Return (added_keys, removed_keys) using (vuln_id, pkg, version) tuples.

    Both callers — scan history and new-vuln marking — must use this function
    so their definition of 'new' stays in sync.
    """
    return current_keys - prev_keys, prev_keys - current_keys


def _new_vuln_keys_for_scans(session: Session, scans: list[Scan]) -> dict[int, set[tuple[str, str, str]]]:
    """Batch-compute new vulnerability keys for each scan vs its predecessor.

    Returns {scan_id: set of (vuln_id, package_name, installed_version) keys that are new}.
    """
    if not scans:
        return {}

    # Predecessor lookup: container-name lineage (bridges image tag changes),
    # falling back to image_name lineage for scans with no container association.
    # Matches the same logic used by get_container_scan_history().
    scan_ids = [s.id for s in scans]

    # 1. Find container associations for the input scans
    sc_rows = session.exec(
        select(ScanContainer.scan_id, ScanContainer.container_name).where(ScanContainer.scan_id.in_(scan_ids))
    ).all()
    containers_by_scan: dict[int, set[str]] = defaultdict(set)
    for sid, cname in sc_rows:
        containers_by_scan[sid].add(cname)

    # 2. Container-lineage predecessors (excludes update checks and previews,
    #    matching scan history behaviour)
    all_cnames = {cn for names in containers_by_scan.values() for cn in names}
    prev_by_scan: dict[int, Scan | None] = {}

    if all_cnames:
        history_rows = session.exec(
            select(ScanContainer.container_name, Scan.id, Scan.scanned_at)
            .join(Scan, Scan.id == ScanContainer.scan_id)
            .where(ScanContainer.container_name.in_(all_cnames))
            .where(Scan.is_update_check == False)  # noqa: E712
            .where(Scan.is_preview == False)  # noqa: E712
            .order_by(Scan.scanned_at.asc())
        ).all()

        by_container: dict[str, list[tuple[int, datetime]]] = defaultdict(list)
        for cname, sid, scanned_at in history_rows:
            by_container[cname].append((sid, scanned_at))

        candidate_ids = {sid for entries in by_container.values() for sid, _ in entries}
        candidate_scans = {s.id: s for s in session.exec(select(Scan).where(Scan.id.in_(candidate_ids))).all()}

        for scan in scans:
            cnames = containers_by_scan.get(scan.id)
            if not cnames:
                continue  # no container association — handled by fallback below
            best_prev: Scan | None = None
            for cname in cnames:
                for sid, t in reversed(by_container[cname]):
                    if sid != scan.id and t < scan.scanned_at:
                        if best_prev is None or t > best_prev.scanned_at:
                            best_prev = candidate_scans.get(sid)
                        break
            prev_by_scan[scan.id] = best_prev

    # 3. Image-name lineage fallback for scans with no container association
    fallback_scans = [s for s in scans if s.id not in prev_by_scan]
    if fallback_scans:
        image_names = {s.image_name for s in fallback_scans}
        lineage_scans = session.exec(
            select(Scan)
            .where(Scan.image_name.in_(image_names))
            .where(Scan.is_update_check == False)  # noqa: E712
            .where(Scan.is_preview == False)  # noqa: E712
            .order_by(Scan.scanned_at.asc())
        ).all()
        by_image: dict[str, list[Scan]] = defaultdict(list)
        for s in lineage_scans:
            by_image[s.image_name].append(s)
        for scan in fallback_scans:
            prev = None
            for h in reversed(by_image[scan.image_name]):
                if h.scanned_at < scan.scanned_at and h.id != scan.id:
                    prev = h
                    break
            prev_by_scan[scan.id] = prev

    # Batch load all vuln keys for current + previous scans in one query
    all_scan_ids = [s.id for s in scans]
    for prev in prev_by_scan.values():
        if prev:
            all_scan_ids.append(prev.id)

    rows = session.exec(
        select(
            Vulnerability.scan_id, Vulnerability.vuln_id, Vulnerability.package_name, Vulnerability.installed_version
        ).where(Vulnerability.scan_id.in_(all_scan_ids))
    ).all()

    keys_by_scan: dict[int, set[tuple[str, str, str]]] = defaultdict(set)
    for scan_id, vuln_id, pkg_name, inst_ver in rows:
        keys_by_scan[scan_id].add((vuln_id, pkg_name, inst_ver))

    result: dict[int, set[tuple[str, str, str]]] = {}
    for scan in scans:
        current_keys = keys_by_scan.get(scan.id, set())
        prev = prev_by_scan[scan.id]
        if prev is None:
            result[scan.id] = current_keys
        else:
            added_keys, _ = _compute_vuln_diff(current_keys, keys_by_scan.get(prev.id, set()))
            result[scan.id] = added_keys

    return result


def _fmt_duration(secs: float) -> str:
    """Format a duration in seconds as 'Xm Ys' or 'Xs'."""
    if secs >= 60:
        m = int(secs // 60)
        s = int(secs % 60)
        return f"{m}m {s}s"
    return f"{int(secs)}s"


def _parse_image_query(image: str) -> tuple[str, str]:
    if image.startswith("sha256:"):
        return "digest", image
    last_colon = image.rfind(":")
    if last_colon != -1 and "/" not in image[last_colon + 1 :]:
        return "image_ref", image
    return "image_repository", image

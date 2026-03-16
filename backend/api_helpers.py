import json
from collections import defaultdict
from datetime import UTC, datetime

from fastapi import HTTPException
from sqlmodel import Session, select

from .models import Scan, Vulnerability

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
}
_SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Negligible", "Unknown"]


def _severity_rank(s: str) -> int:
    try:
        return _SEVERITY_ORDER.index(s)
    except ValueError:
        return 99


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


def _new_vuln_keys_for_scans(session: Session, scans: list[Scan]) -> dict[int, set[tuple[str, str, str]]]:
    """Batch-compute new vulnerability keys for each scan vs its predecessor.

    Returns {scan_id: set of (vuln_id, package_name, installed_version) keys that are new}.
    """
    if not scans:
        return {}

    # Load all scans for the relevant image_name lineages in one query, then
    # resolve previous scans in memory — avoids N per-scan round-trips.
    image_names = {s.image_name for s in scans}
    lineage_scans = session.exec(
        select(Scan).where(Scan.image_name.in_(image_names)).order_by(Scan.scanned_at.asc())
    ).all()
    by_image: dict[str, list[Scan]] = defaultdict(list)
    for s in lineage_scans:
        by_image[s.image_name].append(s)  # ascending by scanned_at

    prev_by_scan: dict[int, Scan | None] = {}
    for scan in scans:
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
            result[scan.id] = current_keys - keys_by_scan.get(prev.id, set())

    return result


def _parse_image_query(image: str) -> tuple[str, str]:
    if image.startswith("sha256:"):
        return "digest", image
    last_colon = image.rfind(":")
    if last_colon != -1 and "/" not in image[last_colon + 1 :]:
        return "image_ref", image
    return "image_repository", image

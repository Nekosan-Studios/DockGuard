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


def _parse_image_query(image: str) -> tuple[str, str]:
    if image.startswith("sha256:"):
        return "digest", image
    last_colon = image.rfind(":")
    if last_colon != -1 and "/" not in image[last_colon + 1 :]:
        return "image_ref", image
    return "image_repository", image

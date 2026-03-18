import asyncio
import logging
from collections import defaultdict
from datetime import UTC, datetime
from typing import Annotated

import yaml
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlmodel import Session, select

from ..api_helpers import _as_utc, _priority_bucket, _severity_rank
from ..database import db
from ..grype_scanner import GrypeScanner
from ..models import Scan, SystemTask, Vulnerability

router = APIRouter(tags=["Preview Scans"])
logger = logging.getLogger(__name__)

_progress_store: dict[int, list[str]] = {}
_active_tasks: dict[int, asyncio.Task] = {}


def _to_grype_registry_ref(image_name: str) -> str:
    """Return a fully-qualified `registry:<host>/...` ref for grype.

    Docker Hub images omit the registry host (e.g. ``nginx:latest`` or
    ``corentinth/it-tools:latest``).  Grype's ``registry:`` scheme requires
    an explicit host, so we apply the same defaulting rules that Docker uses:

    * No slash at all → official library image → ``docker.io/library/<name>``
    * First path component has no ``.`` or ``:`` → Docker Hub user/org image
      → ``docker.io/<name>``
    * Otherwise the host is already present → use as-is.
    """
    # Determine the first path component (before the first slash), which is the
    # registry host when present.  We must strip the tag carefully: the tag
    # separator is the last ":" that is not followed by a "/", so we can't
    # simply split on ":" — instead we work with the slash-based structure.
    slash_idx = image_name.find("/")

    if slash_idx == -1:
        # No slash at all → official library image: nginx → docker.io/library/nginx
        qualified = f"docker.io/library/{image_name}"
    else:
        first_component = image_name[:slash_idx]
        if "." not in first_component and ":" not in first_component:
            # First component is a user/org, not a host: corentinth/it-tools → docker.io/...
            qualified = f"docker.io/{image_name}"
        else:
            # First component looks like a registry host (has dot or port colon)
            qualified = image_name

    return f"registry:{qualified}"


class ParseComposeRequest(BaseModel):
    yaml_text: str


class StartPreviewRequest(BaseModel):
    images: list[str]
    skip_enrichments: bool = False
    max_concurrent: int = Field(default=1, ge=1, le=4)


class DeletePreviewRequest(BaseModel):
    image_names: list[str]
    task_ids: list[int] = []


@router.post("/preview-scans/parse-compose")
def parse_compose(req: ParseComposeRequest):
    """Parse a docker-compose YAML and extract image references."""
    try:
        data = yaml.safe_load(req.yaml_text)
    except yaml.YAMLError as e:
        raise HTTPException(status_code=400, detail=f"Invalid YAML: {e}")

    if not isinstance(data, dict):
        raise HTTPException(status_code=400, detail="YAML must be a mapping (docker-compose format)")

    services = data.get("services", {})
    if not isinstance(services, dict):
        return {"images": [], "parse_errors": ["No services found in YAML"]}

    images = []
    skipped = 0

    for svc in services.values():
        if not isinstance(svc, dict):
            skipped += 1
            continue
        img = svc.get("image")
        if img:
            images.append(str(img))
        else:
            skipped += 1

    # Deduplicate while preserving order
    seen: set[str] = set()
    unique_images: list[str] = []
    for img in images:
        if img not in seen:
            seen.add(img)
            unique_images.append(img)

    parse_errors: list[str] = []
    if skipped:
        parse_errors.append(f"{skipped} service(s) skipped (build-only, no image reference)")

    return {"images": unique_images, "parse_errors": parse_errors}


@router.post("/preview-scans")
async def start_preview_scans(req: StartPreviewRequest, session: Session = Depends(db.get_session)):
    """Start preview scans for a list of images. Returns task IDs for status polling."""
    if not req.images:
        raise HTTPException(status_code=400, detail="No images provided")

    scanner = GrypeScanner(watcher=None, database=db, enable_reference_title_fetch=True)
    session_semaphore = asyncio.Semaphore(req.max_concurrent)

    preview_items = []
    tasks_to_start: list[tuple[str, str, int]] = []

    for image_name in req.images:
        grype_ref = _to_grype_registry_ref(image_name)
        task = SystemTask(
            task_type="preview_scan",
            task_name=f"Preview scan: {image_name}",
            status="queued",
            created_at=datetime.now(UTC),
        )
        session.add(task)
        session.flush()
        tasks_to_start.append((image_name, grype_ref, task.id))  # type: ignore[arg-type]
        preview_items.append({"image_name": image_name, "task_id": task.id})

    session.commit()

    for image_name, grype_ref, task_id in tasks_to_start:
        _progress_store[task_id] = []
        async_task = asyncio.create_task(
            scanner.scan_image_streaming_async(
                image_name=image_name,
                grype_ref=grype_ref,
                semaphore=session_semaphore,
                task_id=task_id,
                progress_store=_progress_store,
                skip_enrichments=req.skip_enrichments,
            )
        )
        _active_tasks[task_id] = async_task

        def _make_done_callback(tid: int):
            def _done(fut: asyncio.Future) -> None:
                _active_tasks.pop(tid, None)
                _progress_store.pop(tid, None)

            return _done

        async_task.add_done_callback(_make_done_callback(task_id))

    return {"preview_items": preview_items}


@router.get("/preview-scans/status")
def get_preview_scan_status(
    task_ids: Annotated[list[int], Query()] = [],
    session: Session = Depends(db.get_session),
):
    """Check status of preview scans by task IDs. Returns status + scan data when complete."""
    if not task_ids:
        return []

    tasks = session.exec(select(SystemTask).where(SystemTask.id.in_(task_ids))).all()
    tasks_by_id = {t.id: t for t in tasks}

    result = []
    for task_id in task_ids:
        task = tasks_by_id.get(task_id)
        if not task:
            continue

        if task.status == "queued":
            status = "pending"
        elif task.status == "running":
            status = "scanning"
        elif task.status == "completed":
            status = "complete"
        else:
            status = "failed"

        # Extract image_name from task_name (stored as "Preview scan: <image>")
        image_name = task.task_name.removeprefix("Preview scan: ")

        item: dict = {
            "task_id": task_id,
            "image_name": image_name,
            "status": status,
            "error_message": task.error_message,
            "scan_data": None,
            "progress_lines": _progress_store.get(task_id, []) if status in ("pending", "scanning") else [],
        }

        if status == "complete":
            scan = session.exec(
                select(Scan)
                .where(Scan.image_name == image_name)
                .where(Scan.is_preview == True)  # noqa: E712
                .order_by(Scan.scanned_at.desc())
            ).first()

            if scan:
                rows = session.exec(
                    select(
                        Vulnerability.vuln_id,
                        Vulnerability.severity,
                        Vulnerability.risk_score,
                        Vulnerability.vex_status,
                    ).where(Vulnerability.scan_id == scan.id)
                ).all()

                best_severity: dict[str, str] = {}
                best_risk: dict[str, float | None] = {}
                is_vex_resolved: dict[str, bool] = {}

                for vuln_id, severity, risk_score, vex_status in rows:
                    if vuln_id not in best_severity or _severity_rank(severity) < _severity_rank(
                        best_severity[vuln_id]
                    ):
                        best_severity[vuln_id] = severity
                    cur_risk = best_risk.get(vuln_id)
                    if cur_risk is None or (risk_score is not None and risk_score > (cur_risk or 0)):
                        best_risk[vuln_id] = risk_score
                    resolved = vex_status in ("not_affected", "fixed")
                    if vuln_id not in is_vex_resolved:
                        is_vex_resolved[vuln_id] = resolved
                    else:
                        is_vex_resolved[vuln_id] = is_vex_resolved[vuln_id] and resolved

                vulns_by_severity: dict[str, int] = {}
                vulns_by_priority: dict[str, int] = defaultdict(int)
                vulns_by_severity_no_vex: dict[str, int] = {}
                vulns_by_priority_no_vex: dict[str, int] = defaultdict(int)

                for vuln_id, severity in best_severity.items():
                    vulns_by_severity[severity] = vulns_by_severity.get(severity, 0) + 1
                    if not is_vex_resolved.get(vuln_id):
                        vulns_by_severity_no_vex[severity] = vulns_by_severity_no_vex.get(severity, 0) + 1

                for vuln_id, risk_score in best_risk.items():
                    bucket = _priority_bucket(risk_score)
                    vulns_by_priority[bucket] += 1
                    if not is_vex_resolved.get(vuln_id):
                        vulns_by_priority_no_vex[bucket] += 1

                item["scan_data"] = {
                    "scan_id": scan.id,
                    "image_name": scan.image_name,
                    "container_name": scan.image_name,
                    "has_scan": True,
                    "scanned_at": _as_utc(scan.scanned_at),
                    "is_distro_eol": scan.is_distro_eol,
                    "distro_display": f"{scan.distro_name} {scan.distro_version}"
                    if scan.distro_name and scan.distro_version
                    else scan.distro_name,
                    "vulns_by_severity": vulns_by_severity,
                    "vulns_by_priority": dict(vulns_by_priority),
                    "vulns_by_severity_no_vex": vulns_by_severity_no_vex,
                    "vulns_by_priority_no_vex": dict(vulns_by_priority_no_vex),
                    "total": sum(vulns_by_severity.values()),
                    "has_vex": scan.vex_status == "found",
                    "vex_status": scan.vex_status,
                    "vex_error": scan.vex_error,
                    "has_update": False,
                    "update_scan_id": None,
                    "update_status": None,
                }

        result.append(item)

    return result


@router.delete("/preview-scans", status_code=204)
def delete_preview_scans(req: DeletePreviewRequest, session: Session = Depends(db.get_session)):
    """Delete preview scan records and their vulnerabilities for the given images. Cancels in-flight tasks."""
    for task_id in req.task_ids:
        task = _active_tasks.pop(task_id, None)
        if task is not None:
            task.cancel()
        _progress_store.pop(task_id, None)

    if not req.image_names:
        return

    scans = session.exec(
        select(Scan).where(Scan.image_name.in_(req.image_names)).where(Scan.is_preview == True)  # noqa: E712
    ).all()

    for scan in scans:
        vulns = session.exec(select(Vulnerability).where(Vulnerability.scan_id == scan.id)).all()
        for v in vulns:
            session.delete(v)
        session.delete(scan)

    session.commit()

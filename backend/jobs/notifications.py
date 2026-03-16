import json
import logging
from datetime import UTC, datetime

from sqlmodel import Session, col, func, select

from backend.api_helpers import _priority_bucket
from backend.config import ConfigManager
from backend.database import Database
from backend.models import AppState, NotificationChannel, NotificationLog, Scan, Vulnerability
from backend.services import notifier

logger = logging.getLogger(__name__)

_VULN_DEEP_LINK = "/vulnerabilities?cve="


def _vuln_label(vuln_id: str, base_url: str) -> str:
    """Return a vuln ID as a Markdown link if base_url is set, otherwise plain text."""
    if base_url:
        return f"[{vuln_id}]({base_url.rstrip('/')}{_VULN_DEEP_LINK}{vuln_id})"
    return vuln_id


_DETAIL_THRESHOLD = 5
_CONTAINER_THRESHOLD = 10

_PRIORITY_ORDER = ["Urgent", "High", "Medium", "Low"]


def _priority_counts_str(counts: dict[str, int]) -> str:
    """Format priority counts like '2 Urgent, 4 High, 3 Medium'."""
    parts = [f"{counts[p]} {p}" for p in _PRIORITY_ORDER if counts.get(p)]
    return ", ".join(parts) if parts else "0 vulnerabilities"


def _build_vuln_body(
    vulns_by_container: dict[str, list[Vulnerability]],
    base_url: str,
) -> str:
    """Build a notification body with progressive summarization.

    - ≤ _DETAIL_THRESHOLD total vulns: full per-CVE detail
    - > _DETAIL_THRESHOLD vulns, ≤ _CONTAINER_THRESHOLD containers: per-container summary
    - > _CONTAINER_THRESHOLD containers: single rolled-up total
    """
    total_vulns = sum(len(vs) for vs in vulns_by_container.values())
    num_containers = len(vulns_by_container)

    # Tier 1: Full detail
    if total_vulns <= _DETAIL_THRESHOLD:
        lines: list[str] = []
        for container_label, vulns in vulns_by_container.items():
            for v in vulns:
                label = _vuln_label(v.vuln_id, base_url)
                priority = _priority_bucket(v.risk_score)
                entry = f"- **{label}** ({priority}) in `{v.package_name}` {v.installed_version}"
                if v.is_kev:
                    entry += " [KEV]"
                entry += f" — {container_label}"
                lines.append(entry)
        return "\n".join(lines)

    # Tier 3: Rolled-up total (check first since tier 2 falls through)
    if num_containers > _CONTAINER_THRESHOLD:
        counts: dict[str, int] = {}
        kev_total = 0
        for vulns in vulns_by_container.values():
            for v in vulns:
                p = _priority_bucket(v.risk_score)
                counts[p] = counts.get(p, 0) + 1
                if v.is_kev:
                    kev_total += 1
        lines = [
            f"**{total_vulns}** new vulnerabilities across **{num_containers}** containers:",
            "",
            _priority_counts_str(counts),
        ]
        if kev_total:
            lines.append(f"**{kev_total}** in CISA KEV catalog")
        return "\n".join(lines)

    # Tier 2: Per-container summary
    lines = []
    for container_label, vulns in vulns_by_container.items():
        counts = {}
        kev_count = 0
        for v in vulns:
            p = _priority_bucket(v.risk_score)
            counts[p] = counts.get(p, 0) + 1
            if v.is_kev:
                kev_count += 1
        summary = _priority_counts_str(counts)
        if kev_count:
            summary += f" ({kev_count} KEV)"
        lines.append(f"- **{container_label}**: {summary}")
    return "\n".join(lines)


def _dedup_key(v: Vulnerability) -> tuple[str, str, str]:
    return (v.vuln_id, v.package_name, v.installed_version)


def find_new_vulnerabilities(session: Session, scan_ids: list[int]) -> dict[int, list[Vulnerability]]:
    """For each scan in scan_ids, find vulns that are new compared to the previous scan of the same image.

    Returns {scan_id: [new Vulnerability objects]}.
    """
    if not scan_ids:
        return {}

    scans = session.exec(select(Scan).where(Scan.id.in_(scan_ids))).all()  # type: ignore[union-attr]
    result: dict[int, list[Vulnerability]] = {}

    for scan in scans:
        # Get the previous scan for the same image_repository
        prev_scan = session.exec(
            select(Scan)
            .where(
                Scan.image_repository == scan.image_repository, Scan.id != scan.id, Scan.scanned_at < scan.scanned_at
            )
            .order_by(col(Scan.scanned_at).desc())
        ).first()

        current_vulns = session.exec(select(Vulnerability).where(Vulnerability.scan_id == scan.id)).all()

        if not prev_scan:
            # First scan for this image — all vulns are new
            result[scan.id] = list(current_vulns)
            continue

        prev_vulns = session.exec(select(Vulnerability).where(Vulnerability.scan_id == prev_scan.id)).all()
        prev_keys = {_dedup_key(v) for v in prev_vulns}

        new_vulns = [v for v in current_vulns if _dedup_key(v) not in prev_keys]
        if new_vulns:
            result[scan.id] = new_vulns

    return result


async def process_scan_notifications(db: Database, scan_ids: list[int], results: list[BaseException | None]) -> None:
    """Process notifications after a batch of scans completes."""
    with Session(db.engine) as session:
        channels = session.exec(select(NotificationChannel).where(NotificationChannel.enabled == True)).all()  # noqa: E712
        if not channels:
            return

        base_url = ConfigManager.get_setting("BASE_URL", session)["value"] or ""

        # Check for scan failures
        failed_images: list[str] = []
        successful_scan_ids: list[int] = []
        scans_by_id: dict[int, Scan] = {}

        for scan_id, exc in zip(scan_ids, results):
            if isinstance(exc, BaseException):
                # Look up what image this scan was for
                task_scan = session.get(Scan, scan_id)
                img_name = task_scan.image_name if task_scan else f"scan_id={scan_id}"
                failed_images.append(f"{img_name}: {exc}")
            else:
                scan = session.get(Scan, scan_id)
                if scan:
                    successful_scan_ids.append(scan_id)
                    scans_by_id[scan_id] = scan

        # Scan failure notifications
        if failed_images:
            failure_channels = [c for c in channels if c.notify_scan_failure]
            if failure_channels:
                title = "Scan Failure Alert"
                body = "The following scans failed:\n\n" + "\n".join(f"- {f}" for f in failed_images)
                await _dispatch(session, failure_channels, "scan_failure", title, body, "failure")

        if not successful_scan_ids:
            session.commit()
            return

        # Find new vulnerabilities
        new_vulns_by_scan = find_new_vulnerabilities(session, successful_scan_ids)

        # EOL distro alerts — only for images not previously flagged as EOL
        eol_scans: list[Scan] = []
        for s in scans_by_id.values():
            if not s.is_distro_eol:
                continue
            prev_scan = session.exec(
                select(Scan)
                .where(
                    Scan.image_repository == s.image_repository,
                    Scan.id != s.id,
                    Scan.scanned_at < s.scanned_at,
                )
                .order_by(col(Scan.scanned_at).desc())
            ).first()
            if prev_scan is None or not prev_scan.is_distro_eol:
                eol_scans.append(s)

        if eol_scans:
            eol_channels = [c for c in channels if c.notify_eol]
            if eol_channels:
                title = "EOL Distro Alert"
                lines = []
                for s in eol_scans:
                    lines.append(
                        f"- **{s.image_name}** ({s.container_name or 'unknown'}): {s.distro_name} {s.distro_version}"
                    )
                body = "Containers running on end-of-life distributions:\n\n" + "\n".join(lines)
                await _dispatch(session, eol_channels, "eol", title, body, "warning")

        if not new_vulns_by_scan:
            session.commit()
            return

        # Categorise new vulns by container into urgent, KEV, and all-new buckets
        all_by_container: dict[str, list[Vulnerability]] = {}
        urgent_by_container: dict[str, list[Vulnerability]] = {}
        kev_by_container: dict[str, list[Vulnerability]] = {}
        urgent_total = 0
        kev_total = 0
        all_total = 0

        for scan_id, vulns in new_vulns_by_scan.items():
            scan = scans_by_id.get(scan_id)
            if not scan:
                continue
            container_label = scan.container_name or scan.image_name
            for v in vulns:
                all_by_container.setdefault(container_label, []).append(v)
                all_total += 1
                if v.risk_score is not None and v.risk_score >= 80:
                    urgent_by_container.setdefault(container_label, []).append(v)
                    urgent_total += 1
                if v.is_kev:
                    kev_by_container.setdefault(container_label, []).append(v)
                    kev_total += 1

        if urgent_by_container:
            urgent_channels = [c for c in channels if c.notify_urgent]
            if urgent_channels:
                title = f"Urgent: {urgent_total} Urgent-Priority Vulnerabilities Found"
                body = "New vulnerabilities with Urgent priority (risk score >= 80) detected:\n\n" + _build_vuln_body(
                    urgent_by_container, base_url
                )
                await _dispatch(session, urgent_channels, "urgent", title, body, "warning")

        if kev_by_container:
            kev_channels = [c for c in channels if c.notify_kev]
            if kev_channels:
                title = f"KEV Alert: {kev_total} Known Exploited Vulnerabilities Found"
                body = (
                    "New vulnerabilities listed in CISA's Known Exploited Vulnerabilities catalog:\n\n"
                    + _build_vuln_body(kev_by_container, base_url)
                )
                await _dispatch(session, kev_channels, "kev", title, body, "warning")

        if all_by_container:
            all_new_channels = [c for c in channels if c.notify_all_new]
            if all_new_channels:
                title = f"{all_total} New Vulnerabilities Found"
                body = "New vulnerabilities detected across scanned images:\n\n" + _build_vuln_body(
                    all_by_container, base_url
                )
                await _dispatch(session, all_new_channels, "new_vulns", title, body, "info")

        session.commit()


async def send_daily_digest(db: Database) -> None:
    """Send a daily digest of current vulnerability state."""
    with Session(db.engine) as session:
        channels = session.exec(
            select(NotificationChannel).where(
                NotificationChannel.enabled == True,  # noqa: E712
                NotificationChannel.notify_digest == True,  # noqa: E712
            )
        ).all()
        if not channels:
            return

        # Get latest scan per image_repository for running containers
        subq = (
            select(Scan.image_repository, func.max(Scan.id).label("max_id")).group_by(Scan.image_repository).subquery()
        )
        latest_scans = session.exec(select(Scan).join(subq, Scan.id == subq.c.max_id)).all()

        if not latest_scans:
            return

        # Aggregate counts
        total_vulns = 0
        severity_counts: dict[str, int] = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Negligible": 0}
        kev_count = 0
        eol_count = 0
        image_count = len(latest_scans)

        for scan in latest_scans:
            if scan.is_distro_eol:
                eol_count += 1
            vulns = session.exec(select(Vulnerability).where(Vulnerability.scan_id == scan.id)).all()
            for v in vulns:
                total_vulns += 1
                if v.severity in severity_counts:
                    severity_counts[v.severity] += 1
                if v.is_kev:
                    kev_count += 1

        # Compute deltas from last digest
        current_data = {
            "total": total_vulns,
            "severity": severity_counts,
            "kev": kev_count,
            "eol": eol_count,
            "images": image_count,
        }

        app_state = session.get(AppState, 1)
        deltas: dict[str, int] = {}
        if app_state and app_state.last_digest_data:
            try:
                prev = json.loads(app_state.last_digest_data)
                deltas["total"] = total_vulns - prev.get("total", 0)
                deltas["kev"] = kev_count - prev.get("kev", 0)
                deltas["eol"] = eol_count - prev.get("eol", 0)
            except (json.JSONDecodeError, TypeError) as exc:
                logger.warning(
                    "Failed to parse last_digest_data from AppState; skipping delta computation: %s",
                    exc,
                )

        # Build digest body
        lines = [
            f"**{image_count}** images scanned | **{total_vulns}** total vulnerabilities",
            "",
            "| Severity | Count |",
            "|----------|-------|",
        ]
        for sev in ["Critical", "High", "Medium", "Low", "Negligible"]:
            lines.append(f"| {sev} | {severity_counts[sev]} |")
        lines.append("")
        lines.append(f"**KEV (Known Exploited):** {kev_count}")
        lines.append(f"**EOL Distros:** {eol_count}")

        if deltas:
            lines.append("")
            lines.append("**Changes since last digest:**")
            for key, val in deltas.items():
                sign = "+" if val > 0 else ""
                lines.append(f"- {key}: {sign}{val}")

        title = f"DockGuard Daily Digest — {datetime.now(UTC).strftime('%Y-%m-%d')}"
        body = "\n".join(lines)

        await _dispatch(session, channels, "digest", title, body, "info")

        # Save current data for next delta computation
        if not app_state:
            app_state = AppState(id=1)
            session.add(app_state)
        app_state.last_digest_data = json.dumps(current_data)
        session.commit()


async def _dispatch(
    session: Session,
    channels: list[NotificationChannel],
    notification_type: str,
    title: str,
    body: str,
    notify_type: str,
) -> None:
    """Send a notification to each channel individually and log results."""
    for channel in channels:
        ok, error = await notifier.send([channel.apprise_url], title, body, notify_type)
        log = NotificationLog(
            channel_id=channel.id,  # type: ignore[arg-type]
            notification_type=notification_type,
            title=title,
            body=body,
            status="sent" if ok else "failed",
            error_message=error,
            created_at=datetime.now(UTC),
        )
        session.add(log)

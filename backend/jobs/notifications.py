import json
import logging
from collections.abc import Callable
from datetime import UTC, datetime

from sqlmodel import Session, func, select

from backend.api_helpers import _new_vuln_keys_for_scans, _previous_scan, _priority_bucket
from backend.config import ConfigManager
from backend.database import Database
from backend.docker_watcher import DockerWatcher
from backend.models import (
    AppState,
    ImageUpdateCheck,
    NotificationChannel,
    NotificationLog,
    Scan,
    ScanContainer,
    Vulnerability,
)
from backend.services import notifier
from backend.services.notifier import _DEFAULT_BODY_MAXLEN

logger = logging.getLogger(__name__)

_VULN_DEEP_LINK = "/vulnerabilities?cve="

_PRIORITY_ORDER = ["Urgent", "High", "Medium", "Low"]


def _vuln_label(vuln_id: str, base_url: str) -> str:
    """Return a vuln ID as a Markdown link if base_url is set, otherwise plain text."""
    if base_url:
        return f"[{vuln_id}]({base_url.rstrip('/')}{_VULN_DEEP_LINK}{vuln_id})"
    return vuln_id


def _priority_counts_str(counts: dict[str, int]) -> str:
    """Format priority counts like '2 Urgent, 4 High, 3 Medium'."""
    parts = [f"{counts[p]} {p}" for p in _PRIORITY_ORDER if counts.get(p)]
    return ", ".join(parts) if parts else "0 vulns"


def _build_tier1(vulns_by_container: dict[str, list[Vulnerability]], base_url: str) -> str:
    """Full per-CVE detail — one line per vulnerability."""
    lines: list[str] = []
    for container_label, vulns in vulns_by_container.items():
        for v in vulns:
            label = _vuln_label(v.vuln_id, base_url)
            priority = _priority_bucket(v.risk_score)
            entry = f"{label} ({priority}) in {v.package_name} {v.installed_version} — {container_label}"
            if v.is_kev:
                entry += " [KEV]"
            lines.append(entry)
    return "\n".join(lines)


def _build_tier2(vulns_by_container: dict[str, list[Vulnerability]]) -> str:
    """Per-container summary — one line per container with priority counts."""
    lines: list[str] = []
    for container_label, vulns in vulns_by_container.items():
        counts: dict[str, int] = {}
        kev_count = 0
        for v in vulns:
            p = _priority_bucket(v.risk_score)
            counts[p] = counts.get(p, 0) + 1
            if v.is_kev:
                kev_count += 1
        summary = _priority_counts_str(counts)
        if kev_count:
            summary += f" ({kev_count} KEV)"
        lines.append(f"{container_label}: {summary}")
    return "\n".join(lines)


def _build_tier3(vulns_by_container: dict[str, list[Vulnerability]]) -> str:
    """Rolled-up total — single summary with priority breakdown."""
    total_vulns = sum(len(vs) for vs in vulns_by_container.values())
    num_containers = len(vulns_by_container)
    counts: dict[str, int] = {}
    kev_total = 0
    for vulns in vulns_by_container.values():
        for v in vulns:
            p = _priority_bucket(v.risk_score)
            counts[p] = counts.get(p, 0) + 1
            if v.is_kev:
                kev_total += 1
    lines = [
        f"{total_vulns} new vulns across {num_containers} containers",
        _priority_counts_str(counts),
    ]
    if kev_total:
        lines.append(f"{kev_total} in CISA KEV catalog")
    return "\n".join(lines)


def _build_vuln_body(
    vulns_by_container: dict[str, list[Vulnerability]],
    base_url: str,
    max_len: int | None = None,
) -> tuple[str, int]:
    """Build a notification body with size-aware progressive summarization.

    Tries each tier in order and returns the most detailed one that fits
    within max_len. Returns (body_text, tier_used) where tier_used is 1, 2,
    or 3. Callers should append ' [Summary]' to the notification title when
    tier_used > 1 so recipients understand why detail was omitted.
    """
    limit = max_len if max_len is not None else _DEFAULT_BODY_MAXLEN

    tier1 = _build_tier1(vulns_by_container, base_url)
    if len(tier1) <= limit:
        return tier1, 1

    tier2 = _build_tier2(vulns_by_container)
    if len(tier2) <= limit:
        return tier2, 2

    tier3 = _build_tier3(vulns_by_container)
    return tier3[:limit], 3


def _compute_update_diffs(session: Session, checks: list[ImageUpdateCheck]) -> list[dict]:
    """Return a per-image update summary for display in the daily digest.

    Each entry: {"image_name": str, "status": str, "added": int|None, "removed": int|None}
    added/removed are None when the update scan has not yet completed.
    Counts unique CVE IDs added/removed in the registry version vs running version.
    """
    results: list[dict] = []
    for check in checks:
        entry: dict = {"image_name": check.image_name, "status": check.status, "added": None, "removed": None}
        if check.status == "scan_complete" and check.update_scan_id and check.current_scan_id:
            update_cves = set(
                session.exec(select(Vulnerability.vuln_id).where(Vulnerability.scan_id == check.update_scan_id)).all()
            )
            current_cves = set(
                session.exec(select(Vulnerability.vuln_id).where(Vulnerability.scan_id == check.current_scan_id)).all()
            )
            entry["added"] = len(update_cves - current_cves)
            entry["removed"] = len(current_cves - update_cves)
        results.append(entry)
    return results


def _build_eol_body(entries: list[dict], max_len: int | None = None) -> tuple[str, int]:
    """Build a size-aware EOL alert body with three tiers.

    entries: list of {"image_name", "container_display", "distro_name", "distro_version"}
    Returns (body_text, tier_used).
    """
    limit = max_len if max_len is not None else _DEFAULT_BODY_MAXLEN

    tier1 = "\n".join(
        f"{e['image_name']} ({e['container_display']}): {e['distro_name']} {e['distro_version']}" for e in entries
    )
    if len(tier1) <= limit:
        return tier1, 1

    tier2 = ", ".join(e["image_name"] for e in entries)
    if len(tier2) <= limit:
        return tier2, 2

    tier3 = f"{len(entries)} images on EOL distributions"
    return tier3[:limit], 3


def _build_digest_tier1(data: dict) -> str:
    """Full digest — severity breakdown, all deltas, per-image update detail."""
    sev = data["severity"]
    sev_line = (
        f"Crit: {sev['Critical']} | High: {sev['High']} | Med: {sev['Medium']}"
        f" | Low: {sev['Low']} | Neg: {sev['Negligible']}"
    )
    lines = [
        f"{data['image_count']} images scanned | {data['total_vulns']} total vulns",
        "",
        sev_line,
        "",
        f"KEV: {data['kev_count']} | EOL distros: {data['eol_count']}",
    ]
    if data["deltas"]:
        parts = [f"{k} {'+' if v > 0 else ''}{v}" for k, v in data["deltas"].items()]
        lines += ["", "Changes: " + ", ".join(parts)]
    updates = data["updates"]
    if updates:
        lines += ["", f"Updates available ({len(updates)}):"]
        for u in updates:
            if u["status"] == "scan_complete":
                added, removed = u["added"], u["removed"]
                if added and removed:
                    lines.append(f"{u['image_name']}: +{added} added, {removed} fixed")
                elif added:
                    lines.append(f"{u['image_name']}: +{added} added")
                elif removed:
                    lines.append(f"{u['image_name']}: {removed} fixed")
                else:
                    lines.append(f"{u['image_name']}: no vuln changes")
            elif u["status"] == "scan_pending":
                lines.append(f"{u['image_name']}: scan in progress")
            else:
                lines.append(f"{u['image_name']}: update detected")
    return "\n".join(lines)


def _build_digest_tier2(data: dict) -> str:
    """Medium digest — full severity breakdown, update count only (no per-image detail)."""
    sev = data["severity"]
    sev_line = (
        f"Crit: {sev['Critical']} | High: {sev['High']} | Med: {sev['Medium']}"
        f" | Low: {sev['Low']} | Neg: {sev['Negligible']}"
    )
    lines = [
        f"{data['image_count']} images scanned | {data['total_vulns']} total vulns",
        "",
        sev_line,
        "",
        f"KEV: {data['kev_count']} | EOL distros: {data['eol_count']}",
    ]
    if data["deltas"]:
        parts = [f"{k} {'+' if v > 0 else ''}{v}" for k, v in data["deltas"].items()]
        lines += ["", "Changes: " + ", ".join(parts)]
    updates = data["updates"]
    if updates:
        lines += ["", f"Updates available: {len(updates)} images"]
    return "\n".join(lines)


def _build_digest_tier3(data: dict) -> str:
    """Compact digest — drops Med/Low/Neg severity, merges KEV/EOL/Updates, total delta only."""
    sev = data["severity"]
    n_updates = len(data["updates"])
    compact_parts = [
        f"Crit: {sev['Critical']}",
        f"High: {sev['High']}",
        f"KEV: {data['kev_count']}",
        f"EOL: {data['eol_count']}",
    ]
    if n_updates:
        compact_parts.append(f"Updates: {n_updates}")
    lines = [
        f"{data['image_count']} images scanned | {data['total_vulns']} total vulns",
        "",
        " | ".join(compact_parts),
    ]
    if data["deltas"]:
        total_delta = data["deltas"].get("total", 0)
        sign = "+" if total_delta > 0 else ""
        lines += ["", f"Changes: total {sign}{total_delta}"]
    return "\n".join(lines)


def _build_digest_body(data: dict, max_len: int | None = None) -> tuple[str, int]:
    """Build a size-aware digest body. Returns (body_text, tier_used)."""
    limit = max_len if max_len is not None else _DEFAULT_BODY_MAXLEN

    tier1 = _build_digest_tier1(data)
    if len(tier1) <= limit:
        return tier1, 1

    tier2 = _build_digest_tier2(data)
    if len(tier2) <= limit:
        return tier2, 2

    tier3 = _build_digest_tier3(data)
    return tier3[:limit], 3


def find_new_vulnerabilities(session: Session, scan_ids: list[int]) -> dict[int, list[Vulnerability]]:
    """For each scan in scan_ids, find vulns that are new compared to the previous scan of the same image.

    Returns {scan_id: [new Vulnerability objects]}.
    """
    if not scan_ids:
        return {}

    scans = session.exec(select(Scan).where(Scan.id.in_(scan_ids))).all()  # type: ignore[union-attr]
    new_keys_by_scan = _new_vuln_keys_for_scans(session, scans)

    # Load full Vulnerability objects for scans that have new keys
    result: dict[int, list[Vulnerability]] = {}
    scans_with_new = [s_id for s_id, keys in new_keys_by_scan.items() if keys]
    if scans_with_new:
        all_vulns = session.exec(select(Vulnerability).where(Vulnerability.scan_id.in_(scans_with_new))).all()
        for v in all_vulns:
            key = (v.vuln_id, v.package_name, v.installed_version)
            if key in new_keys_by_scan.get(v.scan_id, set()):
                result.setdefault(v.scan_id, []).append(v)

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
                if scan and not scan.is_update_check:
                    successful_scan_ids.append(scan_id)
                    scans_by_id[scan_id] = scan

        # Scan failure notifications
        if failed_images:
            failure_channels = [c for c in channels if c.notify_scan_failure]
            if failure_channels:
                title = "Scan Failure Alert"
                body = "\n".join(failed_images)
                await _dispatch(session, failure_channels, "scan_failure", (title, body), "failure")

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
            prev = _previous_scan(session, s)
            if prev is None or not prev.is_distro_eol:
                eol_scans.append(s)

        if eol_scans:
            eol_channels = [c for c in channels if c.notify_eol]
            if eol_channels:
                eol_scan_ids = [s.id for s in eol_scans]
                eol_containers: dict[int, list[str]] = {}
                for scan_id, cname in session.exec(
                    select(ScanContainer.scan_id, ScanContainer.container_name).where(
                        ScanContainer.scan_id.in_(eol_scan_ids)
                    )
                ).all():
                    eol_containers.setdefault(scan_id, []).append(cname)

                eol_entries = [
                    {
                        "image_name": s.image_name,
                        "container_display": ", ".join(sorted(set(eol_containers.get(s.id, [])))) or "unknown",
                        "distro_name": s.distro_name,
                        "distro_version": s.distro_version,
                    }
                    for s in eol_scans
                ]

                def eol_factory(max_len: int, _entries: list = eol_entries) -> tuple[str, str]:
                    body, tier = _build_eol_body(_entries, max_len)
                    t = "EOL Distro Alert" + (" [Summary]" if tier > 1 else "")
                    return t, body

                await _dispatch(session, eol_channels, "eol", eol_factory, "warning")

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

        containers_by_scan: dict[int, list[str]] = {}
        if new_vulns_by_scan:
            rows = session.exec(
                select(ScanContainer.scan_id, ScanContainer.container_name).where(
                    ScanContainer.scan_id.in_(list(new_vulns_by_scan.keys()))
                )
            ).all()
            for scan_id, container_name in rows:
                containers_by_scan.setdefault(scan_id, []).append(container_name)

        for scan_id, vulns in new_vulns_by_scan.items():
            scan = scans_by_id.get(scan_id)
            if not scan:
                continue
            scan_container_names = sorted(set(containers_by_scan.get(scan_id, [])))
            container_labels = [f"{name} ({scan.image_name})" for name in scan_container_names] or [scan.image_name]
            for v in vulns:
                for container_label in container_labels:
                    all_by_container.setdefault(container_label, []).append(v)
                    all_total += 1
                    if v.risk_score is not None and v.risk_score >= 80:
                        urgent_by_container.setdefault(container_label, []).append(v)
                        urgent_total += 1
                    if v.is_kev:
                        kev_by_container.setdefault(container_label, []).append(v)
                        kev_total += 1

        def _title(n_total: int, n_unique: int, n_containers: int, prefix: str) -> str:
            v = "vuln" if n_total == 1 else "vulns"
            c = "container" if n_containers == 1 else "containers"
            return f"{prefix}{n_total} {v} ({n_unique} unique) across {n_containers} {c}"

        if urgent_by_container:
            urgent_channels = [c for c in channels if c.notify_urgent]
            if urgent_channels:
                unique_urgent = len({v.vuln_id for vulns in urgent_by_container.values() for v in vulns})
                base_title = _title(urgent_total, unique_urgent, len(urgent_by_container), "Urgent: ")

                def urgent_factory(
                    max_len: int, _bc: dict = urgent_by_container, _bu: str = base_url, _t: str = base_title
                ) -> tuple[str, str]:
                    body, tier = _build_vuln_body(_bc, _bu, max_len)
                    t = _t + (" [Summary]" if tier > 1 else "")
                    return t, "Risk score ≥ 80:\n\n" + body

                await _dispatch(session, urgent_channels, "urgent", urgent_factory, "warning")

        if kev_by_container:
            kev_channels = [c for c in channels if c.notify_kev]
            if kev_channels:
                unique_kev = len({v.vuln_id for vulns in kev_by_container.values() for v in vulns})
                base_title = _title(kev_total, unique_kev, len(kev_by_container), "KEV: ")

                def kev_factory(
                    max_len: int, _bc: dict = kev_by_container, _bu: str = base_url, _t: str = base_title
                ) -> tuple[str, str]:
                    body, tier = _build_vuln_body(_bc, _bu, max_len)
                    t = _t + (" [Summary]" if tier > 1 else "")
                    return t, body

                await _dispatch(session, kev_channels, "kev", kev_factory, "warning")

        if all_by_container:
            all_new_channels = [c for c in channels if c.notify_all_new]
            if all_new_channels:
                unique_all = len({v.vuln_id for vulns in all_by_container.values() for v in vulns})
                base_title = _title(all_total, unique_all, len(all_by_container), "New: ")

                def all_new_factory(
                    max_len: int, _bc: dict = all_by_container, _bu: str = base_url, _t: str = base_title
                ) -> tuple[str, str]:
                    body, tier = _build_vuln_body(_bc, _bu, max_len)
                    t = _t + (" [Summary]" if tier > 1 else "")
                    return t, body

                await _dispatch(session, all_new_channels, "new_vulns", all_new_factory, "info")

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

        watcher = DockerWatcher()
        running = watcher.list_running_containers()
        if not running:
            return

        running_images = {item["image_name"] for item in running}
        latest_scan_ids_subq = (
            select(func.max(Scan.id)).where(Scan.image_name.in_(running_images)).group_by(Scan.image_name)
        )
        latest_scans = session.exec(select(Scan).where(Scan.id.in_(latest_scan_ids_subq))).all()

        if not latest_scans:
            return

        # Aggregate counts
        total_vulns = 0
        severity_counts: dict[str, int] = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Negligible": 0}
        kev_count = 0
        eol_count = 0
        image_count = len(latest_scans)

        scan_ids = [s.id for s in latest_scans]
        all_vulns = session.exec(select(Vulnerability).where(Vulnerability.scan_id.in_(scan_ids))).all()

        for scan in latest_scans:
            if scan.is_distro_eol:
                eol_count += 1
        for v in all_vulns:
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

        # Collect update availability information
        _UPDATE_STATUSES = {"update_available", "scan_pending", "scan_complete"}
        update_checks = session.exec(
            select(ImageUpdateCheck).where(ImageUpdateCheck.status.in_(_UPDATE_STATUSES))
        ).all()
        updates = _compute_update_diffs(session, list(update_checks))

        digest_data = {
            "image_count": image_count,
            "total_vulns": total_vulns,
            "severity": severity_counts,
            "kev_count": kev_count,
            "eol_count": eol_count,
            "deltas": deltas,
            "updates": updates,
        }

        title = f"DockGuard Daily Digest — {datetime.now(UTC).strftime('%Y-%m-%d')}"

        def digest_factory(max_len: int, _data: dict = digest_data, _title: str = title) -> tuple[str, str]:
            body, _ = _build_digest_body(_data, max_len)
            return _title, body

        await _dispatch(session, channels, "digest", digest_factory, "info")

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
    content: tuple[str, str] | Callable[[int], tuple[str, str]],
    notify_type: str,
) -> None:
    """Send a notification to each channel individually and log results.

    content may be a (title, body) tuple for fixed messages, or a factory
    callable that accepts max_len (int) and returns (title, body) — used
    when the body must be sized to fit the channel's service limit.
    """
    for channel in channels:
        if callable(content):
            max_len = notifier.get_body_maxlen(channel.apprise_url)
            title, channel_body = content(max_len)
        else:
            title, channel_body = content
        ok, error = await notifier.send([channel.apprise_url], title, channel_body, notify_type)
        log = NotificationLog(
            channel_id=channel.id,  # type: ignore[arg-type]
            notification_type=notification_type,
            title=title,
            body=channel_body,
            status="sent" if ok else "failed",
            error_message=error,
            created_at=datetime.now(UTC),
        )
        session.add(log)

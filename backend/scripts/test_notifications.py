"""CLI tool to send one of each notification type with canned data to real Apprise URLs.

Usage:
    uv run python -m backend.scripts.test_notifications URL [URL ...]
    uv run python -m backend.scripts.test_notifications URL --max-len 512
    uv run python -m backend.scripts.test_notifications URL --base-url https://dockguard.example.com

Pass --max-len to override the detected body_maxlen for all channels.
This lets you simulate constrained services and verify which summary tier is chosen.

Pass --base-url to include CVE deep links in vuln notification bodies.
Without it, vuln bodies contain plain CVE IDs with no links.
"""

import argparse
import asyncio

from backend.jobs.notifications import _build_digest_body, _build_eol_body, _build_vuln_body
from backend.models import Vulnerability
from backend.services import notifier
from backend.services.notifier import get_body_maxlen

# ---------------------------------------------------------------------------
# Canned data — vulnerabilities
# ---------------------------------------------------------------------------

_CONTAINERS = {
    "web-1 (nginx:latest)": [
        Vulnerability(
            scan_id=0,
            vuln_id="CVE-2024-1234",
            severity="Critical",
            package_name="openssl",
            installed_version="3.0.1",
            risk_score=92.0,
            is_kev=True,
        ),
        Vulnerability(
            scan_id=0,
            vuln_id="CVE-2024-5678",
            severity="High",
            package_name="curl",
            installed_version="7.81.0",
            risk_score=75.0,
            is_kev=False,
        ),
        Vulnerability(
            scan_id=0,
            vuln_id="CVE-2023-9999",
            severity="Medium",
            package_name="zlib",
            installed_version="1.2.11",
            risk_score=45.0,
            is_kev=False,
        ),
        Vulnerability(
            scan_id=0,
            vuln_id="CVE-2023-8888",
            severity="Low",
            package_name="libxml2",
            installed_version="2.9.10",
            risk_score=18.0,
            is_kev=False,
        ),
    ],
    "db-1 (postgres:16-alpine)": [
        Vulnerability(
            scan_id=0,
            vuln_id="CVE-2024-2222",
            severity="High",
            package_name="libc",
            installed_version="2.35",
            risk_score=78.0,
            is_kev=False,
        ),
        Vulnerability(
            scan_id=0,
            vuln_id="CVE-2024-3333",
            severity="Medium",
            package_name="openssl",
            installed_version="3.0.1",
            risk_score=55.0,
            is_kev=False,
        ),
        Vulnerability(
            scan_id=0,
            vuln_id="CVE-2024-4444",
            severity="Low",
            package_name="bash",
            installed_version="5.1.16",
            risk_score=20.0,
            is_kev=True,
        ),
    ],
    "cache-1 (redis:7-alpine)": [
        Vulnerability(
            scan_id=0,
            vuln_id="CVE-2023-7777",
            severity="Medium",
            package_name="musl",
            installed_version="1.2.3",
            risk_score=40.0,
            is_kev=False,
        ),
        Vulnerability(
            scan_id=0,
            vuln_id="CVE-2023-6666",
            severity="Low",
            package_name="busybox",
            installed_version="1.35.0",
            risk_score=15.0,
            is_kev=False,
        ),
    ],
}

_URGENT_CONTAINERS = {
    k: [v for v in vs if v.risk_score is not None and v.risk_score >= 80]
    for k, vs in _CONTAINERS.items()
    if any(v.risk_score is not None and v.risk_score >= 80 for v in vs)
}

_KEV_CONTAINERS = {k: [v for v in vs if v.is_kev] for k, vs in _CONTAINERS.items() if any(v.is_kev for v in vs)}

# ---------------------------------------------------------------------------
# Canned data — digest
# ---------------------------------------------------------------------------

_DIGEST_DATA = {
    "image_count": 5,
    "total_vulns": 3844,
    "severity": {"Critical": 83, "High": 769, "Medium": 1618, "Low": 253, "Negligible": 1009},
    "kev_count": 16,
    "eol_count": 1,
    "deltas": {"total": 39, "kev": 2, "eol": 0},
    "updates": [
        {"image_name": "nginx:latest", "status": "scan_complete", "added": 3, "removed": 1},
        {"image_name": "postgres:16", "status": "scan_pending", "added": None, "removed": None},
    ],
}

# ---------------------------------------------------------------------------
# Canned data — EOL
# ---------------------------------------------------------------------------

_EOL_ENTRIES = [
    {
        "image_name": "myapp:2.0",
        "container_display": "myapp-1",
        "distro_name": "debian",
        "distro_version": "10 (buster)",
    },
]

_FAILURE_BODY = "broken-image:latest: failed to pull manifest: not found"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _vuln_title(containers: dict, prefix: str) -> str:
    total = sum(len(vs) for vs in containers.values())
    unique = len({v.vuln_id for vs in containers.values() for v in vs})
    n = len(containers)
    v = "vuln" if total == 1 else "vulns"
    c = "container" if n == 1 else "containers"
    return f"{prefix}{total} {v} ({unique} unique) across {n} {c}"


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


async def _send_all(urls: list[str], max_len_override: int | None, base_url: str) -> None:
    print(f"\nSending to {len(urls)} channel(s):")
    limits: list[int] = []
    for url in urls:
        detected = get_body_maxlen(url)
        limit = max_len_override if max_len_override is not None else detected
        limits.append(limit)
        override_note = f" (overridden from {detected})" if max_len_override is not None else ""
        print(f"  {url[:60]}{'...' if len(url) > 60 else ''} → body_maxlen: {limit}{override_note}")

    vuln_notifications = [
        (_CONTAINERS, "New: ", "new_vulns", "", "info"),
        (_URGENT_CONTAINERS, "Urgent: ", "urgent", "Risk score ≥ 80:\n\n", "warning"),
        (_KEV_CONTAINERS, "KEV: ", "kev", "", "warning"),
    ]

    print()
    for url, limit in zip(urls, limits):
        label = url[:50] + ("..." if len(url) > 50 else "")
        print(f"── {label} (limit: {limit}) ──")

        # Digest — size-aware tiering
        digest_body, digest_tier = _build_digest_body(_DIGEST_DATA, limit)
        digest_title = "DockGuard Daily Digest — 2026-03-22"
        ok, err = await notifier.send([url], digest_title, digest_body, "info")
        status = "OK" if ok else f"FAIL: {err}"
        print(f"  [digest] {status} ({len(digest_body)} chars, tier {digest_tier})")

        # EOL — size-aware tiering
        eol_body, eol_tier = _build_eol_body(_EOL_ENTRIES, limit)
        eol_title = "EOL Distro Alert" + (" [Summary]" if eol_tier > 1 else "")
        ok, err = await notifier.send([url], eol_title, eol_body, "warning")
        status = "OK" if ok else f"FAIL: {err}"
        print(f"  [eol] {status} ({len(eol_body)} chars, tier {eol_tier})")

        # Scan failure — fixed format (no tiering needed)
        ok, err = await notifier.send([url], "Scan Failure Alert", _FAILURE_BODY, "failure")
        status = "OK" if ok else f"FAIL: {err}"
        print(f"  [scan_failure] {status} ({len(_FAILURE_BODY)} chars, fixed format)")

        # Vuln notifications — size-aware tiering
        for containers, prefix, notif_type, preamble, notify_type in vuln_notifications:
            if not containers:
                print(f"  [{notif_type}] skipped (no matching vulns in canned data)")
                continue
            base_title = _vuln_title(containers, prefix)
            effective_limit = max(0, limit - len(preamble))
            vuln_body, tier = _build_vuln_body(containers, base_url=base_url, max_len=effective_limit)
            title = base_title + (" [Summary]" if tier > 1 else "")
            full_body = preamble + vuln_body
            ok, err = await notifier.send([url], title, full_body, notify_type)
            status = "OK" if ok else f"FAIL: {err}"
            tier_note = f"tier {tier}" + (" [Summary]" if tier > 1 else "")
            print(f"  [{notif_type}] {status} ({len(full_body)} chars, {tier_note})")

        print()


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Send one of each DockGuard notification type with canned data to real Apprise URLs.",
        epilog="Example: uv run python -m backend.scripts.test_notifications pover://user@token --base-url https://dockguard.example.com",
    )
    parser.add_argument("urls", nargs="+", metavar="URL", help="Apprise URL(s) to send to")
    parser.add_argument(
        "--max-len",
        type=int,
        default=None,
        metavar="N",
        help="Override body_maxlen for all channels (useful for testing summary tiers)",
    )
    parser.add_argument(
        "--base-url",
        default="",
        metavar="URL",
        help="Base URL for CVE deep links in vuln notifications (e.g. https://dockguard.example.com)",
    )
    args = parser.parse_args()
    asyncio.run(_send_all(args.urls, args.max_len, args.base_url))


if __name__ == "__main__":
    main()

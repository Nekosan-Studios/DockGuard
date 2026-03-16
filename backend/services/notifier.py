import asyncio
import logging

import apprise

logger = logging.getLogger(__name__)


def validate_url(apprise_url: str) -> bool:
    """Check whether *apprise_url* is recognised by Apprise.

    NOTE: This only validates the URL scheme — it does not restrict target hosts.
    Apprise schemes like json://, xml://, form:// will make outbound HTTP requests
    to whatever host the user specifies.  This is acceptable for the current
    single-user, self-hosted deployment model.  If multi-user auth is added,
    revisit this to either restrict schemes or validate resolved IPs against
    private/link-local ranges (see changedetection.io CVE-2026-27696 for prior art).
    """
    ap = apprise.Apprise()
    return ap.add(apprise_url)


async def send(
    apprise_urls: list[str],
    title: str,
    body: str,
    notify_type: str = "info",
) -> tuple[bool, str | None]:
    """Send a notification via Apprise (runs in a thread since Apprise is sync).

    Notifications are always sent as Markdown.  Apprise automatically converts
    to the native format each plugin expects (plain text, HTML, etc.).

    Returns (success, error_message).
    """
    type_map = {
        "info": apprise.NotifyType.INFO,
        "success": apprise.NotifyType.SUCCESS,
        "warning": apprise.NotifyType.WARNING,
        "failure": apprise.NotifyType.FAILURE,
    }
    nt = type_map.get(notify_type, apprise.NotifyType.INFO)

    def _send() -> tuple[bool, str | None]:
        ap = apprise.Apprise()
        invalid_urls: list[str] = []
        for url in apprise_urls:
            if not ap.add(url):
                invalid_urls.append(url)
        if not ap:
            msg = "No valid Apprise URLs"
            if invalid_urls:
                msg += f": all {len(invalid_urls)} URL(s) were rejected"
            return False, msg
        ok = ap.notify(title=title, body=body, notify_type=nt, body_format=apprise.NotifyFormat.MARKDOWN)
        if not ok:
            msg = "Apprise notify() returned False — check URL validity"
            if invalid_urls:
                msg += f"; {len(invalid_urls)} URL(s) were also rejected before sending"
            return False, msg
        if invalid_urls:
            logger.warning("Some Apprise URLs were rejected and skipped: %s", invalid_urls)
        return True, None

    try:
        return await asyncio.to_thread(_send)
    except Exception as exc:
        logger.exception("Apprise send error")
        return False, str(exc)


async def test(apprise_url: str) -> tuple[bool, str | None]:
    """Send a test notification to a single Apprise URL."""
    return await send(
        [apprise_url],
        title="DockGuard Test Notification",
        body="If you see this, your notification channel is working correctly.",
        notify_type="info",
    )

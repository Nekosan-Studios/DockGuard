import html
import ipaddress
import logging
import re
import time
from collections.abc import Iterable
from urllib.parse import urlparse

import httpx

logger = logging.getLogger(__name__)

_TITLE_TIMEOUT_SECONDS = 2.5
_MAX_URLS_PER_VULN = 8
_MAX_CWES_PER_VULN = 8
_MAX_URLS_PER_SCAN = 100
_MAX_CWES_PER_SCAN = 50
_GLOBAL_TITLE_BUDGET_SECONDS = 30.0
_MAX_TITLE_LENGTH = 140
_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
_CWE_ID_RE = re.compile(r"^CWE-(\d+)$", re.IGNORECASE)
_ALLOWED_SCHEMES = frozenset({"http", "https"})
_BLOCKED_SUFFIXES = (".local", ".internal", ".localhost")


def _is_safe_url(url: str) -> bool:
    """Return True only if the URL is safe to fetch (public http/https, no private IPs)."""
    try:
        parsed = urlparse(url)
    except Exception:
        return False
    if parsed.scheme not in _ALLOWED_SCHEMES:
        return False
    host = parsed.hostname
    if not host:
        return False
    # Block IP literals that point to private/loopback/link-local/reserved ranges
    try:
        addr = ipaddress.ip_address(host)
        if addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved:
            return False
    except ValueError:
        pass  # Not an IP literal — check hostname
    lower = host.lower()
    if lower == "localhost" or any(lower.endswith(s) for s in _BLOCKED_SUFFIXES):
        return False
    return True


def _assert_safe_url(request: httpx.Request) -> None:
    """httpx event hook: fires before every request, including redirects."""
    if not _is_safe_url(str(request.url)):
        raise httpx.HTTPError(f"Blocked request to unsafe URL: {request.url}")


def _clean_title(raw_title: str) -> str | None:
    if not raw_title:
        return None
    title = html.unescape(raw_title)
    title = re.sub(r"\s+", " ", title).strip()
    title = re.sub(r"^[\s\-|:–—]+", "", title)
    title = re.sub(r"[\s\-|:–—]+$", "", title)
    if not title:
        return None
    if len(title) > _MAX_TITLE_LENGTH:
        return title[: _MAX_TITLE_LENGTH - 1].rstrip() + "…"
    return title


def _extract_html_title(body: str) -> str | None:
    match = _TITLE_RE.search(body)
    if not match:
        return None
    return _clean_title(match.group(1))


def _fetch_title(url: str, client: httpx.Client, deadline: float | None = None) -> str | None:
    if deadline is not None and time.monotonic() >= deadline:
        return None
    try:
        response = client.get(
            url,
            headers={"User-Agent": "DockGuard/1.0 (+https://github.com/mattweinecke/DockGuard)"},
        )
    except (httpx.HTTPError, ValueError):
        return None

    if response.status_code < 200 or response.status_code >= 300:
        return None

    content_type = response.headers.get("content-type", "").lower()
    if "text/html" not in content_type and "application/xhtml+xml" not in content_type:
        return None

    return _extract_html_title(response.text)


def fetch_reference_titles(urls: Iterable[str]) -> dict[str, str]:
    seen: set[str] = set()
    unique_urls: list[str] = []
    for raw_url in urls:
        url = raw_url.strip()
        if not url or url in seen:
            continue
        seen.add(url)
        unique_urls.append(url)
        if len(unique_urls) >= _MAX_URLS_PER_VULN:
            break

    if not unique_urls:
        return {}

    titles: dict[str, str] = {}
    try:
        with httpx.Client(
            timeout=_TITLE_TIMEOUT_SECONDS,
            follow_redirects=True,
            event_hooks={"request": [_assert_safe_url]},
        ) as client:
            for url in unique_urls:
                title = _fetch_title(url, client)
                if title:
                    titles[url] = title
    except Exception:
        logger.debug("Reference title fetching skipped due to unexpected error", exc_info=True)

    return titles


def _normalise_cwe_id(cwe_id: str) -> str | None:
    value = cwe_id.strip().upper()
    match = _CWE_ID_RE.match(value)
    if not match:
        return None
    return f"CWE-{match.group(1)}"


def _extract_cwe_name(title: str, cwe_id: str) -> str | None:
    # Common MITRE title format: "CWE - CWE-400: Uncontrolled Resource Consumption"
    cwe_pattern = re.escape(cwe_id)
    match = re.search(rf"{cwe_pattern}\s*:\s*(.+)$", title, re.IGNORECASE)
    if match:
        return _clean_title(match.group(1))
    return None


def fetch_all_titles(
    all_urls: Iterable[str],
    all_cwe_ids: Iterable[str],
    budget_seconds: float = _GLOBAL_TITLE_BUDGET_SECONDS,
) -> tuple[dict[str, str], dict[str, str]]:
    """Fetch reference URL titles and CWE names for an entire scan in one pass.

    Deduplicates across all vulnerabilities and stops once the global time budget
    is exhausted. Returns (url_titles, cwe_titles).
    """
    seen_urls: set[str] = set()
    unique_urls: list[str] = []
    for raw_url in all_urls:
        url = raw_url.strip()
        if not url or url in seen_urls:
            continue
        seen_urls.add(url)
        unique_urls.append(url)
        if len(unique_urls) >= _MAX_URLS_PER_SCAN:
            break

    seen_cwes: set[str] = set()
    unique_cwes: list[str] = []
    for raw_cwe in all_cwe_ids:
        cwe_id = _normalise_cwe_id(raw_cwe)
        if not cwe_id or cwe_id in seen_cwes:
            continue
        seen_cwes.add(cwe_id)
        unique_cwes.append(cwe_id)
        if len(unique_cwes) >= _MAX_CWES_PER_SCAN:
            break

    if not unique_urls and not unique_cwes:
        return {}, {}

    url_titles: dict[str, str] = {}
    cwe_titles: dict[str, str] = {}
    deadline = time.monotonic() + budget_seconds

    try:
        with httpx.Client(
            timeout=_TITLE_TIMEOUT_SECONDS,
            follow_redirects=True,
            event_hooks={"request": [_assert_safe_url]},
        ) as client:
            for url in unique_urls:
                title = _fetch_title(url, client, deadline)
                if title:
                    url_titles[url] = title

            for cwe_id in unique_cwes:
                cwe_num = cwe_id.replace("CWE-", "")
                cwe_url = f"https://cwe.mitre.org/data/definitions/{cwe_num}.html"
                title = _fetch_title(cwe_url, client, deadline)
                if not title:
                    continue
                name = _extract_cwe_name(title, cwe_id)
                if name:
                    cwe_titles[cwe_id] = name
    except Exception:
        logger.debug("Reference title fetching skipped due to unexpected error", exc_info=True)

    return url_titles, cwe_titles


def fetch_cwe_titles(cwe_ids: Iterable[str]) -> dict[str, str]:
    normalised: list[str] = []
    seen: set[str] = set()
    for raw in cwe_ids:
        cwe_id = _normalise_cwe_id(raw)
        if not cwe_id or cwe_id in seen:
            continue
        seen.add(cwe_id)
        normalised.append(cwe_id)
        if len(normalised) >= _MAX_CWES_PER_VULN:
            break

    if not normalised:
        return {}

    titles: dict[str, str] = {}
    try:
        with httpx.Client(
            timeout=_TITLE_TIMEOUT_SECONDS,
            follow_redirects=True,
            event_hooks={"request": [_assert_safe_url]},
        ) as client:
            for cwe_id in normalised:
                cwe_num = cwe_id.replace("CWE-", "")
                url = f"https://cwe.mitre.org/data/definitions/{cwe_num}.html"
                title = _fetch_title(url, client)
                if not title:
                    continue
                name = _extract_cwe_name(title, cwe_id)
                if name:
                    titles[cwe_id] = name
    except Exception:
        logger.debug("CWE title fetching skipped due to unexpected error", exc_info=True)

    return titles

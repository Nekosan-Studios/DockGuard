import html
import logging
import re
from collections.abc import Iterable

import httpx

logger = logging.getLogger(__name__)

_TITLE_TIMEOUT_SECONDS = 2.5
_MAX_URLS_PER_VULN = 8
_MAX_CWES_PER_VULN = 8
_MAX_TITLE_LENGTH = 140
_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
_CWE_ID_RE = re.compile(r"^CWE-(\d+)$", re.IGNORECASE)


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


def _fetch_title(url: str, client: httpx.Client) -> str | None:
    try:
        response = client.get(
            url,
            headers={"User-Agent": "DockGuard/1.0 (+https://github.com/mattweinecke/DockGuard)"},
        )
    except httpx.HTTPError, ValueError:
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
        with httpx.Client(timeout=_TITLE_TIMEOUT_SECONDS, follow_redirects=True) as client:
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
        with httpx.Client(timeout=_TITLE_TIMEOUT_SECONDS, follow_redirects=True) as client:
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

from unittest.mock import MagicMock, patch

import httpx

from backend.reference_titles import (
    _clean_title,
    _extract_cwe_name,
    _extract_html_title,
    _fetch_title,
    fetch_cwe_titles,
    fetch_reference_titles,
)


def test_clean_title_normalizes_whitespace_and_html_entities():
    result = _clean_title("  Security &amp; Advisory   Update  ")
    assert result == "Security & Advisory Update"


def test_clean_title_trims_leading_and_trailing_separators():
    result = _clean_title(" - | : Advisory title — ")
    assert result == "Advisory title"


def test_extract_html_title_returns_none_when_missing():
    assert _extract_html_title("<html><body>No title here</body></html>") is None


def test_extract_html_title_extracts_case_insensitive_title_tag():
    body = "<HTML><HEAD><TITLE> Example Advisory </TITLE></HEAD><BODY></BODY></HTML>"
    assert _extract_html_title(body) == "Example Advisory"


def test_fetch_title_returns_none_on_non_2xx_status():
    client = MagicMock()
    client.get.return_value = MagicMock(status_code=404, headers={"content-type": "text/html"}, text="<title>X</title>")

    assert _fetch_title("https://example.com", client) is None


def test_fetch_title_returns_none_on_non_html_content_type():
    client = MagicMock()
    client.get.return_value = MagicMock(status_code=200, headers={"content-type": "application/json"}, text="{}")

    assert _fetch_title("https://example.com", client) is None


def test_fetch_title_extracts_title_for_valid_html_response():
    client = MagicMock()
    client.get.return_value = MagicMock(
        status_code=200,
        headers={"content-type": "text/html; charset=utf-8"},
        text="<html><head><title>Vendor Advisory</title></head><body></body></html>",
    )

    assert _fetch_title("https://example.com", client) == "Vendor Advisory"


def test_fetch_title_handles_http_errors():
    client = MagicMock()
    client.get.side_effect = httpx.TimeoutException("timeout")

    assert _fetch_title("https://example.com", client) is None


def test_fetch_reference_titles_deduplicates_and_skips_empty_urls():
    client = MagicMock()
    client.__enter__.return_value = client
    client.__exit__.return_value = None

    first = MagicMock(
        status_code=200,
        headers={"content-type": "text/html"},
        text="<title>First</title>",
    )
    second = MagicMock(
        status_code=200,
        headers={"content-type": "text/html"},
        text="<title>Second</title>",
    )
    client.get.side_effect = [first, second]

    with patch("backend.reference_titles.httpx.Client", return_value=client):
        result = fetch_reference_titles(
            [
                "https://one.example/advisory",
                "https://one.example/advisory",
                "  ",
                "https://two.example/advisory",
            ]
        )

    assert result == {
        "https://one.example/advisory": "First",
        "https://two.example/advisory": "Second",
    }


def test_fetch_reference_titles_returns_empty_on_unexpected_exception():
    with patch("backend.reference_titles.httpx.Client", side_effect=RuntimeError("boom")):
        result = fetch_reference_titles(["https://one.example/advisory"])

    assert result == {}


def test_extract_cwe_name_from_mitre_style_title():
    title = "CWE - CWE-400: Uncontrolled Resource Consumption"
    assert _extract_cwe_name(title, "CWE-400") == "Uncontrolled Resource Consumption"


def test_fetch_cwe_titles_uses_cwe_id_as_key_and_name_as_value():
    client = MagicMock()
    client.__enter__.return_value = client
    client.__exit__.return_value = None

    cwe_400 = MagicMock(
        status_code=200,
        headers={"content-type": "text/html"},
        text="<title>CWE - CWE-400: Uncontrolled Resource Consumption</title>",
    )
    client.get.side_effect = [cwe_400]

    with patch("backend.reference_titles.httpx.Client", return_value=client):
        result = fetch_cwe_titles(["CWE-400", "cwe-400", "invalid"])

    assert result == {"CWE-400": "Uncontrolled Resource Consumption"}

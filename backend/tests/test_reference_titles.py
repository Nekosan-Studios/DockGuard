from unittest.mock import MagicMock, patch

import httpx

from backend.reference_titles import (
    _assert_safe_url,
    _clean_title,
    _extract_cwe_name,
    _extract_html_title,
    _fetch_title,
    _is_safe_url,
    fetch_all_titles,
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


def test_fetch_all_titles_returns_empty_for_no_input():
    url_titles, cwe_titles = fetch_all_titles([], [])
    assert url_titles == {}
    assert cwe_titles == {}


def test_fetch_all_titles_deduplicates_urls_and_cwes():
    client = MagicMock()
    client.__enter__.return_value = client
    client.__exit__.return_value = None

    url_response = MagicMock(
        status_code=200,
        headers={"content-type": "text/html"},
        text="<title>Advisory</title>",
    )
    cwe_response = MagicMock(
        status_code=200,
        headers={"content-type": "text/html"},
        text="<title>CWE - CWE-79: Cross-site Scripting</title>",
    )
    # Only 2 HTTP calls should be made despite duplicates in input
    client.get.side_effect = [url_response, cwe_response]

    with patch("backend.reference_titles.httpx.Client", return_value=client):
        url_titles, cwe_titles = fetch_all_titles(
            ["https://example.com/a", "https://example.com/a"],  # duplicate URL
            ["CWE-79", "cwe-79"],  # duplicate CWE
        )

    assert client.get.call_count == 2
    assert url_titles == {"https://example.com/a": "Advisory"}
    assert cwe_titles == {"CWE-79": "Cross-site Scripting"}


def test_is_safe_url_allows_public_https():
    assert _is_safe_url("https://nvd.nist.gov/vuln/detail/CVE-2023-1234") is True


def test_is_safe_url_allows_public_http():
    assert _is_safe_url("http://example.com/advisory") is True


def test_is_safe_url_blocks_file_scheme():
    assert _is_safe_url("file:///etc/passwd") is False


def test_is_safe_url_blocks_loopback_ip():
    assert _is_safe_url("http://127.0.0.1/") is False


def test_is_safe_url_blocks_private_ip():
    assert _is_safe_url("http://192.168.1.1/") is False
    assert _is_safe_url("http://10.0.0.1/") is False


def test_is_safe_url_blocks_link_local_ip():
    assert _is_safe_url("http://169.254.169.254/latest/meta-data/") is False


def test_is_safe_url_blocks_localhost_hostname():
    assert _is_safe_url("http://localhost/") is False


def test_is_safe_url_blocks_dot_local_hostname():
    assert _is_safe_url("http://myserver.local/") is False


def test_is_safe_url_blocks_internal_hostname():
    assert _is_safe_url("http://db.internal/") is False


def test_assert_safe_url_raises_for_private_ip():
    request = MagicMock(spec=httpx.Request)
    request.url = httpx.URL("http://192.168.1.1/")
    try:
        _assert_safe_url(request)
        assert False, "Expected HTTPError"
    except httpx.HTTPError:
        pass


def test_assert_safe_url_does_not_raise_for_public_url():
    request = MagicMock(spec=httpx.Request)
    request.url = httpx.URL("https://nvd.nist.gov/vuln/detail/CVE-2023-1234")
    _assert_safe_url(request)  # Should not raise


def test_fetch_all_titles_stops_when_budget_exceeded():
    client = MagicMock()
    client.__enter__.return_value = client
    client.__exit__.return_value = None
    client.get.return_value = MagicMock(
        status_code=200,
        headers={"content-type": "text/html"},
        text="<title>Advisory</title>",
    )

    # Simulate an already-expired budget by setting budget_seconds to 0 and
    # patching monotonic so the deadline is immediately in the past.
    with patch("backend.reference_titles.httpx.Client", return_value=client):
        with patch("backend.reference_titles.time.monotonic", return_value=1000.0):
            url_titles, cwe_titles = fetch_all_titles(
                ["https://example.com/a", "https://example.com/b"],
                [],
                budget_seconds=0.0,  # deadline = 1000.0 + 0.0 = 1000.0, already met
            )

    client.get.assert_not_called()
    assert url_titles == {}
    assert cwe_titles == {}

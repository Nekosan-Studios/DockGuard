"""End-to-end tests — auto-skipped if Docker or Grype are not available.

These tests exercise the full pipeline:
  Docker daemon → scheduler detects running container → Grype scans → DB → API

Excluded from the default test run (see addopts in pyproject.toml). Run with:
    uv run pytest -v -m e2e
"""
import time

import pytest


@pytest.mark.e2e
def test_new_running_image_gets_scanned(e2e_client, test_container):
    """A running container is detected, scanned by Grype, and queryable via API.

    The scheduler is patched to a 5-second interval so we don't wait a full
    minute for the first poll. We then poll the API for up to 120 seconds
    (enough for Grype to finish scanning alpine:latest).
    """
    client, _db = e2e_client
    image_name = test_container["image_ref"]

    deadline = time.time() + 120
    response = None
    while time.time() < deadline:
        resp = client.get(f"/images/vulnerabilities?image_ref={image_name}")
        if resp.status_code == 200:
            response = resp
            break
        time.sleep(2)

    assert response is not None, (
        f"No successful scan appeared for '{image_name}' within 120 seconds"
    )
    assert response.status_code == 200
    body = response.json()
    assert body["scan_id"] is not None, "scan_id should be set"
    assert "vulnerabilities" in body

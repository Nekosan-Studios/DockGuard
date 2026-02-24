from datetime import datetime, timedelta, timezone

import pytest

from tests.conftest import (
    VULN_CRITICAL,
    VULN_CRITICAL_2,
    VULN_HIGH,
    VULN_MEDIUM,
    seed_scan,
)


# ---------------------------------------------------------------------------
# GET /images/vulnerabilities
# ---------------------------------------------------------------------------

def test_get_vulnerabilities_returns_all(api_client):
    client, test_db, _ = api_client
    seed_scan(test_db, "nginx:latest", "sha256:aaaa", [VULN_CRITICAL, VULN_HIGH, VULN_MEDIUM])

    response = client.get("/images/vulnerabilities?name=nginx:latest")
    assert response.status_code == 200
    data = response.json()
    assert data["count"] == 3
    assert len(data["vulnerabilities"]) == 3


def test_get_vulnerabilities_not_found(api_client):
    client, test_db, _ = api_client
    response = client.get("/images/vulnerabilities?name=unknown:image")
    assert response.status_code == 404


def test_get_vulnerabilities_returns_latest_scan_only(api_client):
    client, test_db, _ = api_client
    t1 = datetime.now(timezone.utc) - timedelta(hours=1)
    t2 = datetime.now(timezone.utc)
    # older scan: 3 vulns
    seed_scan(test_db, "nginx:latest", "sha256:aaaa", [VULN_CRITICAL, VULN_HIGH, VULN_MEDIUM], scanned_at=t1)
    # newer scan: 1 vuln
    seed_scan(test_db, "nginx:latest", "sha256:bbbb", [VULN_CRITICAL], scanned_at=t2)

    response = client.get("/images/vulnerabilities?name=nginx:latest")
    assert response.json()["count"] == 1


# ---------------------------------------------------------------------------
# GET /images/vulnerabilities/critical
# ---------------------------------------------------------------------------

def test_get_critical_vulnerabilities_returns_only_critical(api_client):
    client, test_db, _ = api_client
    seed_scan(test_db, "nginx:latest", "sha256:aaaa", [VULN_CRITICAL, VULN_HIGH, VULN_MEDIUM])

    response = client.get("/images/vulnerabilities/critical?name=nginx:latest")
    assert response.status_code == 200
    data = response.json()
    assert data["count"] == 1
    assert data["vulnerabilities"][0]["severity"] == "Critical"


def test_get_critical_vulnerabilities_not_found(api_client):
    client, test_db, _ = api_client
    response = client.get("/images/vulnerabilities/critical?name=unknown:image")
    assert response.status_code == 404


# ---------------------------------------------------------------------------
# GET /vulnerabilities/critical/running
# ---------------------------------------------------------------------------

def test_get_critical_running_with_running_containers(api_client):
    client, test_db, mock_watcher_cls = api_client
    seed_scan(test_db, "redis:7", "sha256:cccc", [VULN_CRITICAL_2, VULN_CRITICAL_2])
    mock_watcher_cls.return_value.list_images.return_value = [
        {"name": "redis:7", "grype_ref": "redis:7", "hash": "cccc00000000", "running": True},
    ]

    response = client.get("/vulnerabilities/critical/running")
    assert response.status_code == 200
    data = response.json()
    assert data["count"] == 2
    assert "redis:7" in data["running_images"]


def test_get_critical_running_no_running_containers(api_client):
    client, test_db, mock_watcher_cls = api_client
    seed_scan(test_db, "nginx:latest", "sha256:aaaa", [VULN_CRITICAL])
    mock_watcher_cls.return_value.list_images.return_value = [
        {"name": "nginx:latest", "grype_ref": "nginx:latest", "hash": "aaaa00000000", "running": False},
    ]

    response = client.get("/vulnerabilities/critical/running")
    data = response.json()
    assert data["count"] == 0
    assert data["running_images"] == []


def test_get_critical_running_no_scan_for_running_image(api_client):
    client, test_db, mock_watcher_cls = api_client
    # running image exists in Docker but has no scan in DB
    mock_watcher_cls.return_value.list_images.return_value = [
        {"name": "alpine:latest", "grype_ref": "alpine:latest", "hash": "dddd00000000", "running": True},
    ]

    response = client.get("/vulnerabilities/critical/running")
    assert response.status_code == 200
    assert response.json()["count"] == 0


# ---------------------------------------------------------------------------
# GET /vulnerabilities/count
# ---------------------------------------------------------------------------

def test_get_total_count(api_client):
    client, test_db, _ = api_client
    seed_scan(test_db, "nginx:latest", "sha256:aaaa", [VULN_CRITICAL, VULN_HIGH, VULN_MEDIUM])
    seed_scan(test_db, "redis:7", "sha256:cccc", [VULN_CRITICAL_2, VULN_CRITICAL_2])

    response = client.get("/vulnerabilities/count")
    assert response.status_code == 200
    assert response.json()["total_vulnerability_count"] == 5


def test_get_total_count_uses_latest_scan_per_image(api_client):
    client, test_db, _ = api_client
    t1 = datetime.now(timezone.utc) - timedelta(hours=1)
    t2 = datetime.now(timezone.utc)
    seed_scan(test_db, "nginx:latest", "sha256:aaaa", [VULN_CRITICAL, VULN_HIGH, VULN_MEDIUM], scanned_at=t1)
    seed_scan(test_db, "nginx:latest", "sha256:bbbb", [VULN_CRITICAL], scanned_at=t2)

    response = client.get("/vulnerabilities/count")
    # latest scan has 1 vuln, older scan should not be counted
    assert response.json()["total_vulnerability_count"] == 1


def test_get_total_count_empty_db(api_client):
    client, test_db, _ = api_client
    response = client.get("/vulnerabilities/count")
    assert response.status_code == 200
    assert response.json()["total_vulnerability_count"] == 0


# ---------------------------------------------------------------------------
# GET /images/vulnerabilities/history
# ---------------------------------------------------------------------------

def test_get_history_single_scan(api_client):
    client, test_db, _ = api_client
    seed_scan(test_db, "nginx:latest", "sha256:aaaa", [VULN_CRITICAL, VULN_HIGH])

    response = client.get("/images/vulnerabilities/history?name=nginx:latest")
    assert response.status_code == 200
    data = response.json()
    assert len(data["history"]) == 1
    assert data["history"][0]["total"] == 2


def test_get_history_multiple_scans_chronological_order(api_client):
    client, test_db, _ = api_client
    t1 = datetime.now(timezone.utc) - timedelta(days=1)
    t2 = datetime.now(timezone.utc)
    seed_scan(test_db, "nginx:latest", "sha256:aaaa", [VULN_CRITICAL, VULN_HIGH, VULN_MEDIUM], scanned_at=t1)
    seed_scan(test_db, "nginx:latest", "sha256:bbbb", [VULN_CRITICAL, VULN_HIGH], scanned_at=t2)

    response = client.get("/images/vulnerabilities/history?name=nginx:latest")
    data = response.json()
    assert len(data["history"]) == 2
    assert data["history"][0]["total"] == 3
    assert data["history"][1]["total"] == 2
    assert data["history"][0]["image_digest"] == "sha256:aaaa"
    assert data["history"][1]["image_digest"] == "sha256:bbbb"


def test_get_history_not_found(api_client):
    client, test_db, _ = api_client
    response = client.get("/images/vulnerabilities/history?name=unknown:image")
    assert response.status_code == 404

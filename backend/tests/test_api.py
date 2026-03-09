from datetime import datetime, timedelta, timezone


from backend.tests.conftest import (
    VULN_CRITICAL,
    VULN_CRITICAL_2,
    VULN_HIGH,
    VULN_MEDIUM,
    seed_scan,
)


def _make_running_container(container_name: str, image_name: str, image_id: str) -> dict:
    return {
        "container_name": container_name,
        "image_name": image_name,
        "grype_ref": image_name,
        "hash": image_id.replace("sha256:", "")[:12],
        "image_id": image_id,
    }


# ---------------------------------------------------------------------------
# GET /images/vulnerabilities
# ---------------------------------------------------------------------------

def test_get_vulnerabilities_returns_all(api_client):
    client, test_db, _ = api_client
    seed_scan(test_db, "nginx:latest", "sha256:aaaa", [VULN_CRITICAL, VULN_HIGH, VULN_MEDIUM])

    response = client.get("/images/vulnerabilities?image_ref=nginx:latest")
    assert response.status_code == 200
    data = response.json()
    assert data["count"] == 3
    assert len(data["vulnerabilities"]) == 3


def test_get_vulnerabilities_by_digest(api_client):
    client, test_db, _ = api_client
    seed_scan(test_db, "nginx:latest", "sha256:aaaa000000000000", [VULN_CRITICAL, VULN_HIGH])

    response = client.get("/images/vulnerabilities?image_ref=sha256:aaaa000000000000")
    assert response.status_code == 200
    assert response.json()["count"] == 2


def test_get_vulnerabilities_not_found(api_client):
    client, test_db, _ = api_client
    response = client.get("/images/vulnerabilities?image_ref=unknown:image")
    assert response.status_code == 404


def test_get_vulnerabilities_returns_latest_scan_only(api_client):
    client, test_db, _ = api_client
    t1 = datetime.now(timezone.utc) - timedelta(hours=1)
    t2 = datetime.now(timezone.utc)
    # older scan: 3 vulns
    seed_scan(test_db, "nginx:latest", "sha256:aaaa", [VULN_CRITICAL, VULN_HIGH, VULN_MEDIUM], scanned_at=t1)
    # newer scan: 1 vuln
    seed_scan(test_db, "nginx:latest", "sha256:bbbb", [VULN_CRITICAL], scanned_at=t2)

    response = client.get("/images/vulnerabilities?image_ref=nginx:latest")
    assert response.json()["count"] == 1


# ---------------------------------------------------------------------------
# GET /images/vulnerabilities/critical
# ---------------------------------------------------------------------------

def test_get_critical_vulnerabilities_returns_only_critical(api_client):
    client, test_db, _ = api_client
    seed_scan(test_db, "nginx:latest", "sha256:aaaa", [VULN_CRITICAL, VULN_HIGH, VULN_MEDIUM])

    response = client.get("/images/vulnerabilities/critical?image_ref=nginx:latest")
    assert response.status_code == 200
    data = response.json()
    assert data["count"] == 1
    assert data["vulnerabilities"][0]["severity"] == "Critical"


def test_get_critical_vulnerabilities_not_found(api_client):
    client, test_db, _ = api_client
    response = client.get("/images/vulnerabilities/critical?image_ref=unknown:image")
    assert response.status_code == 404


# ---------------------------------------------------------------------------
# GET /vulnerabilities/critical/running
# ---------------------------------------------------------------------------

def test_get_critical_running_with_running_containers(api_client):
    client, test_db, (mock_cw, mock_vw) = api_client
    seed_scan(test_db, "redis:7", "sha256:cccc", [VULN_CRITICAL_2, VULN_CRITICAL_2])
    mock_vw.return_value.list_running_containers.return_value = [
        _make_running_container("my-redis", "redis:7", "sha256:cccc"),
    ]

    response = client.get("/vulnerabilities/critical/running")
    assert response.status_code == 200
    data = response.json()
    assert data["count"] == 2
    assert "redis:7" in data["running_images"]


def test_get_critical_running_no_running_containers(api_client):
    client, test_db, (mock_cw, mock_vw) = api_client
    seed_scan(test_db, "nginx:latest", "sha256:aaaa", [VULN_CRITICAL])
    mock_vw.return_value.list_running_containers.return_value = []

    response = client.get("/vulnerabilities/critical/running")
    data = response.json()
    assert data["count"] == 0
    assert data["running_images"] == []


def test_get_critical_running_no_scan_for_running_image(api_client):
    client, test_db, (mock_cw, mock_vw) = api_client
    # running container exists in Docker but has no scan in DB
    mock_vw.return_value.list_running_containers.return_value = [
        _make_running_container("my-alpine", "alpine:latest", "sha256:dddd"),
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

def test_get_history_by_image_ref(api_client):
    client, test_db, _ = api_client
    seed_scan(test_db, "nginx:latest", "sha256:aaaa", [VULN_CRITICAL, VULN_HIGH])

    response = client.get("/images/vulnerabilities/history?image=nginx:latest")
    assert response.status_code == 200
    data = response.json()
    assert len(data["history"]) == 1
    assert data["history"][0]["total"] == 2
    assert data["history"][0]["image_ref"] == "nginx:latest"


def test_get_history_by_image_repository_returns_all_tags(api_client):
    client, test_db, _ = api_client
    t1 = datetime.now(timezone.utc) - timedelta(days=2)
    t2 = datetime.now(timezone.utc) - timedelta(days=1)
    t3 = datetime.now(timezone.utc)
    seed_scan(test_db, "nginx:latest", "sha256:aaaa", [VULN_CRITICAL, VULN_HIGH, VULN_MEDIUM], scanned_at=t1)
    seed_scan(test_db, "nginx:1.25", "sha256:bbbb", [VULN_HIGH], scanned_at=t2)
    seed_scan(test_db, "nginx:latest", "sha256:cccc", [VULN_CRITICAL], scanned_at=t3)

    response = client.get("/images/vulnerabilities/history?image=nginx")
    assert response.status_code == 200
    data = response.json()
    assert data["image"] == "nginx"
    assert len(data["history"]) == 3
    # each entry includes image_ref so callers can distinguish tags
    refs = [e["image_ref"] for e in data["history"]]
    assert "nginx:latest" in refs
    assert "nginx:1.25" in refs


def test_get_history_by_digest(api_client):
    client, test_db, _ = api_client
    seed_scan(test_db, "nginx:latest", "sha256:aaaa111", [VULN_CRITICAL])

    response = client.get("/images/vulnerabilities/history?image=sha256:aaaa111")
    assert response.status_code == 200
    data = response.json()
    assert len(data["history"]) == 1
    assert data["history"][0]["image_digest"] == "sha256:aaaa111"


def test_get_history_multiple_scans_chronological_order(api_client):
    client, test_db, _ = api_client
    t1 = datetime.now(timezone.utc) - timedelta(days=1)
    t2 = datetime.now(timezone.utc)
    seed_scan(test_db, "nginx:latest", "sha256:aaaa", [VULN_CRITICAL, VULN_HIGH, VULN_MEDIUM], scanned_at=t1)
    seed_scan(test_db, "nginx:latest", "sha256:bbbb", [VULN_CRITICAL, VULN_HIGH], scanned_at=t2)

    response = client.get("/images/vulnerabilities/history?image=nginx:latest")
    data = response.json()
    assert len(data["history"]) == 2
    assert data["history"][0]["total"] == 3
    assert data["history"][1]["total"] == 2
    assert data["history"][0]["image_digest"] == "sha256:aaaa"
    assert data["history"][1]["image_digest"] == "sha256:bbbb"


def test_get_history_not_found(api_client):
    client, test_db, _ = api_client
    response = client.get("/images/vulnerabilities/history?image=unknown:image")
    assert response.status_code == 404


# ---------------------------------------------------------------------------
# GET /containers/running
# ---------------------------------------------------------------------------

def test_get_running_containers_no_running(api_client):
    client, test_db, (mock_cw, mock_vw) = api_client
    seed_scan(test_db, "nginx:latest", "sha256:aaaa", [VULN_CRITICAL, VULN_HIGH])
    mock_cw.return_value.list_running_containers.return_value = []

    response = client.get("/containers/running")
    assert response.status_code == 200
    assert response.json()["containers"] == []


def test_get_running_containers_with_scan(api_client):
    client, test_db, (mock_cw, mock_vw) = api_client
    seed_scan(test_db, "nginx:latest", "sha256:aaaa", [VULN_CRITICAL, VULN_HIGH, VULN_MEDIUM])
    mock_cw.return_value.list_running_containers.return_value = [
        _make_running_container("my-nginx", "nginx:latest", "sha256:aaaa"),
    ]

    response = client.get("/containers/running")
    assert response.status_code == 200
    data = response.json()
    assert len(data["containers"]) == 1
    c = data["containers"][0]
    assert c["container_name"] == "my-nginx"
    assert c["image_name"] == "nginx:latest"
    assert c["has_scan"] is True
    assert c["total"] == 3
    assert c["vulns_by_severity"]["Critical"] == 1
    assert c["vulns_by_severity"]["High"] == 1
    assert c["vulns_by_severity"]["Medium"] == 1
    assert c["scanned_at"] is not None


def test_get_running_containers_no_scan_for_image(api_client):
    client, test_db, (mock_cw, mock_vw) = api_client
    mock_cw.return_value.list_running_containers.return_value = [
        _make_running_container("my-alpine", "alpine:latest", "sha256:dddd"),
    ]

    response = client.get("/containers/running")
    assert response.status_code == 200
    data = response.json()
    assert len(data["containers"]) == 1
    c = data["containers"][0]
    assert c["container_name"] == "my-alpine"
    assert c["image_name"] == "alpine:latest"
    assert c["has_scan"] is False
    assert c["total"] == 0
    assert c["vulns_by_severity"] == {}
    assert c["scanned_at"] is None


def test_get_running_containers_multiple_mixed(api_client):
    client, test_db, (mock_cw, mock_vw) = api_client
    seed_scan(test_db, "nginx:latest", "sha256:aaaa", [VULN_CRITICAL, VULN_HIGH])
    seed_scan(test_db, "redis:7", "sha256:cccc", [VULN_CRITICAL_2, VULN_CRITICAL])
    mock_cw.return_value.list_running_containers.return_value = [
        _make_running_container("my-nginx", "nginx:latest", "sha256:aaaa"),
        _make_running_container("my-redis", "redis:7", "sha256:cccc"),
        _make_running_container("my-alpine", "alpine:latest", "sha256:dddd"),
    ]

    response = client.get("/containers/running")
    assert response.status_code == 200
    data = response.json()
    assert len(data["containers"]) == 3

    by_name = {c["container_name"]: c for c in data["containers"]}
    assert by_name["my-nginx"]["has_scan"] is True
    assert by_name["my-nginx"]["total"] == 2
    assert by_name["my-redis"]["has_scan"] is True
    assert by_name["my-redis"]["vulns_by_severity"]["Critical"] == 2
    assert by_name["my-alpine"]["has_scan"] is False


def test_get_running_containers_uses_latest_scan(api_client):
    client, test_db, (mock_cw, mock_vw) = api_client
    t1 = datetime.now(timezone.utc) - timedelta(hours=1)
    t2 = datetime.now(timezone.utc)
    seed_scan(test_db, "nginx:latest", "sha256:aaaa", [VULN_CRITICAL, VULN_HIGH, VULN_MEDIUM], scanned_at=t1)
    seed_scan(test_db, "nginx:latest", "sha256:bbbb", [VULN_CRITICAL], scanned_at=t2)
    mock_cw.return_value.list_running_containers.return_value = [
        _make_running_container("my-nginx", "nginx:latest", "sha256:bbbb"),
    ]

    response = client.get("/containers/running")
    data = response.json()
    c = data["containers"][0]
    assert c["total"] == 1
    assert c["image_digest"] == "sha256:bbbb"
# ---------------------------------------------------------------------------
# GET /vulnerabilities
# ---------------------------------------------------------------------------

def test_get_vulnerabilities_across_running_returns_total_instances_and_unique_count(api_client):
    client, test_db, (mock_cw, mock_vw) = api_client
    
    # Same CVE (VULN_CRITICAL) mapped to two different images.
    seed_scan(test_db, "nginx:latest", "sha256:aaaa", [VULN_CRITICAL])
    seed_scan(test_db, "redis:7", "sha256:cccc", [VULN_CRITICAL])
    
    # 3 total instances of the same CVE across 2 images.
    mock_vw.return_value.list_running_containers.return_value = [
        _make_running_container("my-nginx-1", "nginx:latest", "sha256:aaaa"),
        _make_running_container("my-nginx-2", "nginx:latest", "sha256:aaaa"),
        _make_running_container("my-redis", "redis:7", "sha256:cccc"),
    ]

    response = client.get("/vulnerabilities?report=all")
    assert response.status_code == 200
    data = response.json()
    
    # There is only 1 unique vulnerability (grouped by CVE)
    assert data["total_count"] == 1
    assert data["count"] == 1
    
    # But there are 3 raw occurrences/instances of this vulnerability
    assert data["total_instances"] == 3

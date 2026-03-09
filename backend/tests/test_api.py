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


# ---------------------------------------------------------------------------
# GET /images/vulnerabilities — sort validation and sort columns
# ---------------------------------------------------------------------------

def test_get_vulnerabilities_invalid_sort_by_returns_422(api_client):
    client, test_db, _ = api_client
    seed_scan(test_db, "nginx:latest", "sha256:aaaa", [VULN_CRITICAL])
    response = client.get("/images/vulnerabilities?image_ref=nginx:latest&sort_by=invalid_col")
    assert response.status_code == 422


def test_get_vulnerabilities_sort_by_cvss(api_client):
    client, test_db, _ = api_client
    seed_scan(test_db, "nginx:latest", "sha256:aaaa", [VULN_CRITICAL, VULN_HIGH, VULN_MEDIUM])
    response = client.get("/images/vulnerabilities?image_ref=nginx:latest&sort_by=cvss_base_score")
    assert response.status_code == 200
    vulns = response.json()["vulnerabilities"]
    scores = [v["cvss_base_score"] for v in vulns if v["cvss_base_score"] is not None]
    assert scores == sorted(scores, reverse=True)


def test_get_vulnerabilities_sort_by_epss(api_client):
    client, test_db, _ = api_client
    seed_scan(test_db, "nginx:latest", "sha256:aaaa", [VULN_CRITICAL, VULN_HIGH, VULN_MEDIUM])
    response = client.get("/images/vulnerabilities?image_ref=nginx:latest&sort_by=epss_score")
    assert response.status_code == 200


def test_get_vulnerabilities_sort_by_is_kev(api_client):
    client, test_db, _ = api_client
    seed_scan(test_db, "nginx:latest", "sha256:aaaa", [VULN_CRITICAL, VULN_HIGH])
    response = client.get("/images/vulnerabilities?image_ref=nginx:latest&sort_by=is_kev")
    assert response.status_code == 200
    vulns = response.json()["vulnerabilities"]
    # The endpoint treats is_kev=True as rank 0 (highest priority), so True sorts first on asc
    kev_flags = [v["is_kev"] for v in vulns]
    assert kev_flags[0] is True


def test_get_vulnerabilities_sort_by_vuln_id(api_client):
    client, test_db, _ = api_client
    seed_scan(test_db, "nginx:latest", "sha256:aaaa", [VULN_CRITICAL, VULN_HIGH, VULN_MEDIUM])
    response = client.get("/images/vulnerabilities?image_ref=nginx:latest&sort_by=vuln_id")
    assert response.status_code == 200
    ids = [v["vuln_id"] for v in response.json()["vulnerabilities"]]
    assert ids == sorted(ids)


def test_get_vulnerabilities_sort_by_package_name(api_client):
    client, test_db, _ = api_client
    seed_scan(test_db, "nginx:latest", "sha256:aaaa", [VULN_CRITICAL, VULN_HIGH, VULN_MEDIUM])
    response = client.get("/images/vulnerabilities?image_ref=nginx:latest&sort_by=package_name")
    assert response.status_code == 200


def test_get_vulnerabilities_sort_by_first_seen_at(api_client):
    client, test_db, _ = api_client
    seed_scan(test_db, "nginx:latest", "sha256:aaaa", [VULN_CRITICAL, VULN_HIGH])
    response = client.get("/images/vulnerabilities?image_ref=nginx:latest&sort_by=first_seen_at")
    assert response.status_code == 200


def test_get_vulnerabilities_sort_desc(api_client):
    client, test_db, _ = api_client
    seed_scan(test_db, "nginx:latest", "sha256:aaaa", [VULN_CRITICAL, VULN_HIGH, VULN_MEDIUM])
    response = client.get("/images/vulnerabilities?image_ref=nginx:latest&sort_by=vuln_id&sort_dir=desc")
    assert response.status_code == 200
    ids = [v["vuln_id"] for v in response.json()["vulnerabilities"]]
    assert ids == sorted(ids, reverse=True)


def test_get_vulnerabilities_pagination(api_client):
    client, test_db, _ = api_client
    seed_scan(test_db, "nginx:latest", "sha256:aaaa", [VULN_CRITICAL, VULN_HIGH, VULN_MEDIUM])
    response = client.get("/images/vulnerabilities?image_ref=nginx:latest&limit=2&offset=0")
    data = response.json()
    assert data["count"] == 2
    assert data["has_more"] is True

    response2 = client.get("/images/vulnerabilities?image_ref=nginx:latest&limit=2&offset=2")
    data2 = response2.json()
    assert data2["count"] == 1
    assert data2["has_more"] is False


def test_get_vulnerabilities_grouped_same_cve_different_packages(api_client):
    """Same CVE affecting two different packages should produce one grouped entry with two packages."""
    client, test_db, _ = api_client
    same_cve_pkg2 = dict(
        vuln_id="CVE-2024-0001",  # same CVE as VULN_CRITICAL
        severity="High",
        package_name="openssl",
        installed_version="3.0.0",
        cvss_base_score=9.9,
        is_kev=False,
        epss_score=0.50,
        epss_percentile=0.80,
        risk_score=7.0,
        fix_state="fixed",
        fixed_version="3.0.1",
    )
    seed_scan(test_db, "nginx:latest", "sha256:aaaa", [VULN_CRITICAL, same_cve_pkg2])

    response = client.get("/images/vulnerabilities?image_ref=nginx:latest")
    data = response.json()
    # Two rows in DB but they share a vuln_id — should be grouped into 1
    assert data["count"] == 1
    grouped = data["vulnerabilities"][0]
    assert len(grouped["packages"]) == 2
    pkg_names = {p["package_name"] for p in grouped["packages"]}
    assert pkg_names == {"libssl", "openssl"}
    # Should take the highest severity
    assert grouped["severity"] == "Critical"


# ---------------------------------------------------------------------------
# GET /vulnerabilities — sort validation and report filters
# ---------------------------------------------------------------------------

def test_get_vulnerabilities_across_running_invalid_sort_by(api_client):
    client, _, (_, mock_vw) = api_client
    mock_vw.return_value.list_running_containers.return_value = []
    response = client.get("/vulnerabilities?sort_by=bad_col")
    assert response.status_code == 422


def test_get_vulnerabilities_across_running_report_critical(api_client):
    client, test_db, (_, mock_vw) = api_client
    seed_scan(test_db, "nginx:latest", "sha256:aaaa", [VULN_CRITICAL, VULN_HIGH])
    mock_vw.return_value.list_running_containers.return_value = [
        _make_running_container("my-nginx", "nginx:latest", "sha256:aaaa"),
    ]

    data = client.get("/vulnerabilities?report=critical").json()
    assert data["total_count"] == 1
    assert data["vulnerabilities"][0]["severity"] == "Critical"


def test_get_vulnerabilities_across_running_report_kev(api_client):
    client, test_db, (_, mock_vw) = api_client
    seed_scan(test_db, "nginx:latest", "sha256:aaaa", [VULN_CRITICAL, VULN_HIGH])
    mock_vw.return_value.list_running_containers.return_value = [
        _make_running_container("my-nginx", "nginx:latest", "sha256:aaaa"),
    ]

    data = client.get("/vulnerabilities?report=kev").json()
    assert data["total_count"] == 1
    assert data["vulnerabilities"][0]["is_kev"] is True


def test_get_vulnerabilities_across_running_report_new(api_client):
    from datetime import datetime, timezone
    from sqlmodel import Session, select
    from backend.models import Vulnerability as V

    client, test_db, (_, mock_vw) = api_client
    scan = seed_scan(test_db, "nginx:latest", "sha256:aaaa", [VULN_CRITICAL, VULN_HIGH])

    # Set first_seen_at on our seeded vulns so they appear in the "new" filter
    with Session(test_db.engine) as session:
        vulns = session.exec(select(V).where(V.scan_id == scan.id)).all()
        for v in vulns:
            v.first_seen_at = datetime.now(timezone.utc)
        session.commit()

    mock_vw.return_value.list_running_containers.return_value = [
        _make_running_container("my-nginx", "nginx:latest", "sha256:aaaa"),
    ]

    data = client.get("/vulnerabilities?report=new&new_hours=24").json()
    assert data["total_count"] >= 1


def test_get_vulnerabilities_across_running_report_vex_annotated(api_client):
    from sqlmodel import Session, select
    from backend.models import Vulnerability as V

    client, test_db, (_, mock_vw) = api_client
    scan = seed_scan(test_db, "nginx:latest", "sha256:aaaa", [VULN_CRITICAL, VULN_HIGH])

    with Session(test_db.engine) as session:
        vuln = session.exec(select(V).where(V.scan_id == scan.id).limit(1)).first()
        if vuln:
            vuln.vex_status = "not_affected"
            session.add(vuln)
            session.commit()

    mock_vw.return_value.list_running_containers.return_value = [
        _make_running_container("my-nginx", "nginx:latest", "sha256:aaaa"),
    ]

    data = client.get("/vulnerabilities?report=vex_annotated").json()
    assert data["total_count"] == 1
    assert data["vulnerabilities"][0]["vex_status"] == "not_affected"


def test_get_vulnerabilities_across_running_sort_columns(api_client):
    client, test_db, (_, mock_vw) = api_client
    seed_scan(test_db, "nginx:latest", "sha256:aaaa", [VULN_CRITICAL, VULN_HIGH, VULN_MEDIUM])
    mock_vw.return_value.list_running_containers.return_value = [
        _make_running_container("my-nginx", "nginx:latest", "sha256:aaaa"),
    ]

    for col in ["cvss_base_score", "epss_score", "is_kev", "first_seen_at", "vuln_id", "package_name"]:
        r = client.get(f"/vulnerabilities?report=all&sort_by={col}")
        assert r.status_code == 200, f"sort_by={col} failed"
        r_desc = client.get(f"/vulnerabilities?report=all&sort_by={col}&sort_dir=desc")
        assert r_desc.status_code == 200, f"sort_by={col} desc failed"


def test_get_vulnerabilities_across_running_description_truncated(api_client):
    from sqlmodel import Session, select
    from backend.models import Vulnerability as V

    client, test_db, (_, mock_vw) = api_client
    scan = seed_scan(test_db, "nginx:latest", "sha256:aaaa", [VULN_CRITICAL])

    long_desc = "x" * 2000
    with Session(test_db.engine) as session:
        vuln = session.exec(select(V).where(V.scan_id == scan.id).limit(1)).first()
        if vuln:
            vuln.description = long_desc
            session.add(vuln)
            session.commit()

    mock_vw.return_value.list_running_containers.return_value = [
        _make_running_container("my-nginx", "nginx:latest", "sha256:aaaa"),
    ]

    data = client.get("/vulnerabilities?report=all").json()
    desc = data["vulnerabilities"][0]["description"]
    assert len(desc) <= 1001  # _DESC_LIMIT + "…"
    assert desc.endswith("…")


def test_get_vulnerabilities_across_running_eol_images(api_client):
    from datetime import datetime, timezone
    from sqlmodel import Session
    from backend.models import Scan
    from backend.grype_scanner import _parse_image_repository

    client, test_db, (_, mock_vw) = api_client
    with Session(test_db.engine) as session:
        session.add(Scan(
            scanned_at=datetime.now(timezone.utc),
            image_name="nginx:latest",
            image_repository=_parse_image_repository("nginx:latest"),
            image_digest="sha256:aaaa",
            grype_version="0.85.0",
            is_distro_eol=True,
            distro_name="debian",
            distro_version="10",
        ))
        session.commit()

    mock_vw.return_value.list_running_containers.return_value = [
        _make_running_container("my-nginx", "nginx:latest", "sha256:aaaa"),
    ]

    data = client.get("/vulnerabilities?report=all").json()
    assert len(data["eol_images"]) == 1
    assert data["eol_images"][0]["container_name"] == "my-nginx"


def test_get_vulnerabilities_across_running_no_scans_for_running_images(api_client):
    client, _, (_, mock_vw) = api_client
    mock_vw.return_value.list_running_containers.return_value = [
        _make_running_container("my-alpine", "alpine:latest", "sha256:dddd"),
    ]

    data = client.get("/vulnerabilities?report=all").json()
    assert data["total_count"] == 0

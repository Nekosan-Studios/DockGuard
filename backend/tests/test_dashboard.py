from datetime import UTC, datetime, timedelta

from sqlmodel import Session

from backend.models import AppState, SystemTask
from backend.tests.conftest import VULN_CRITICAL, VULN_HIGH, VULN_MEDIUM, seed_scan


def _make_running_container(container_name, image_name, image_id):
    return {
        "container_name": container_name,
        "image_name": image_name,
        "grype_ref": image_name,
        "hash": image_id.replace("sha256:", "")[:12],
        "config_digest": image_id,
    }


# ---------------------------------------------------------------------------
# GET /dashboard/summary
# ---------------------------------------------------------------------------


def test_dashboard_summary_empty_db(api_client):
    client, _, (mock_cw, _) = api_client
    mock_cw.return_value.list_running_containers.return_value = []

    response = client.get("/dashboard/summary")
    assert response.status_code == 200
    data = response.json()
    assert data["running_containers"] == 0
    assert data["images_scanned"] == 0
    assert data["critical_count"] == 0
    assert data["kev_count"] == 0
    assert data["trend"] == []


def test_dashboard_summary_with_running_containers_and_scan(api_client):
    client, test_db, (mock_cw, _) = api_client
    seed_scan(test_db, "nginx:latest", "sha256:aaaa", [VULN_CRITICAL, VULN_HIGH, VULN_MEDIUM])
    mock_cw.return_value.list_running_containers.return_value = [
        _make_running_container("my-nginx", "nginx:latest", "sha256:aaaa"),
    ]

    response = client.get("/dashboard/summary")
    assert response.status_code == 200
    data = response.json()
    assert data["running_containers"] == 1
    assert data["images_scanned"] == 1
    assert data["critical_count"] == 1


def test_dashboard_summary_kev_count(api_client):
    client, test_db, (mock_cw, _) = api_client
    seed_scan(test_db, "nginx:latest", "sha256:aaaa", [VULN_CRITICAL])  # VULN_CRITICAL has is_kev=True
    mock_cw.return_value.list_running_containers.return_value = [
        _make_running_container("my-nginx", "nginx:latest", "sha256:aaaa"),
    ]

    data = client.get("/dashboard/summary").json()
    assert data["kev_count"] == 1


def test_dashboard_summary_trend_includes_recent_scans(api_client):
    client, test_db, (mock_cw, _) = api_client
    seed_scan(
        test_db,
        "nginx:latest",
        "sha256:aaaa",
        [VULN_CRITICAL],
        scanned_at=datetime.now(UTC) - timedelta(days=1),
    )
    mock_cw.return_value.list_running_containers.return_value = []

    data = client.get("/dashboard/summary").json()
    assert len(data["trend"]) >= 1
    assert data["trend"][0]["urgent"] == 1
    assert "kev" in data["trend"][0]


def test_dashboard_summary_trend_current_day_adjustment(api_client):
    client, test_db, (mock_cw, _) = api_client
    yesterday = datetime.now(UTC) - timedelta(days=1)
    # Seed a scan from yesterday for the running container
    seed_scan(
        test_db,
        "nginx:latest",
        "sha256:aaaa",
        [VULN_CRITICAL],
        scanned_at=yesterday,
    )
    # It is currently running, so its critical_count will be calculated for "today"
    mock_cw.return_value.list_running_containers.return_value = [
        _make_running_container("my-nginx", "nginx:latest", "sha256:aaaa"),
    ]

    data = client.get("/dashboard/summary").json()

    # Trend should have two entries: yesterday's actual scan, and today's carried-forward state
    assert len(data["trend"]) == 2

    yesterday_iso = yesterday.date().isoformat()
    today_iso = datetime.now(UTC).date().isoformat()

    dates = [t["date"] for t in data["trend"]]
    assert yesterday_iso in dates
    assert today_iso in dates

    # Both should have 1 urgent vulnerability
    assert data["trend"][0]["urgent"] == 1
    assert data["trend"][1]["urgent"] == 1


def test_dashboard_summary_docker_disconnected(api_client):
    client, _, (mock_cw, _) = api_client
    mock_cw.return_value.list_running_containers.side_effect = Exception("Docker not available")

    response = client.get("/dashboard/summary")
    assert response.status_code == 200
    data = response.json()
    assert data["docker_connected"] is False
    assert data["running_containers"] == 0


def test_dashboard_summary_grype_info_from_app_state(api_client):
    client, test_db, (mock_cw, _) = api_client
    with Session(test_db.engine) as session:
        session.add(AppState(id=1, grype_version="0.85.0"))
        session.commit()
    mock_cw.return_value.list_running_containers.return_value = []

    data = client.get("/dashboard/summary").json()
    assert data["grype_version"] == "0.85.0"


def test_dashboard_summary_grype_info_fallback_to_latest_scan(api_client):
    client, test_db, (mock_cw, _) = api_client
    seed_scan(test_db, "nginx:latest", "sha256:aaaa", [])
    mock_cw.return_value.list_running_containers.return_value = []

    data = client.get("/dashboard/summary").json()
    assert data["grype_version"] == "0.85.0"  # grype_version in seed_scan fixture


def test_dashboard_summary_active_and_queued_tasks(api_client):
    client, test_db, (mock_cw, _) = api_client
    with Session(test_db.engine) as session:
        session.add(SystemTask(task_type="scan", task_name="Scan A", status="running", created_at=datetime.now(UTC)))
        session.add(SystemTask(task_type="scan", task_name="Scan B", status="queued", created_at=datetime.now(UTC)))
        session.commit()
    mock_cw.return_value.list_running_containers.return_value = []

    data = client.get("/dashboard/summary").json()
    # Scheduler may also add tasks during the lifespan; check >= 1
    assert data["active_tasks"] >= 1
    assert data["queued_tasks"] >= 1


def test_dashboard_summary_eol_count(api_client):
    client, test_db, (mock_cw, _) = api_client
    from backend.grype_scanner import _parse_image_repository
    from backend.models import Scan

    with Session(test_db.engine) as session:
        session.add(
            Scan(
                scanned_at=datetime.now(UTC),
                image_name="nginx:latest",
                image_repository=_parse_image_repository("nginx:latest"),
                image_digest="sha256:aaaa",
                grype_version="0.85.0",
                is_distro_eol=True,
            )
        )
        session.commit()
    mock_cw.return_value.list_running_containers.return_value = [
        _make_running_container("my-nginx", "nginx:latest", "sha256:aaaa"),
    ]

    data = client.get("/dashboard/summary").json()
    assert data["eol_count"] == 1


def test_dashboard_summary_new_findings_uses_last_scan_delta(api_client):
    client, test_db, (mock_cw, _) = api_client
    seed_scan(
        test_db,
        "nginx:latest",
        "sha256:aaaa",
        [VULN_CRITICAL],
        scanned_at=datetime(2026, 1, 1, tzinfo=UTC),
    )
    seed_scan(
        test_db,
        "nginx:latest",
        "sha256:bbbb",
        [VULN_CRITICAL, VULN_HIGH],
        scanned_at=datetime(2026, 1, 2, tzinfo=UTC),
    )
    mock_cw.return_value.list_running_containers.return_value = [
        _make_running_container("my-nginx", "nginx:latest", "sha256:bbbb"),
    ]

    data = client.get("/dashboard/summary").json()
    assert data["new_findings"] == 1


# ---------------------------------------------------------------------------
# GET /activity/recent
# ---------------------------------------------------------------------------


def test_get_recent_activity_empty(api_client):
    client, _, _ = api_client
    response = client.get("/activity/recent")
    assert response.status_code == 200
    assert response.json()["activities"] == []


def test_get_recent_activity_returns_scans(api_client):
    client, test_db, _ = api_client
    seed_scan(test_db, "nginx:latest", "sha256:aaaa", [VULN_CRITICAL, VULN_HIGH])
    seed_scan(test_db, "redis:7", "sha256:cccc", [VULN_CRITICAL])

    response = client.get("/activity/recent")
    assert response.status_code == 200
    data = response.json()
    assert len(data["activities"]) == 2
    totals = {a["image_name"]: a["total"] for a in data["activities"]}
    assert totals["nginx:latest"] == 2
    assert totals["redis:7"] == 1


def test_get_recent_activity_respects_limit(api_client):
    client, test_db, _ = api_client
    for i in range(10):
        seed_scan(test_db, f"image{i}:latest", f"sha256:{'a' * 4}{i}", [])

    response = client.get("/activity/recent?page_size=3")
    assert response.status_code == 200
    assert len(response.json()["activities"]) == 3


def test_get_recent_activity_ordered_most_recent_first(api_client):
    client, test_db, _ = api_client
    t1 = datetime.now(UTC) - timedelta(hours=2)
    t2 = datetime.now(UTC) - timedelta(hours=1)
    seed_scan(test_db, "nginx:latest", "sha256:aaaa", [], scanned_at=t1)
    seed_scan(test_db, "redis:7", "sha256:cccc", [], scanned_at=t2)

    activities = client.get("/activity/recent").json()["activities"]
    assert activities[0]["image_name"] == "redis:7"
    assert activities[1]["image_name"] == "nginx:latest"


def test_get_recent_activity_includes_severity_breakdown(api_client):
    client, test_db, _ = api_client
    seed_scan(test_db, "nginx:latest", "sha256:aaaa", [VULN_CRITICAL, VULN_HIGH, VULN_MEDIUM])

    activities = client.get("/activity/recent?limit=50").json()["activities"]
    # The scheduler may add other scans concurrently; find ours by name
    activity = next(a for a in activities if a["image_name"] == "nginx:latest" and a["image_digest"] == "sha256:aaaa")
    assert activity["vulns_by_severity"]["Critical"] == 1
    assert activity["vulns_by_severity"]["High"] == 1
    assert activity["vulns_by_severity"]["Medium"] == 1


def test_get_recent_activity_includes_scan_time_containers(api_client):
    client, test_db, _ = api_client
    seed_scan(
        test_db,
        "nginx:latest",
        "sha256:aaaa",
        [VULN_CRITICAL],
        container_names=["web-1", "web-2"],
    )

    activities = client.get("/activity/recent").json()["activities"]
    activity = next(a for a in activities if a["image_name"] == "nginx:latest")
    assert activity["affected_container_count_at_scan"] == 2
    assert set(activity["affected_containers_at_scan"]) == {"web-1", "web-2"}

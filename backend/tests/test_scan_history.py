"""Tests for GET /containers/{container_name}/scan-history."""

from datetime import UTC, datetime, timedelta

from backend.tests.conftest import (
    VULN_CRITICAL,
    VULN_HIGH,
    VULN_MEDIUM,
    seed_scan,
)


class TestScanHistoryNotFound:
    def test_unknown_container_returns_404(self, api_client):
        client, _test_db, _ = api_client
        response = client.get("/containers/no-such-container/scan-history")
        assert response.status_code == 404

    def test_container_with_no_scans_returns_404(self, api_client):
        client, test_db, _ = api_client
        # Seed a scan without a container_name link — history should be 404
        seed_scan(test_db, "nginx:latest", "sha256:aaaa", [VULN_CRITICAL])
        response = client.get("/containers/my-nginx/scan-history")
        assert response.status_code == 404


class TestScanHistoryBaseline:
    def test_single_scan_is_baseline(self, api_client):
        client, test_db, _ = api_client
        seed_scan(
            test_db,
            "nginx:latest",
            "sha256:aaaa",
            [VULN_CRITICAL, VULN_HIGH],
            container_names=["my-nginx"],
        )

        response = client.get("/containers/my-nginx/scan-history")
        assert response.status_code == 200
        data = response.json()

        assert data["container_name"] == "my-nginx"
        assert data["total_scans"] == 1
        assert data["has_more"] is False
        assert len(data["entries"]) == 1

        entry = data["entries"][0]
        assert entry["is_baseline"] is True
        assert entry["total"] == 2
        assert entry["added"] == []
        assert entry["removed"] == []
        assert entry["vulns_by_priority"] is not None
        # VULN_CRITICAL has risk_score=95 → Urgent; VULN_HIGH has risk_score=68 → High
        assert entry["vulns_by_priority"].get("Urgent") == 1
        assert entry["vulns_by_priority"].get("High") == 1


class TestScanHistoryDiff:
    def test_two_scans_produce_diff(self, api_client):
        client, test_db, _ = api_client
        t1 = datetime.now(UTC) - timedelta(hours=2)
        t2 = datetime.now(UTC) - timedelta(hours=1)

        # Baseline: critical + high + medium
        seed_scan(
            test_db,
            "nginx:latest",
            "sha256:aaaa",
            [VULN_CRITICAL, VULN_HIGH, VULN_MEDIUM],
            scanned_at=t1,
            container_names=["my-nginx"],
        )
        # Second scan: medium removed, high remains, critical remains
        seed_scan(
            test_db,
            "nginx:latest",
            "sha256:bbbb",
            [VULN_CRITICAL, VULN_HIGH],
            scanned_at=t2,
            container_names=["my-nginx"],
        )

        response = client.get("/containers/my-nginx/scan-history")
        assert response.status_code == 200
        data = response.json()

        assert data["total_scans"] == 2
        assert data["has_more"] is False
        assert len(data["entries"]) == 2

        # Most recent scan first (descending)
        latest = data["entries"][0]
        baseline = data["entries"][1]

        assert latest["is_baseline"] is False
        assert latest["total"] == 2
        assert latest["added"] == []
        assert len(latest["removed"]) == 1
        assert latest["removed"][0]["vuln_id"] == VULN_MEDIUM["vuln_id"]

        assert baseline["is_baseline"] is True
        assert baseline["total"] == 3

    def test_three_scans_diffs_chain(self, api_client):
        client, test_db, _ = api_client
        t1 = datetime.now(UTC) - timedelta(hours=3)
        t2 = datetime.now(UTC) - timedelta(hours=2)
        t3 = datetime.now(UTC) - timedelta(hours=1)

        # Scan 1 (baseline): critical only
        seed_scan(
            test_db,
            "nginx:latest",
            "sha256:s1",
            [VULN_CRITICAL],
            scanned_at=t1,
            container_names=["my-nginx"],
        )
        # Scan 2: critical + high (high added)
        seed_scan(
            test_db,
            "nginx:latest",
            "sha256:s2",
            [VULN_CRITICAL, VULN_HIGH],
            scanned_at=t2,
            container_names=["my-nginx"],
        )
        # Scan 3: high + medium (critical removed, medium added)
        seed_scan(
            test_db,
            "nginx:latest",
            "sha256:s3",
            [VULN_HIGH, VULN_MEDIUM],
            scanned_at=t3,
            container_names=["my-nginx"],
        )

        response = client.get("/containers/my-nginx/scan-history")
        assert response.status_code == 200
        data = response.json()

        assert data["total_scans"] == 3
        entries = data["entries"]
        assert len(entries) == 3

        # scan3 diff vs scan2
        s3 = entries[0]
        assert s3["is_baseline"] is False
        added_ids = {v["vuln_id"] for v in s3["added"]}
        removed_ids = {v["vuln_id"] for v in s3["removed"]}
        assert added_ids == {VULN_MEDIUM["vuln_id"]}
        assert removed_ids == {VULN_CRITICAL["vuln_id"]}

        # scan2 diff vs scan1
        s2 = entries[1]
        assert s2["is_baseline"] is False
        assert {v["vuln_id"] for v in s2["added"]} == {VULN_HIGH["vuln_id"]}
        assert s2["removed"] == []

        # scan1 is baseline
        s1 = entries[2]
        assert s1["is_baseline"] is True


class TestScanHistoryPagination:
    def test_pagination_offset_and_limit(self, api_client):
        client, test_db, _ = api_client
        base_time = datetime.now(UTC) - timedelta(hours=15)

        for i in range(12):
            seed_scan(
                test_db,
                "nginx:latest",
                f"sha256:p{i:04d}",
                [VULN_CRITICAL],
                scanned_at=base_time + timedelta(hours=i),
                container_names=["my-nginx"],
            )

        # First page
        resp1 = client.get("/containers/my-nginx/scan-history?offset=0&limit=10")
        assert resp1.status_code == 200
        d1 = resp1.json()
        assert d1["total_scans"] == 12
        assert d1["has_more"] is True
        assert len(d1["entries"]) == 10

        # Second page
        resp2 = client.get("/containers/my-nginx/scan-history?offset=10&limit=10")
        assert resp2.status_code == 200
        d2 = resp2.json()
        assert d2["has_more"] is False
        assert len(d2["entries"]) == 2

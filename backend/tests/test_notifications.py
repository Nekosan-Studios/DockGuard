from datetime import UTC, datetime
from unittest.mock import AsyncMock, patch

import pytest
from sqlmodel import Session

from backend.models import NotificationChannel, NotificationLog, Scan, SystemTask
from backend.tests.conftest import VULN_CRITICAL, VULN_HIGH, VULN_MEDIUM, seed_scan


class TestNotificationChannelCRUD:
    def test_list_channels_empty(self, api_client):
        client, _, _ = api_client
        resp = client.get("/notifications/channels")
        assert resp.status_code == 200
        assert resp.json() == []

    def test_create_channel(self, api_client):
        client, _, _ = api_client
        with patch("backend.routers.notifications.notifier.validate_url", return_value=True):
            resp = client.post(
                "/notifications/channels",
                json={
                    "name": "Test Slack",
                    "apprise_url": "slack://token",
                },
            )
        assert resp.status_code == 201
        data = resp.json()
        assert data["name"] == "Test Slack"
        assert data["apprise_url"] == "slack://token"
        assert data["enabled"] is True
        assert data["notify_urgent"] is False
        assert data["notify_all_new"] is False
        assert data["id"] is not None

    def test_create_channel_invalid_url(self, api_client):
        client, _, _ = api_client
        with patch("backend.routers.notifications.notifier.validate_url", return_value=False):
            resp = client.post(
                "/notifications/channels",
                json={"name": "Bad", "apprise_url": "bad://url"},
            )
        assert resp.status_code == 400
        assert "Invalid" in resp.json()["detail"]

    def test_update_channel(self, api_client):
        client, db, _ = api_client
        with Session(db.engine) as session:
            ch = NotificationChannel(
                name="Old",
                apprise_url="slack://old",
                created_at=datetime.now(UTC),
                updated_at=datetime.now(UTC),
            )
            session.add(ch)
            session.commit()
            ch_id = ch.id

        resp = client.patch(f"/notifications/channels/{ch_id}", json={"name": "New Name"})
        assert resp.status_code == 200
        assert resp.json()["name"] == "New Name"

    def test_update_channel_not_found(self, api_client):
        client, _, _ = api_client
        resp = client.patch("/notifications/channels/999", json={"name": "X"})
        assert resp.status_code == 404

    def test_delete_channel(self, api_client):
        client, db, _ = api_client
        with Session(db.engine) as session:
            ch = NotificationChannel(
                name="Delete Me",
                apprise_url="slack://x",
                created_at=datetime.now(UTC),
                updated_at=datetime.now(UTC),
            )
            session.add(ch)
            session.commit()
            ch_id = ch.id

        resp = client.delete(f"/notifications/channels/{ch_id}")
        assert resp.status_code == 200

        resp = client.get("/notifications/channels")
        assert len(resp.json()) == 0

    def test_delete_channel_not_found(self, api_client):
        client, _, _ = api_client
        resp = client.delete("/notifications/channels/999")
        assert resp.status_code == 404

    def test_test_channel_success(self, api_client):
        client, db, _ = api_client
        with Session(db.engine) as session:
            ch = NotificationChannel(
                name="Tester",
                apprise_url="slack://x",
                created_at=datetime.now(UTC),
                updated_at=datetime.now(UTC),
            )
            session.add(ch)
            session.commit()
            ch_id = ch.id

        with patch("backend.routers.notifications.notifier.test", new_callable=AsyncMock, return_value=(True, None)):
            resp = client.post(f"/notifications/channels/{ch_id}/test")
        assert resp.status_code == 200

    def test_test_channel_failure(self, api_client):
        client, db, _ = api_client
        with Session(db.engine) as session:
            ch = NotificationChannel(
                name="Fail",
                apprise_url="slack://x",
                created_at=datetime.now(UTC),
                updated_at=datetime.now(UTC),
            )
            session.add(ch)
            session.commit()
            ch_id = ch.id

        with patch(
            "backend.routers.notifications.notifier.test",
            new_callable=AsyncMock,
            return_value=(False, "Connection refused"),
        ):
            resp = client.post(f"/notifications/channels/{ch_id}/test")
        assert resp.status_code == 502

        # Check log was created
        resp = client.get("/notifications/log")
        logs = resp.json()
        assert len(logs) == 1
        assert logs[0]["status"] == "failed"
        assert logs[0]["notification_type"] == "test"


class TestNotificationLog:
    def test_get_log_empty(self, api_client):
        client, _, _ = api_client
        resp = client.get("/notifications/log")
        assert resp.status_code == 200
        assert resp.json() == []

    def test_get_log_with_entries(self, api_client):
        client, db, _ = api_client
        with Session(db.engine) as session:
            ch = NotificationChannel(
                name="Ch",
                apprise_url="slack://x",
                created_at=datetime.now(UTC),
                updated_at=datetime.now(UTC),
            )
            session.add(ch)
            session.commit()
            session.add(
                NotificationLog(
                    channel_id=ch.id,
                    notification_type="test",
                    title="Test",
                    body="Body",
                    status="sent",
                    created_at=datetime.now(UTC),
                )
            )
            session.commit()

        resp = client.get("/notifications/log")
        logs = resp.json()
        assert len(logs) == 1
        assert logs[0]["channel_name"] == "Ch"
        assert logs[0]["notification_type"] == "test"


class TestFindNewVulnerabilities:
    def test_first_scan_all_new(self, test_db):
        scan = seed_scan(test_db, "nginx:latest", "sha256:aaa", [VULN_CRITICAL, VULN_HIGH])

        from backend.jobs.notifications import find_new_vulnerabilities

        with Session(test_db.engine) as session:
            result = find_new_vulnerabilities(session, [scan.id])

        assert scan.id in result
        assert len(result[scan.id]) == 2

    def test_second_scan_only_new(self, test_db):
        seed_scan(
            test_db,
            "nginx:latest",
            "sha256:aaa",
            [VULN_CRITICAL],
            scanned_at=datetime(2026, 1, 1, tzinfo=UTC),
        )
        scan2 = seed_scan(
            test_db,
            "nginx:latest",
            "sha256:bbb",
            [VULN_CRITICAL, VULN_MEDIUM],
            scanned_at=datetime(2026, 1, 2, tzinfo=UTC),
        )

        from backend.jobs.notifications import find_new_vulnerabilities

        with Session(test_db.engine) as session:
            result = find_new_vulnerabilities(session, [scan2.id])

        # Only VULN_MEDIUM is new
        assert scan2.id in result
        new_ids = {v.vuln_id for v in result[scan2.id]}
        assert VULN_MEDIUM["vuln_id"] in new_ids
        assert VULN_CRITICAL["vuln_id"] not in new_ids

    def test_no_new_vulns(self, test_db):
        seed_scan(
            test_db,
            "nginx:latest",
            "sha256:aaa",
            [VULN_CRITICAL],
            scanned_at=datetime(2026, 1, 1, tzinfo=UTC),
        )
        scan2 = seed_scan(
            test_db,
            "nginx:latest",
            "sha256:bbb",
            [VULN_CRITICAL],
            scanned_at=datetime(2026, 1, 2, tzinfo=UTC),
        )

        from backend.jobs.notifications import find_new_vulnerabilities

        with Session(test_db.engine) as session:
            result = find_new_vulnerabilities(session, [scan2.id])

        assert scan2.id not in result

    def test_different_tag_does_not_reuse_other_tag_history(self, test_db):
        """First scan of image_name lineage should be all new, even if another tag
        from the same repository was scanned previously."""
        seed_scan(
            test_db,
            "postgres:18",
            "sha256:aaa",
            [VULN_CRITICAL],
            scanned_at=datetime(2026, 1, 1, tzinfo=UTC),
        )
        scan2 = seed_scan(
            test_db,
            "postgres:17",
            "sha256:bbb",
            [VULN_CRITICAL, VULN_MEDIUM],
            scanned_at=datetime(2026, 1, 2, tzinfo=UTC),
        )

        from backend.jobs.notifications import find_new_vulnerabilities

        with Session(test_db.engine) as session:
            result = find_new_vulnerabilities(session, [scan2.id])

        assert scan2.id in result
        assert {v.vuln_id for v in result[scan2.id]} == {
            VULN_CRITICAL["vuln_id"],
            VULN_MEDIUM["vuln_id"],
        }


class TestNotifierService:
    def test_validate_url_valid(self):
        from backend.services.notifier import validate_url

        assert validate_url("json://localhost") is True

    def test_validate_url_invalid(self):
        from backend.services.notifier import validate_url

        assert validate_url("completely-invalid-not-a-url") is False

    @pytest.mark.anyio
    async def test_send_success(self):
        from backend.services.notifier import send

        with patch("backend.services.notifier.apprise.Apprise") as MockApprise:
            mock_instance = MockApprise.return_value
            mock_instance.add.return_value = True
            mock_instance.notify.return_value = True

            ok, err = await send(["json://localhost"], "Title", "Body")
            assert ok is True
            assert err is None

    @pytest.mark.anyio
    async def test_send_failure(self):
        from backend.services.notifier import send

        with patch("backend.services.notifier.apprise.Apprise") as MockApprise:
            mock_instance = MockApprise.return_value
            mock_instance.add.return_value = True
            mock_instance.notify.return_value = False

            ok, err = await send(["json://localhost"], "Title", "Body")
            assert ok is False
            assert err is not None


class TestRunScansThenNotify:
    """Tests for _run_scans_then_notify — the function that bridges scan
    completion to notification dispatch.

    The original bug: SystemTask IDs were passed as Scan IDs. Since these are
    different tables with independent auto-increment sequences, lookups
    returned None and no notifications fired.
    """

    @pytest.mark.anyio
    async def test_passes_real_scan_ids_not_task_ids(self, test_db):
        """_run_scans_then_notify must query for Scan rows and pass their IDs
        to process_scan_notifications — NOT the SystemTask IDs."""
        from backend.jobs.containers import _run_scans_then_notify

        # Create SystemTask rows (these have their own auto-increment IDs)
        with Session(test_db.engine) as session:
            for i in range(3):
                session.add(
                    SystemTask(
                        task_type="scan",
                        task_name=f"Scan image-{i}",
                        status="queued",
                        created_at=datetime.now(UTC),
                    )
                )
            session.commit()

        # Record the max scan ID before the batch so only new scans are captured
        batch_min_scan_id = 0

        # Create Scan rows (simulating what scan_image_async would produce)
        scan = seed_scan(
            test_db,
            "nginx:latest",
            "sha256:abc",
            [VULN_CRITICAL],
            scanned_at=datetime(2026, 3, 15, 12, 0, 1, tzinfo=UTC),
        )

        # The scan coroutines are already "done" — we just need dummy coros
        async def noop():
            return None

        with patch("backend.jobs.containers.process_scan_notifications", new_callable=AsyncMock) as mock_notify:
            await _run_scans_then_notify(
                test_db,
                [noop()],
                [999],  # SystemTask ID — should NOT appear in scan_ids
                batch_min_scan_id,
            )

            mock_notify.assert_called_once()
            called_scan_ids = mock_notify.call_args[0][1]
            called_results = mock_notify.call_args[0][2]

            # The real Scan ID must be in the list
            assert scan.id in called_scan_ids
            # The SystemTask ID must NOT be in the list (no failure)
            assert 999 not in called_scan_ids
            # Result for the successful scan should be None (no exception)
            assert called_results[called_scan_ids.index(scan.id)] is None

    @pytest.mark.anyio
    async def test_failures_appended_with_task_id(self, test_db):
        """When a scan coroutine raises, the task_id and exception should be
        appended to the lists passed to process_scan_notifications."""
        from backend.jobs.containers import _run_scans_then_notify

        async def failing_scan():
            raise RuntimeError("grype crashed")

        with patch("backend.jobs.containers.process_scan_notifications", new_callable=AsyncMock) as mock_notify:
            await _run_scans_then_notify(
                test_db,
                [failing_scan()],
                [42],  # SystemTask ID for the failed scan
                0,  # batch_min_scan_id — no prior scans in this test db
            )

            mock_notify.assert_called_once()
            called_scan_ids = mock_notify.call_args[0][1]
            called_results = mock_notify.call_args[0][2]

            # The failed task_id should be appended
            assert 42 in called_scan_ids
            idx = called_scan_ids.index(42)
            assert isinstance(called_results[idx], RuntimeError)

    @pytest.mark.anyio
    async def test_mixed_success_and_failure(self, test_db):
        """Mix of successful scans and failures produces correct ID/result lists."""
        from backend.jobs.containers import _run_scans_then_notify

        # Record baseline before seeding the batch scan
        batch_min_scan_id = 0

        # Seed a successful scan
        scan = seed_scan(
            test_db,
            "redis:7",
            "sha256:def",
            [VULN_HIGH],
            scanned_at=datetime(2026, 3, 15, 12, 0, 1, tzinfo=UTC),
        )

        async def success_coro():
            return None

        async def fail_coro():
            raise ValueError("connection refused")

        with patch("backend.jobs.containers.process_scan_notifications", new_callable=AsyncMock) as mock_notify:
            await _run_scans_then_notify(
                test_db,
                [success_coro(), fail_coro()],
                [100, 200],  # SystemTask IDs
                batch_min_scan_id,
            )

            mock_notify.assert_called_once()
            called_scan_ids = mock_notify.call_args[0][1]
            called_results = mock_notify.call_args[0][2]

            # Successful scan ID present, failed task ID appended
            assert scan.id in called_scan_ids
            assert 200 in called_scan_ids
            # Successful scan has None result
            assert called_results[called_scan_ids.index(scan.id)] is None
            # Failed scan has the exception
            assert isinstance(called_results[called_scan_ids.index(200)], ValueError)


class TestProcessScanNotifications:
    """Integration tests for process_scan_notifications — verifies that
    notifications are actually dispatched when given real Scan IDs."""

    @pytest.mark.anyio
    async def test_urgent_notification_for_high_risk_score(self, test_db):
        """A vuln with risk_score >= 80 triggers an urgent notification."""
        # VULN_CRITICAL has risk_score=95.0 — qualifies as urgent priority
        scan = seed_scan(test_db, "nginx:latest", "sha256:aaa", [VULN_CRITICAL])

        with Session(test_db.engine) as session:
            session.add(
                NotificationChannel(
                    name="Test",
                    apprise_url="json://localhost",
                    enabled=True,
                    notify_urgent=True,
                    notify_all_new=True,
                )
            )
            session.commit()

        from backend.jobs.notifications import process_scan_notifications

        with patch("backend.services.notifier.apprise.Apprise") as MockApprise:
            mock_instance = MockApprise.return_value
            mock_instance.add.return_value = True
            mock_instance.notify.return_value = True

            await process_scan_notifications(test_db, [scan.id], [None])

        with Session(test_db.engine) as session:
            logs = session.exec(
                NotificationLog.__table__.select()  # type: ignore[attr-defined]
            ).all()
            log_types = {row.notification_type for row in logs}
            assert "urgent" in log_types

    @pytest.mark.anyio
    async def test_urgent_not_triggered_by_low_risk_score(self, test_db):
        """A High-severity vuln with risk_score < 80 should NOT trigger urgent."""
        # VULN_HIGH has risk_score=68.0 — does not qualify as urgent priority
        scan = seed_scan(test_db, "nginx:latest", "sha256:aaa", [VULN_HIGH])

        with Session(test_db.engine) as session:
            session.add(
                NotificationChannel(
                    name="Test",
                    apprise_url="json://localhost",
                    enabled=True,
                    notify_urgent=True,
                )
            )
            session.commit()

        from backend.jobs.notifications import process_scan_notifications

        with patch("backend.services.notifier.apprise.Apprise") as MockApprise:
            mock_instance = MockApprise.return_value
            mock_instance.add.return_value = True
            mock_instance.notify.return_value = True

            await process_scan_notifications(test_db, [scan.id], [None])

        with Session(test_db.engine) as session:
            logs = session.exec(
                NotificationLog.__table__.select()  # type: ignore[attr-defined]
            ).all()
            log_types = {row.notification_type for row in logs}
            assert "urgent" not in log_types

    @pytest.mark.anyio
    async def test_kev_notification_sent_separately(self, test_db):
        """A KEV vuln triggers a separate KEV notification."""
        # VULN_CRITICAL has is_kev=True
        scan = seed_scan(test_db, "nginx:latest", "sha256:aaa", [VULN_CRITICAL])

        with Session(test_db.engine) as session:
            session.add(
                NotificationChannel(
                    name="Test",
                    apprise_url="json://localhost",
                    enabled=True,
                    notify_kev=True,
                    notify_urgent=False,
                )
            )
            session.commit()

        from backend.jobs.notifications import process_scan_notifications

        with patch("backend.services.notifier.apprise.Apprise") as MockApprise:
            mock_instance = MockApprise.return_value
            mock_instance.add.return_value = True
            mock_instance.notify.return_value = True

            await process_scan_notifications(test_db, [scan.id], [None])

        with Session(test_db.engine) as session:
            logs = session.exec(
                NotificationLog.__table__.select()  # type: ignore[attr-defined]
            ).all()
            log_types = {row.notification_type for row in logs}
            assert "kev" in log_types
            assert "urgent" not in log_types

    @pytest.mark.anyio
    async def test_new_vuln_notification_includes_container_and_image_label(self, test_db):
        scan = seed_scan(
            test_db,
            "nginx:latest",
            "sha256:aaa",
            [VULN_HIGH],
            container_names=["web-1"],
        )

        with Session(test_db.engine) as session:
            session.add(
                NotificationChannel(
                    name="AllNew",
                    apprise_url="json://localhost",
                    enabled=True,
                    notify_all_new=True,
                )
            )
            session.commit()

        from backend.jobs.notifications import process_scan_notifications

        with patch("backend.services.notifier.apprise.Apprise") as MockApprise:
            mock_instance = MockApprise.return_value
            mock_instance.add.return_value = True
            mock_instance.notify.return_value = True

            await process_scan_notifications(test_db, [scan.id], [None])

        with Session(test_db.engine) as session:
            logs = session.exec(
                NotificationLog.__table__.select()  # type: ignore[attr-defined]
            ).all()
            new_logs = [row for row in logs if row.notification_type == "new_vulns"]
            assert len(new_logs) == 1
            assert "web-1 (nginx:latest)" in new_logs[0].body

    @pytest.mark.anyio
    async def test_no_notification_when_scan_id_does_not_exist(self, test_db):
        """If scan IDs don't correspond to real Scan rows, no notifications fire.
        This is the exact scenario the original bug produced."""
        # Create a channel that would fire for any notification type
        with Session(test_db.engine) as session:
            session.add(
                NotificationChannel(
                    name="Test",
                    apprise_url="json://localhost",
                    enabled=True,
                    notify_urgent=True,
                    notify_all_new=True,
                    notify_eol=True,
                )
            )
            session.commit()

        from backend.jobs.notifications import process_scan_notifications

        with patch("backend.services.notifier.apprise.Apprise") as MockApprise:
            mock_instance = MockApprise.return_value
            mock_instance.add.return_value = True
            mock_instance.notify.return_value = True

            # Pass bogus IDs (simulating the old bug where SystemTask IDs were used)
            await process_scan_notifications(test_db, [9999, 9998], [None, None])

        # No notification logs should exist — the scans don't exist
        with Session(test_db.engine) as session:
            logs = session.exec(
                NotificationLog.__table__.select()  # type: ignore[attr-defined]
            ).all()
            assert len(logs) == 0

    @pytest.mark.anyio
    async def test_scan_failure_notification(self, test_db):
        """A failed scan should trigger a scan_failure notification."""
        with Session(test_db.engine) as session:
            session.add(
                NotificationChannel(
                    name="Failures",
                    apprise_url="json://localhost",
                    enabled=True,
                    notify_scan_failure=True,
                )
            )
            session.commit()

        from backend.jobs.notifications import process_scan_notifications

        with patch("backend.services.notifier.apprise.Apprise") as MockApprise:
            mock_instance = MockApprise.return_value
            mock_instance.add.return_value = True
            mock_instance.notify.return_value = True

            await process_scan_notifications(test_db, [42], [RuntimeError("grype crashed")])

        with Session(test_db.engine) as session:
            logs = session.exec(
                NotificationLog.__table__.select()  # type: ignore[attr-defined]
            ).all()
            assert len(logs) == 1
            assert logs[0].notification_type == "scan_failure"

    @pytest.mark.anyio
    async def test_eol_notification(self, test_db):
        """A scan with is_distro_eol=True should trigger an EOL notification."""
        # Create a scan with EOL flag
        with Session(test_db.engine) as session:
            scan = Scan(
                scanned_at=datetime.now(UTC),
                image_name="oldimage:latest",
                image_repository="oldimage",
                image_digest="sha256:eol",
                grype_version="0.85.0",
                distro_name="debian",
                distro_version="9",
                is_distro_eol=True,
            )
            session.add(scan)
            session.commit()
            scan_id = scan.id

            session.add(
                NotificationChannel(
                    name="EOL",
                    apprise_url="json://localhost",
                    enabled=True,
                    notify_eol=True,
                )
            )
            session.commit()

        from backend.jobs.notifications import process_scan_notifications

        with patch("backend.services.notifier.apprise.Apprise") as MockApprise:
            mock_instance = MockApprise.return_value
            mock_instance.add.return_value = True
            mock_instance.notify.return_value = True

            await process_scan_notifications(test_db, [scan_id], [None])

        with Session(test_db.engine) as session:
            logs = session.exec(
                NotificationLog.__table__.select()  # type: ignore[attr-defined]
            ).all()
            log_types = {row.notification_type for row in logs}
            assert "eol" in log_types

    @pytest.mark.anyio
    async def test_eol_not_repeated_on_rescan(self, test_db):
        """EOL notification should not re-fire if the previous scan of the same
        image was also EOL (e.g. after a Grype DB update triggers a full rescan)."""
        # First scan — EOL
        with Session(test_db.engine) as session:
            scan1 = Scan(
                scanned_at=datetime(2026, 3, 14, tzinfo=UTC),
                image_name="oldimage:latest",
                image_repository="oldimage",
                image_digest="sha256:eol1",
                grype_version="0.85.0",
                distro_name="debian",
                distro_version="9",
                is_distro_eol=True,
            )
            session.add(scan1)
            session.commit()

        # Second scan of same image — still EOL (e.g. rescan after DB update)
        with Session(test_db.engine) as session:
            scan2 = Scan(
                scanned_at=datetime(2026, 3, 15, tzinfo=UTC),
                image_name="oldimage:latest",
                image_repository="oldimage",
                image_digest="sha256:eol2",
                grype_version="0.85.0",
                distro_name="debian",
                distro_version="9",
                is_distro_eol=True,
            )
            session.add(scan2)
            session.commit()
            scan2_id = scan2.id

            session.add(
                NotificationChannel(
                    name="EOL",
                    apprise_url="json://localhost",
                    enabled=True,
                    notify_eol=True,
                )
            )
            session.commit()

        from backend.jobs.notifications import process_scan_notifications

        with patch("backend.services.notifier.apprise.Apprise") as MockApprise:
            mock_instance = MockApprise.return_value
            mock_instance.add.return_value = True
            mock_instance.notify.return_value = True

            await process_scan_notifications(test_db, [scan2_id], [None])

        # No EOL notification should fire — previous scan was already EOL
        with Session(test_db.engine) as session:
            logs = session.exec(
                NotificationLog.__table__.select()  # type: ignore[attr-defined]
            ).all()
            eol_logs = [row for row in logs if row.notification_type == "eol"]
            assert len(eol_logs) == 0


# ---------------------------------------------------------------------------
# Helper function unit tests
# ---------------------------------------------------------------------------


class TestVulnLabel:
    def test_plain_text_when_no_base_url(self):
        from backend.jobs.notifications import _vuln_label

        assert _vuln_label("CVE-2024-0001", "") == "CVE-2024-0001"

    def test_markdown_link_when_base_url_set(self):
        from backend.jobs.notifications import _vuln_label

        result = _vuln_label("CVE-2024-0001", "https://dockguard.example.com")
        assert result == "[CVE-2024-0001](https://dockguard.example.com/vulnerabilities?cve=CVE-2024-0001)"

    def test_base_url_trailing_slash_stripped(self):
        from backend.jobs.notifications import _vuln_label

        result = _vuln_label("CVE-2024-0001", "https://dockguard.example.com/")
        assert result == "[CVE-2024-0001](https://dockguard.example.com/vulnerabilities?cve=CVE-2024-0001)"


class TestPriorityCountsStr:
    def test_multiple_priorities(self):
        from backend.jobs.notifications import _priority_counts_str

        result = _priority_counts_str({"Urgent": 2, "High": 4, "Medium": 3})
        assert result == "2 Urgent, 4 High, 3 Medium"

    def test_zero_count_omitted(self):
        from backend.jobs.notifications import _priority_counts_str

        result = _priority_counts_str({"Urgent": 0, "High": 1})
        assert result == "1 High"

    def test_empty_dict(self):
        from backend.jobs.notifications import _priority_counts_str

        assert _priority_counts_str({}) == "0 vulnerabilities"


class TestBuildVulnBody:
    """Coverage for all three tiers of _build_vuln_body."""

    def _make_vuln(self, vuln_id: str, risk_score: float, is_kev: bool = False):
        from backend.models import Vulnerability

        return Vulnerability(
            scan_id=1,
            vuln_id=vuln_id,
            severity="High",
            package_name="pkg",
            installed_version="1.0",
            risk_score=risk_score,
            is_kev=is_kev,
        )

    def test_tier1_full_detail(self):
        """≤5 vulns → full per-CVE listing."""
        from backend.jobs.notifications import _build_vuln_body

        vulns = [self._make_vuln(f"CVE-2024-000{i}", 70.0) for i in range(3)]
        body = _build_vuln_body({"web": vulns}, base_url="")
        assert "CVE-2024-0000" in body
        assert "web" in body

    def test_tier1_includes_kev_badge(self):
        from backend.jobs.notifications import _build_vuln_body

        vuln = self._make_vuln("CVE-2024-9999", 70.0, is_kev=True)
        body = _build_vuln_body({"web": [vuln]}, base_url="")
        assert "[KEV]" in body

    def test_tier1_includes_markdown_link_with_base_url(self):
        from backend.jobs.notifications import _build_vuln_body

        vuln = self._make_vuln("CVE-2024-9999", 70.0)
        body = _build_vuln_body({"web": [vuln]}, base_url="https://example.com")
        assert "[CVE-2024-9999](" in body

    def test_tier2_per_container_summary(self):
        """6–10 total vulns with ≤10 containers → per-container summary lines."""
        from backend.jobs.notifications import _build_vuln_body

        # 6 vulns in 2 containers — exceeds DETAIL_THRESHOLD of 5
        vulns = [self._make_vuln(f"CVE-2024-{i:04d}", 70.0) for i in range(3)]
        body = _build_vuln_body({"web": vulns, "db": vulns}, base_url="")
        # Tier 2 shows container names as bold labels
        assert "**web**" in body
        assert "**db**" in body
        # Tier 2 does NOT list individual CVE IDs
        assert "CVE-2024-0000" not in body

    def test_tier2_kev_count_in_summary(self):
        from backend.jobs.notifications import _build_vuln_body

        vulns = [self._make_vuln(f"CVE-2024-{i:04d}", 70.0, is_kev=(i == 0)) for i in range(3)]
        body = _build_vuln_body({"web": vulns, "db": vulns}, base_url="")
        assert "KEV" in body

    def test_tier3_rolled_up_total(self):
        """More than 10 containers → single rolled-up summary."""
        from backend.jobs.notifications import _build_vuln_body

        # 11 containers, 1 vuln each → triggers tier 3
        containers = {f"container-{i}": [self._make_vuln(f"CVE-2024-{i:04d}", 70.0)] for i in range(11)}
        body = _build_vuln_body(containers, base_url="")
        assert "**11** containers" in body
        assert "**11**" in body

    def test_tier3_kev_count_shown(self):
        from backend.jobs.notifications import _build_vuln_body

        containers = {f"container-{i}": [self._make_vuln(f"CVE-2024-{i:04d}", 70.0, is_kev=True)] for i in range(11)}
        body = _build_vuln_body(containers, base_url="")
        assert "CISA KEV" in body


class TestFindNewVulnerabilitiesEmpty:
    def test_empty_scan_ids_returns_empty_dict(self, test_db):
        from backend.jobs.notifications import find_new_vulnerabilities

        with Session(test_db.engine) as session:
            result = find_new_vulnerabilities(session, [])

        assert result == {}


class TestProcessScanNotificationsNoChannels:
    @pytest.mark.anyio
    async def test_returns_early_when_no_enabled_channels(self, test_db):
        """process_scan_notifications must no-op when there are no enabled channels."""
        from backend.jobs.notifications import process_scan_notifications

        scan = seed_scan(test_db, "nginx:latest", "sha256:aaa", [VULN_CRITICAL])

        with patch("backend.services.notifier.apprise.Apprise") as MockApprise:
            await process_scan_notifications(test_db, [scan.id], [None])
            # Apprise should never be instantiated when there are no channels
            MockApprise.assert_not_called()


# ---------------------------------------------------------------------------
# send_daily_digest
# ---------------------------------------------------------------------------


class TestSendDailyDigest:
    def _add_digest_channel(self, test_db):
        with Session(test_db.engine) as session:
            ch = NotificationChannel(
                name="Digest",
                apprise_url="json://localhost",
                enabled=True,
                notify_digest=True,
            )
            session.add(ch)
            session.commit()

    @pytest.mark.anyio
    async def test_no_channels_returns_early(self, test_db):
        from backend.jobs.notifications import send_daily_digest

        with patch("backend.jobs.notifications.DockerWatcher") as MockWatcher:
            await send_daily_digest(test_db)
            MockWatcher.assert_not_called()

    @pytest.mark.anyio
    async def test_no_running_containers_returns_early(self, test_db):
        from backend.jobs.notifications import send_daily_digest

        self._add_digest_channel(test_db)

        with patch("backend.jobs.notifications.DockerWatcher") as MockWatcher:
            MockWatcher.return_value.list_running_containers.return_value = []
            await send_daily_digest(test_db)

        # No notification log created
        with Session(test_db.engine) as session:
            logs = session.exec(NotificationLog.__table__.select()).all()  # type: ignore[attr-defined]
        assert len(logs) == 0

    @pytest.mark.anyio
    async def test_sends_digest_and_saves_app_state(self, test_db):
        from backend.jobs.notifications import send_daily_digest
        from backend.models import AppState

        self._add_digest_channel(test_db)
        seed_scan(test_db, "nginx:latest", "sha256:aaa", [VULN_CRITICAL, VULN_HIGH])

        with patch("backend.jobs.notifications.DockerWatcher") as MockWatcher:
            MockWatcher.return_value.list_running_containers.return_value = [
                {"image_name": "nginx:latest"},
            ]
            with patch("backend.services.notifier.apprise.Apprise") as MockApprise:
                mock_inst = MockApprise.return_value
                mock_inst.add.return_value = True
                mock_inst.notify.return_value = True

                await send_daily_digest(test_db)

        # Notification log should be written
        with Session(test_db.engine) as session:
            logs = session.exec(NotificationLog.__table__.select()).all()  # type: ignore[attr-defined]
            digest_logs = [r for r in logs if r.notification_type == "digest"]
        assert len(digest_logs) == 1

        # AppState.last_digest_data should be persisted
        with Session(test_db.engine) as session:
            state = session.get(AppState, 1)
        assert state is not None
        assert state.last_digest_data is not None
        import json

        data = json.loads(state.last_digest_data)
        assert data["total"] == 2

    @pytest.mark.anyio
    async def test_includes_delta_on_second_run(self, test_db):
        """Second digest run computes deltas against saved AppState."""
        from backend.jobs.notifications import send_daily_digest

        self._add_digest_channel(test_db)
        seed_scan(test_db, "nginx:latest", "sha256:aaa", [VULN_CRITICAL])

        with patch("backend.jobs.notifications.DockerWatcher") as MockWatcher:
            MockWatcher.return_value.list_running_containers.return_value = [{"image_name": "nginx:latest"}]
            with patch("backend.services.notifier.apprise.Apprise") as MockApprise:
                mock_inst = MockApprise.return_value
                mock_inst.add.return_value = True
                mock_inst.notify.return_value = True
                # First run — establishes baseline
                await send_daily_digest(test_db)
                captured_bodies: list[str] = []
                mock_inst.notify.side_effect = lambda **kw: captured_bodies.append(kw.get("body", "")) or True
                # Second run — should include "Changes since last digest"
                await send_daily_digest(test_db)

        assert any("Changes since last digest" in b for b in captured_bodies)

    @pytest.mark.anyio
    async def test_invalid_last_digest_data_does_not_crash(self, test_db):
        """Corrupt AppState.last_digest_data → warning logged, no crash."""
        from backend.jobs.notifications import send_daily_digest
        from backend.models import AppState

        self._add_digest_channel(test_db)
        seed_scan(test_db, "nginx:latest", "sha256:aaa", [VULN_CRITICAL])

        with Session(test_db.engine) as session:
            state = AppState(id=1, last_digest_data="not-valid-json")
            session.add(state)
            session.commit()

        with patch("backend.jobs.notifications.DockerWatcher") as MockWatcher:
            MockWatcher.return_value.list_running_containers.return_value = [{"image_name": "nginx:latest"}]
            with patch("backend.services.notifier.apprise.Apprise") as MockApprise:
                mock_inst = MockApprise.return_value
                mock_inst.add.return_value = True
                mock_inst.notify.return_value = True
                # Should not raise despite corrupt data
                await send_daily_digest(test_db)

        with Session(test_db.engine) as session:
            logs = session.exec(NotificationLog.__table__.select()).all()  # type: ignore[attr-defined]
        assert len([r for r in logs if r.notification_type == "digest"]) == 1


# ---------------------------------------------------------------------------
# Notifier service: uncovered branches
# ---------------------------------------------------------------------------


class TestNotifierServiceBranches:
    @pytest.mark.anyio
    async def test_all_urls_rejected_returns_false(self):
        from backend.services.notifier import send

        with patch("backend.services.notifier.apprise.Apprise") as MockApprise:
            mock_inst = MockApprise.return_value
            mock_inst.add.return_value = False
            # ap.__bool__ must return False so `if not ap:` is True
            mock_inst.__bool__ = lambda self: False

            ok, err = await send(["bad://url"], "Title", "Body")

        assert ok is False
        assert err is not None
        assert "No valid Apprise URLs" in err

    @pytest.mark.anyio
    async def test_partial_url_rejection_warns_but_succeeds(self):
        from backend.services.notifier import send

        add_calls: list[str] = []

        def _add(url):
            add_calls.append(url)
            # First URL valid, second invalid
            return url == "json://localhost"

        with patch("backend.services.notifier.apprise.Apprise") as MockApprise:
            mock_inst = MockApprise.return_value
            mock_inst.add.side_effect = _add
            mock_inst.__bool__ = lambda self: True
            mock_inst.notify.return_value = True

            ok, err = await send(["json://localhost", "bad://url"], "Title", "Body")

        assert ok is True
        assert err is None

    @pytest.mark.anyio
    async def test_exception_in_thread_returns_error(self):
        from backend.services.notifier import send

        with patch("backend.services.notifier.apprise.Apprise") as MockApprise:
            MockApprise.side_effect = RuntimeError("boom")

            ok, err = await send(["json://localhost"], "Title", "Body")

        assert ok is False
        assert "boom" in (err or "")

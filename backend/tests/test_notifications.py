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

        batch_started = datetime(2026, 3, 15, 12, 0, 0, tzinfo=UTC)

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
                batch_started,
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

        batch_started = datetime(2026, 3, 15, 12, 0, 0, tzinfo=UTC)

        async def failing_scan():
            raise RuntimeError("grype crashed")

        with patch("backend.jobs.containers.process_scan_notifications", new_callable=AsyncMock) as mock_notify:
            await _run_scans_then_notify(
                test_db,
                [failing_scan()],
                [42],  # SystemTask ID for the failed scan
                batch_started,
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

        batch_started = datetime(2026, 3, 15, 12, 0, 0, tzinfo=UTC)

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
                batch_started,
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

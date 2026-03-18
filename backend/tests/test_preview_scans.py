"""Tests for preview scan streaming path: _parse_progress_line, scan_image_streaming_async,
and the DELETE /preview-scans cancellation endpoint."""

import asyncio
import json
from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock, patch

from sqlmodel import Session

from backend.grype_scanner import GrypeScanner, _parse_progress_line
from backend.models import SystemTask
from backend.tests.fixtures import GRYPE_JSON_NGINX

# ---------------------------------------------------------------------------
# _parse_progress_line
# ---------------------------------------------------------------------------


def test_parse_progress_line_db_load():
    assert _parse_progress_line("[0] INFO load vulnerability db") == "Loading vulnerability database"


def test_parse_progress_line_updating_db():
    assert _parse_progress_line("updating vulnerability db...") == "Loading vulnerability database"


def test_parse_progress_line_catalog():
    assert _parse_progress_line("[1] DEBUG cataloging image packages") == "Cataloging packages"


def test_parse_progress_line_index_layer():
    assert _parse_progress_line("index layer sha256:abc") == "Cataloging packages"


def test_parse_progress_line_match_vulns():
    assert _parse_progress_line("matching vulnerabilities against packages") == "Matching vulnerabilities"


def test_parse_progress_line_strips_ansi():
    ansi_line = "\x1b[32mload vulnerability db\x1b[0m"
    assert _parse_progress_line(ansi_line) == "Loading vulnerability database"


def test_parse_progress_line_empty_returns_none():
    assert _parse_progress_line("") is None
    assert _parse_progress_line("   ") is None
    assert _parse_progress_line("\x1b[32m\x1b[0m") is None


def test_parse_progress_line_unrecognised_returns_none():
    assert _parse_progress_line("some random grype log line about nothing") is None


# ---------------------------------------------------------------------------
# scan_image_streaming_async — happy path (mock subprocess)
# ---------------------------------------------------------------------------


def _make_mock_proc(stdout_data: bytes, stderr_lines: list[bytes], returncode: int = 0):
    """Return a mock async subprocess that yields fake stdout/stderr."""
    mock_proc = MagicMock()
    mock_proc.returncode = returncode

    # stdout: single read() call returns all bytes
    mock_stdout = AsyncMock()
    mock_stdout.read = AsyncMock(return_value=stdout_data)
    mock_proc.stdout = mock_stdout

    # stderr: readline() yields lines one at a time then b""
    lines = list(stderr_lines) + [b""]
    readline_side_effects = [AsyncMock(return_value=line) for line in lines]
    mock_stderr = MagicMock()
    mock_stderr.readline = MagicMock(side_effect=[se.return_value for se in readline_side_effects])

    async def _readline():
        if not lines:
            return b""
        return lines.pop(0)

    mock_stderr.readline = _readline
    mock_proc.stderr = mock_stderr
    mock_proc.wait = AsyncMock(return_value=None)
    mock_proc.kill = MagicMock()
    return mock_proc


def test_streaming_async_happy_path(test_db):
    """scan_image_streaming_async stores a scan and marks task completed."""
    stdout_bytes = json.dumps(GRYPE_JSON_NGINX).encode()
    stderr_lines = [
        b"[0] INFO load vulnerability db\n",
        b"[1] DEBUG cataloging image packages\n",
        b"[2] INFO matching vulnerabilities against packages\n",
    ]

    mock_proc = _make_mock_proc(stdout_bytes, stderr_lines)

    with Session(test_db.engine) as session:
        task = SystemTask(
            task_type="preview_scan",
            task_name="Preview scan: nginx:latest",
            status="queued",
            created_at=datetime.now(UTC),
        )
        session.add(task)
        session.commit()
        session.refresh(task)
        task_id = task.id

    progress_store: dict[int, list[str]] = {task_id: []}
    semaphore = asyncio.Semaphore(1)

    scanner = GrypeScanner(watcher=None, database=test_db, enable_reference_title_fetch=False)

    with patch("backend.grype_scanner.asyncio.create_subprocess_exec", return_value=mock_proc):
        asyncio.run(
            scanner.scan_image_streaming_async(
                image_name="nginx:latest",
                grype_ref="registry:docker.io/library/nginx:latest",
                semaphore=semaphore,
                task_id=task_id,
                progress_store=progress_store,
            )
        )

    with Session(test_db.engine) as session:
        task = session.get(SystemTask, task_id)
        assert task is not None
        assert task.status == "completed"

    # Progress lines should have been populated during the scan
    assert len(progress_store[task_id]) >= 1
    assert "Loading vulnerability database" in progress_store[task_id]


def test_streaming_async_progress_deduplication(test_db):
    """Duplicate consecutive progress labels are not appended."""
    stdout_bytes = json.dumps(GRYPE_JSON_NGINX).encode()
    stderr_lines = [
        b"load vulnerability db\n",
        b"still loading vulnerability db\n",  # same phase — should not duplicate
        b"cataloging packages\n",
    ]

    mock_proc = _make_mock_proc(stdout_bytes, stderr_lines)

    with Session(test_db.engine) as session:
        task = SystemTask(
            task_type="preview_scan",
            task_name="Preview scan: nginx:latest",
            status="queued",
            created_at=datetime.now(UTC),
        )
        session.add(task)
        session.commit()
        session.refresh(task)
        task_id = task.id

    progress_store: dict[int, list[str]] = {task_id: []}
    semaphore = asyncio.Semaphore(1)
    scanner = GrypeScanner(watcher=None, database=test_db, enable_reference_title_fetch=False)

    with patch("backend.grype_scanner.asyncio.create_subprocess_exec", return_value=mock_proc):
        asyncio.run(
            scanner.scan_image_streaming_async(
                image_name="nginx:latest",
                grype_ref="registry:docker.io/library/nginx:latest",
                semaphore=semaphore,
                task_id=task_id,
                progress_store=progress_store,
            )
        )

    lines = progress_store[task_id]
    assert lines.count("Loading vulnerability database") == 1


# ---------------------------------------------------------------------------
# scan_image_streaming_async — timeout path
# ---------------------------------------------------------------------------


def test_streaming_async_timeout_marks_task_failed(test_db):
    """TimeoutError during gather kills proc and marks task failed."""

    async def _fake_create_subprocess(*args, **kwargs):
        mock_proc = MagicMock()
        mock_proc.kill = MagicMock()
        mock_proc.wait = AsyncMock(return_value=None)
        mock_proc.stdout = MagicMock()
        mock_proc.stderr = MagicMock()

        async def _never_ending_readline():
            await asyncio.sleep(9999)
            return b""

        mock_proc.stderr.readline = _never_ending_readline

        async def _never_ending_read():
            await asyncio.sleep(9999)
            return b""

        mock_proc.stdout.read = _never_ending_read
        return mock_proc

    with Session(test_db.engine) as session:
        task = SystemTask(
            task_type="preview_scan",
            task_name="Preview scan: nginx:latest",
            status="queued",
            created_at=datetime.now(UTC),
        )
        session.add(task)
        session.commit()
        session.refresh(task)
        task_id = task.id

    progress_store: dict[int, list[str]] = {task_id: []}
    semaphore = asyncio.Semaphore(1)
    scanner = GrypeScanner(watcher=None, database=test_db, enable_reference_title_fetch=False)

    with patch("backend.grype_scanner.asyncio.create_subprocess_exec", side_effect=_fake_create_subprocess):
        with patch("backend.grype_scanner.asyncio.wait_for", side_effect=asyncio.TimeoutError):
            asyncio.run(
                scanner.scan_image_streaming_async(
                    image_name="nginx:latest",
                    grype_ref="registry:docker.io/library/nginx:latest",
                    semaphore=semaphore,
                    task_id=task_id,
                    progress_store=progress_store,
                )
            )

    with Session(test_db.engine) as session:
        task = session.get(SystemTask, task_id)
        assert task is not None
        assert task.status == "failed"
        assert "timed out" in (task.error_message or "").lower()


# ---------------------------------------------------------------------------
# scan_image_streaming_async — cancellation path
# ---------------------------------------------------------------------------


def test_streaming_async_cancelled_marks_task_failed(test_db):
    """CancelledError kills proc, marks task failed/cancelled, and re-raises."""

    async def _run():
        async def _fake_create_subprocess(*args, **kwargs):
            mock_proc = MagicMock()
            mock_proc.kill = MagicMock()
            mock_proc.wait = AsyncMock(return_value=None)
            mock_proc.stdout = MagicMock()
            mock_proc.stderr = MagicMock()

            async def _blocking_readline():
                await asyncio.sleep(9999)
                return b""

            mock_proc.stderr.readline = _blocking_readline
            mock_proc.stdout.read = AsyncMock(side_effect=asyncio.CancelledError)
            return mock_proc

        with Session(test_db.engine) as session:
            task = SystemTask(
                task_type="preview_scan",
                task_name="Preview scan: nginx:latest",
                status="queued",
                created_at=datetime.now(UTC),
            )
            session.add(task)
            session.commit()
            session.refresh(task)
            task_id = task.id

        progress_store: dict[int, list[str]] = {task_id: []}
        semaphore = asyncio.Semaphore(1)
        scanner = GrypeScanner(watcher=None, database=test_db, enable_reference_title_fetch=False)

        with patch("backend.grype_scanner.asyncio.create_subprocess_exec", side_effect=_fake_create_subprocess):
            coro = scanner.scan_image_streaming_async(
                image_name="nginx:latest",
                grype_ref="registry:docker.io/library/nginx:latest",
                semaphore=semaphore,
                task_id=task_id,
                progress_store=progress_store,
            )
            task_obj = asyncio.create_task(coro)
            # Let the task start, then cancel it
            await asyncio.sleep(0)
            task_obj.cancel()
            try:
                await task_obj
            except (asyncio.CancelledError, Exception):
                pass

        with Session(test_db.engine) as session:
            db_task = session.get(SystemTask, task_id)
            assert db_task is not None
            assert db_task.status == "failed"

    asyncio.run(_run())


# ---------------------------------------------------------------------------
# DELETE /preview-scans — cancellation endpoint
# ---------------------------------------------------------------------------


def test_delete_preview_scans_cancels_active_tasks(api_client):
    """DELETE /preview-scans with task_ids cancels the in-flight asyncio tasks."""
    client, test_db, _ = api_client

    # Inject a fake active task into the module-level store
    import backend.routers.preview_scans as preview_module

    mock_task = MagicMock()
    mock_task.cancel = MagicMock()
    preview_module._active_tasks[9999] = mock_task
    preview_module._progress_store[9999] = ["Loading vulnerability database"]

    res = client.request(
        "DELETE",
        "/preview-scans",
        json={"image_names": [], "task_ids": [9999]},
    )
    assert res.status_code == 204
    mock_task.cancel.assert_called_once()
    assert 9999 not in preview_module._active_tasks
    assert 9999 not in preview_module._progress_store


def test_delete_preview_scans_handles_missing_task_id(api_client):
    """DELETE with a task_id not in _active_tasks does not raise."""
    client, _, _ = api_client
    res = client.request(
        "DELETE",
        "/preview-scans",
        json={"image_names": [], "task_ids": [99999]},
    )
    assert res.status_code == 204


# ---------------------------------------------------------------------------
# GET /preview-scans/status — progress_lines in response
# ---------------------------------------------------------------------------


def test_status_returns_progress_lines_for_scanning_task(api_client):
    """Status endpoint returns progress_lines for in-progress tasks."""
    client, test_db, _ = api_client
    import backend.routers.preview_scans as preview_module

    with Session(test_db.engine) as session:
        task = SystemTask(
            task_type="preview_scan",
            task_name="Preview scan: nginx:latest",
            status="running",
            created_at=datetime.now(UTC),
        )
        session.add(task)
        session.commit()
        session.refresh(task)
        task_id = task.id

    preview_module._progress_store[task_id] = ["Loading vulnerability database", "Cataloging packages"]

    res = client.get(f"/preview-scans/status?task_ids={task_id}")
    assert res.status_code == 200
    data = res.json()
    assert len(data) == 1
    assert data[0]["progress_lines"] == ["Loading vulnerability database", "Cataloging packages"]

    # Clean up
    preview_module._progress_store.pop(task_id, None)


def test_status_returns_empty_progress_lines_for_completed_task(api_client):
    """Status endpoint returns empty progress_lines for completed tasks."""
    client, test_db, _ = api_client
    import backend.routers.preview_scans as preview_module

    with Session(test_db.engine) as session:
        task = SystemTask(
            task_type="preview_scan",
            task_name="Preview scan: nginx:latest",
            status="completed",
            created_at=datetime.now(UTC),
        )
        session.add(task)
        session.commit()
        session.refresh(task)
        task_id = task.id

    # Even if somehow still in store, should return []
    preview_module._progress_store[task_id] = ["Loading vulnerability database"]

    res = client.get(f"/preview-scans/status?task_ids={task_id}")
    assert res.status_code == 200
    data = res.json()
    assert data[0]["progress_lines"] == []

    preview_module._progress_store.pop(task_id, None)

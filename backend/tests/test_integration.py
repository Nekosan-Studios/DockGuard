"""Integration tests — require real Alembic migrations and full app lifespan.

Run with: uv run pytest -v -m integration
"""

import logging

import pytest
from sqlalchemy import inspect as sa_inspect

import backend.scheduler as sched_module


@pytest.mark.integration
def test_app_loggers_enabled_after_startup(integration_client):
    """Module loggers must not be disabled and must propagate INFO after startup.

    Catches regressions where alembic's fileConfig silences loggers by setting
    disable_existing_loggers=True (the Python default).
    """
    _client, _db = integration_client
    for name in ("scheduler", "grype_scanner", "docker_watcher"):
        log = logging.getLogger(name)
        assert not log.disabled, f"Logger '{name}' is disabled after startup"
        assert log.getEffectiveLevel() == logging.INFO, (
            f"Logger '{name}' effective level is {log.getEffectiveLevel()}, expected INFO"
        )


@pytest.mark.integration
def test_alembic_upgrade_runs_cleanly(tmp_db, monkeypatch):
    """Alembic migrations create all expected tables and columns.

    Catches bugs like missing 'import sqlmodel' in generated migration files,
    wrong backfill logic, or columns that were renamed/dropped accidentally.
    """
    monkeypatch.setattr("backend.database.DATABASE_PATH", str(tmp_db.engine.url).replace("sqlite:///", ""))
    tmp_db.init()

    inspector = sa_inspect(tmp_db.engine)
    table_names = inspector.get_table_names()
    assert "scan" in table_names, "Table 'scan' missing after migration"
    assert "vulnerability" in table_names, "Table 'vulnerability' missing after migration"

    scan_columns = {c["name"] for c in inspector.get_columns("scan")}
    assert "image_repository" in scan_columns, "'image_repository' column missing from scan"
    assert "image_digest" in scan_columns, "'image_digest' column missing from scan"
    assert "image_name" in scan_columns, "'image_name' column missing from scan"


@pytest.mark.integration
def test_scheduler_job_registered(integration_client):
    """APScheduler must have both scheduled jobs registered after startup."""
    _client, _db = integration_client
    assert sched_module._active_scheduler is not None, "_active_scheduler was never set"
    jobs = sched_module._active_scheduler.get_jobs()
    job_ids = [j.id for j in jobs]
    assert "scan_for_container_changes" in job_ids, f"Expected job 'scan_for_container_changes', found: {job_ids}"
    assert "check_db_update" in job_ids, f"Expected job 'check_db_update', found: {job_ids}"

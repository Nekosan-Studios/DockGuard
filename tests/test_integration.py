"""Integration tests — always run, no external dependencies required.

These tests exercise the real lifespan pipeline (alembic migrations, logging
config, scheduler wiring) using a throwaway SQLite file via tmp_path.
"""
import logging

import pytest
from sqlalchemy import inspect as sa_inspect

import server.scheduler as sched_module


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


def test_alembic_upgrade_runs_cleanly(tmp_db, monkeypatch):
    """Alembic migrations create all expected tables and columns.

    Catches bugs like missing 'import sqlmodel' in generated migration files,
    wrong backfill logic, or columns that were renamed/dropped accidentally.
    """
    monkeypatch.setattr("server.database.DATABASE_URL", str(tmp_db.engine.url))
    tmp_db.init()

    inspector = sa_inspect(tmp_db.engine)
    table_names = inspector.get_table_names()
    assert "scan" in table_names, "Table 'scan' missing after migration"
    assert "vulnerability" in table_names, "Table 'vulnerability' missing after migration"

    scan_columns = {c["name"] for c in inspector.get_columns("scan")}
    assert "image_repository" in scan_columns, "'image_repository' column missing from scan"
    assert "image_digest" in scan_columns, "'image_digest' column missing from scan"
    assert "image_name" in scan_columns, "'image_name' column missing from scan"


def test_scheduler_job_registered(integration_client):
    """APScheduler must have the container-monitor job registered after startup."""
    _client, _db = integration_client
    assert sched_module._active_scheduler is not None, "_active_scheduler was never set"
    jobs = sched_module._active_scheduler.get_jobs()
    job_ids = [j.id for j in jobs]
    assert "check_running_containers" in job_ids, (
        f"Expected job 'check_running_containers', found: {job_ids}"
    )

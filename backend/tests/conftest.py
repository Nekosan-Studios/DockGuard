import os
import shutil

# Point the test database to the tests/data directory before any backend
# modules are imported. DATABASE_PATH is read at module-load time in
# backend/database.py, so this must come first.
os.environ.setdefault("DATABASE_PATH", "backend/tests/data/test.db")

import pytest


def pytest_sessionfinish(session, exitstatus):
    """Remind the developer to run e2e tests when they are excluded by default."""
    markexpr = getattr(session.config.option, "markexpr", "")
    if "not e2e" in markexpr:
        print("\nNote: e2e tests excluded. Run `uv run pytest -v -m e2e` to include them.")


from datetime import UTC, datetime
from unittest.mock import patch

from fastapi.testclient import TestClient
from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel, create_engine

import docker as docker_sdk
from backend.database import Database
from backend.database import db as production_db
from backend.grype_scanner import _parse_image_repository
from backend.main import app
from backend.models import Scan, Vulnerability

# ---------------------------------------------------------------------------
# Test database — fresh in-memory SQLite per test
#
# StaticPool ensures all connections (seed_scan + API handler) share the
# same in-memory database. Without it each new connection gets its own
# empty database and the API can't see data inserted by seed_scan.
# ---------------------------------------------------------------------------


@pytest.fixture
def test_db():
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    SQLModel.metadata.create_all(engine)
    database = Database.__new__(Database)
    database.engine = engine
    yield database
    SQLModel.metadata.drop_all(engine)


# ---------------------------------------------------------------------------
# API test client — wired to test_db, Docker mocked to no running containers
# ---------------------------------------------------------------------------


@pytest.fixture
def api_client(test_db):
    app.dependency_overrides[production_db.get_session] = test_db.get_session

    # Patch init on both the production db and test_db: the lifespan calls
    # db.init() where db has been replaced by test_db, and test_db.init()
    # would invoke Alembic against the real DATABASE_PATH. Tables are already
    # created by SQLModel.metadata.create_all in the test_db fixture.
    with patch.object(production_db, "init"):
        with patch.object(test_db, "init"):
            with patch("backend.main.db", test_db):
                with patch("backend.routers.vulnerabilities.db", test_db):
                    with patch("backend.routers.containers.db", test_db):
                        with patch("backend.routers.tasks.db", test_db):
                            with patch("backend.routers.settings.db", test_db):
                                with patch("backend.routers.internal.db", test_db):
                                    with (
                                        patch("backend.routers.containers.DockerWatcher") as cw,
                                        patch("backend.routers.vulnerabilities.DockerWatcher") as vw,
                                        patch("backend.jobs.containers.DockerWatcher") as jw,
                                    ):
                                        cw.return_value.list_images.return_value = []
                                        cw.return_value.list_running_containers.return_value = []
                                        vw.return_value.list_images.return_value = []
                                        vw.return_value.list_running_containers.return_value = []
                                        jw.return_value.list_images.return_value = []
                                        jw.return_value.list_running_containers.return_value = []
                                        with TestClient(app, raise_server_exceptions=True) as client:
                                            # tests expect the mock instance
                                            yield client, test_db, (cw, vw)

    app.dependency_overrides.clear()


# ---------------------------------------------------------------------------
# Seed helper — insert a scan + vulnerabilities directly into the test DB
# ---------------------------------------------------------------------------


def seed_scan(
    database: Database, image_name: str, image_digest: str, vulns: list[dict], scanned_at: datetime | None = None
) -> Scan:
    scan = Scan(
        scanned_at=scanned_at or datetime.now(UTC),
        image_name=image_name,
        image_repository=_parse_image_repository(image_name),
        image_digest=image_digest,
        grype_version="0.85.0",
        db_built=datetime(2024, 1, 15, tzinfo=UTC),
        distro_name="debian",
        distro_version="12",
    )
    with Session(database.engine) as session:
        session.add(scan)
        session.flush()
        for v in vulns:
            session.add(Vulnerability(scan_id=scan.id, **v))
        session.commit()
        session.refresh(scan)
    return scan


# ---------------------------------------------------------------------------
# Shared vulnerability dicts for seeding
# ---------------------------------------------------------------------------

VULN_CRITICAL = dict(
    vuln_id="CVE-2024-0001",
    severity="Critical",
    package_name="libssl",
    installed_version="1.1.1",
    cvss_base_score=9.8,
    is_kev=True,
    epss_score=0.94,
    epss_percentile=0.99,
    risk_score=9.5,
    fix_state="fixed",
    fixed_version="1.2.3",
)
VULN_HIGH = dict(
    vuln_id="CVE-2024-0002",
    severity="High",
    package_name="curl",
    installed_version="7.88.0",
    cvss_base_score=7.5,
    is_kev=False,
    epss_score=0.12,
    epss_percentile=0.75,
    risk_score=6.8,
    fix_state="not-fixed",
    fixed_version=None,
)
VULN_MEDIUM = dict(
    vuln_id="CVE-2024-0003",
    severity="Medium",
    package_name="zlib",
    installed_version="1.2.11",
    cvss_base_score=5.3,
    is_kev=False,
    epss_score=0.02,
    epss_percentile=0.40,
    risk_score=3.1,
    fix_state="fixed",
    fixed_version="2.0.0",
)
VULN_CRITICAL_2 = dict(
    vuln_id="CVE-2024-0010",
    severity="Critical",
    package_name="redis-server",
    installed_version="7.0.11",
    cvss_base_score=9.1,
    is_kev=False,
    epss_score=0.55,
    epss_percentile=0.95,
    risk_score=8.9,
    fix_state="fixed",
    fixed_version="7.0.15",
)


# ---------------------------------------------------------------------------
# Integration fixtures — use a real temp SQLite file; alembic migrations run
# ---------------------------------------------------------------------------


@pytest.fixture
def tmp_db(tmp_path):
    """Real Database backed by a throwaway SQLite file (no migrations run yet)."""
    db_file = tmp_path / "test.db"
    database = Database(f"sqlite:///{db_file}")
    yield database


@pytest.fixture
def integration_client(tmp_path):
    """TestClient with real lifespan (alembic migrations run) against a temp DB.

    DockerWatcher is mocked to return no containers so the scheduler never
    triggers a real Grype scan.
    """
    db_file = tmp_path / "integration.db"
    temp_db = Database(f"sqlite:///{db_file}")
    app.dependency_overrides[production_db.get_session] = temp_db.get_session
    with patch("backend.database.DATABASE_PATH", str(db_file)):
        with patch("backend.main.db", temp_db):
            with patch("backend.routers.vulnerabilities.db", temp_db):
                with patch("backend.routers.containers.db", temp_db):
                    with patch("backend.routers.tasks.db", temp_db):
                        with patch("backend.routers.settings.db", temp_db):
                            with patch("backend.routers.internal.db", temp_db):
                                with patch("backend.jobs.containers.DockerWatcher") as mock_watcher:
                                    mock_watcher.return_value.list_images.return_value = []
                                    with TestClient(app, raise_server_exceptions=True) as client:
                                        yield client, temp_db
    app.dependency_overrides.clear()


# ---------------------------------------------------------------------------
# E2E fixtures — skip automatically when Docker / Grype are unavailable
# ---------------------------------------------------------------------------


@pytest.fixture
def require_docker():
    """Skip the test if Docker daemon is not reachable."""
    try:
        docker_sdk.from_env().ping()
    except Exception:
        pytest.skip("Docker daemon not available")


@pytest.fixture
def require_grype():
    """Skip the test if grype is not on PATH."""
    if shutil.which("grype") is None:
        pytest.skip("grype not on PATH")


@pytest.fixture
def test_container(require_docker):
    """Ensure a known small container is running for E2E tests.

    1. If the 'dg-test' container is already running → use it, leave it running.
    2. Otherwise → start alpine:latest with 'sleep 300', stop it after the test.

    Yields dict: {"image_ref": "alpine:latest", "started_by_fixture": bool}
    """
    client = docker_sdk.from_env()
    test_image = "alpine:latest"
    test_name = "dg-test"

    for container in client.containers.list():
        if container.name == test_name:
            yield {"image_ref": test_image, "started_by_fixture": False}
            return

    try:
        client.images.get(test_image)
    except docker_sdk.errors.ImageNotFound:
        client.images.pull(test_image)

    container = client.containers.run(
        test_image,
        command="sleep 300",
        name=test_name,
        detach=True,
        auto_remove=True,
    )
    yield {"image_ref": test_image, "started_by_fixture": True}
    container.stop()


@pytest.fixture
def e2e_client(tmp_path, require_docker, require_grype):
    """TestClient backed by a temp DB with real Docker and real Grype.

    Scheduler interval is patched to 5 s so the test does not wait a full minute.
    """
    db_file = tmp_path / "e2e.db"
    temp_db = Database(f"sqlite:///{db_file}")
    app.dependency_overrides[production_db.get_session] = temp_db.get_session
    with patch("backend.database.DATABASE_PATH", str(db_file)):
        with patch("backend.main.db", temp_db):
            with patch("backend.routers.vulnerabilities.db", temp_db):
                with patch("backend.routers.containers.db", temp_db):
                    with patch("backend.routers.tasks.db", temp_db):
                        with patch("backend.routers.settings.db", temp_db):
                            with patch("backend.routers.internal.db", temp_db):
                                with patch("backend.scheduler.ConfigManager.get_setting") as mock_get:
                                    mock_get.side_effect = lambda k, s: (
                                        {"value": "5"} if k == "SCAN_INTERVAL_SECONDS" else {"value": "86400"}
                                    )
                                    with TestClient(app, raise_server_exceptions=True) as client:
                                        yield client, temp_db
    app.dependency_overrides.clear()

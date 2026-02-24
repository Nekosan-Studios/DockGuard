import pytest
from fastapi.testclient import TestClient
from sqlalchemy.pool import StaticPool
from sqlmodel import SQLModel, Session, create_engine
from unittest.mock import patch

from api import app
from database import Database, db as production_db
from grype_scanner import _parse_image_repository
from models import Scan, Vulnerability
from datetime import datetime, timezone


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

    with patch("api.DockerWatcher") as mock_watcher_cls:
        mock_watcher_cls.return_value.list_images.return_value = []
        with TestClient(app, raise_server_exceptions=True) as client:
            yield client, test_db, mock_watcher_cls

    app.dependency_overrides.clear()


# ---------------------------------------------------------------------------
# Seed helper — insert a scan + vulnerabilities directly into the test DB
# ---------------------------------------------------------------------------

def seed_scan(database: Database, image_name: str, image_digest: str, vulns: list[dict], scanned_at: datetime | None = None) -> Scan:
    scan = Scan(
        scanned_at=scanned_at or datetime.now(timezone.utc),
        image_name=image_name,
        image_repository=_parse_image_repository(image_name),
        image_digest=image_digest,
        grype_version="0.85.0",
        db_built=datetime(2024, 1, 15, tzinfo=timezone.utc),
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
    vuln_id="CVE-2024-0001", severity="Critical", package_name="libssl",
    installed_version="1.1.1", cvss_base_score=9.8, is_kev=True,
    epss_score=0.94, epss_percentile=0.99, risk_score=9.5,
    fix_state="fixed", fixed_version="1.2.3",
)
VULN_HIGH = dict(
    vuln_id="CVE-2024-0002", severity="High", package_name="curl",
    installed_version="7.88.0", cvss_base_score=7.5, is_kev=False,
    epss_score=0.12, epss_percentile=0.75, risk_score=6.8,
    fix_state="not-fixed", fixed_version=None,
)
VULN_MEDIUM = dict(
    vuln_id="CVE-2024-0003", severity="Medium", package_name="zlib",
    installed_version="1.2.11", cvss_base_score=5.3, is_kev=False,
    epss_score=0.02, epss_percentile=0.40, risk_score=3.1,
    fix_state="fixed", fixed_version="2.0.0",
)
VULN_CRITICAL_2 = dict(
    vuln_id="CVE-2024-0010", severity="Critical", package_name="redis-server",
    installed_version="7.0.11", cvss_base_score=9.1, is_kev=False,
    epss_score=0.55, epss_percentile=0.95, risk_score=8.9,
    fix_state="fixed", fixed_version="7.0.15",
)

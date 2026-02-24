import json
from datetime import datetime, timezone
from subprocess import CompletedProcess
from unittest.mock import MagicMock, patch

import pytest
from sqlmodel import Session, select

from server.grype_scanner import GrypeScanner
from server.models import Scan, Vulnerability
from tests.conftest import seed_scan
from tests.fixtures import GRYPE_JSON_NGINX, GRYPE_JSON_REDIS, MOCK_DOCKER_IMAGES


def _make_scanner(test_db, images=None):
    mock_watcher = MagicMock()
    mock_watcher.list_images.return_value = images if images is not None else MOCK_DOCKER_IMAGES
    return GrypeScanner(watcher=mock_watcher, database=test_db)


def _mock_subprocess(json_payload: dict, returncode: int = 0) -> CompletedProcess:
    return CompletedProcess(
        args=["grype"],
        returncode=returncode,
        stdout=json.dumps(json_payload),
        stderr="",
    )


# ---------------------------------------------------------------------------
# subprocess interaction
# ---------------------------------------------------------------------------

@patch("server.grype_scanner.subprocess.run")
def test_scan_images_calls_subprocess_with_correct_args(mock_run, test_db):
    mock_run.return_value = _mock_subprocess(GRYPE_JSON_NGINX)
    scanner = _make_scanner(test_db, images=[MOCK_DOCKER_IMAGES[0]])  # nginx only
    scanner.scan_images()
    mock_run.assert_called_once_with(
        ["grype", "nginx:latest", "-o", "json", "-q"],
        capture_output=True,
        text=True,
    )


# ---------------------------------------------------------------------------
# Scan persistence
# ---------------------------------------------------------------------------

@patch("server.grype_scanner.subprocess.run")
def test_scan_images_stores_scan_row(mock_run, test_db):
    mock_run.return_value = _mock_subprocess(GRYPE_JSON_NGINX)
    scanner = _make_scanner(test_db, images=[MOCK_DOCKER_IMAGES[0]])
    scanner.scan_images()

    with Session(test_db.engine) as session:
        scan = session.exec(select(Scan)).first()
    assert scan is not None
    assert scan.image_name == "nginx:latest"
    assert scan.image_repository == "nginx"
    assert scan.image_digest == GRYPE_JSON_NGINX["source"]["target"]["imageID"]
    assert scan.grype_version == "0.85.0"
    assert scan.distro_name == "debian"
    assert scan.distro_version == "12"


@patch("server.grype_scanner.subprocess.run")
def test_scan_image_targeted(mock_run, test_db):
    """scan_image() scans a single image by name and grype_ref."""
    mock_run.return_value = _mock_subprocess(GRYPE_JSON_NGINX)
    scanner = _make_scanner(test_db)
    scanner.scan_image("nginx:latest", "nginx:latest")

    mock_run.assert_called_once_with(
        ["grype", "nginx:latest", "-o", "json", "-q"],
        capture_output=True,
        text=True,
    )
    with Session(test_db.engine) as session:
        scan = session.exec(select(Scan)).first()
    assert scan is not None
    assert scan.image_name == "nginx:latest"


@patch("server.grype_scanner.subprocess.run")
def test_scan_images_stores_correct_vulnerability_count(mock_run, test_db):
    mock_run.return_value = _mock_subprocess(GRYPE_JSON_NGINX)
    scanner = _make_scanner(test_db, images=[MOCK_DOCKER_IMAGES[0]])
    scanner.scan_images()

    with Session(test_db.engine) as session:
        vulns = session.exec(select(Vulnerability)).all()
    assert len(vulns) == 3


# ---------------------------------------------------------------------------
# Field parsing
# ---------------------------------------------------------------------------

def test_store_scan_parses_cvss(test_db):
    scanner = _make_scanner(test_db)
    scanner._store_scan(GRYPE_JSON_NGINX, "nginx:latest")

    with Session(test_db.engine) as session:
        vuln = session.exec(select(Vulnerability).where(Vulnerability.vuln_id == "CVE-2024-0001")).first()
    assert vuln.cvss_base_score == 9.8


def test_store_scan_parses_epss(test_db):
    scanner = _make_scanner(test_db)
    scanner._store_scan(GRYPE_JSON_NGINX, "nginx:latest")

    with Session(test_db.engine) as session:
        vuln = session.exec(select(Vulnerability).where(Vulnerability.vuln_id == "CVE-2024-0001")).first()
    assert vuln.epss_score == 0.94
    assert vuln.epss_percentile == 0.99


def test_store_scan_parses_kev_true(test_db):
    scanner = _make_scanner(test_db)
    scanner._store_scan(GRYPE_JSON_NGINX, "nginx:latest")

    with Session(test_db.engine) as session:
        vuln = session.exec(select(Vulnerability).where(Vulnerability.vuln_id == "CVE-2024-0001")).first()
    assert vuln.is_kev is True


def test_store_scan_parses_kev_false(test_db):
    scanner = _make_scanner(test_db)
    scanner._store_scan(GRYPE_JSON_NGINX, "nginx:latest")

    with Session(test_db.engine) as session:
        vuln = session.exec(select(Vulnerability).where(Vulnerability.vuln_id == "CVE-2024-0002")).first()
    assert vuln.is_kev is False


def test_store_scan_parses_cwes_as_comma_separated(test_db):
    scanner = _make_scanner(test_db)
    scanner._store_scan(GRYPE_JSON_NGINX, "nginx:latest")

    with Session(test_db.engine) as session:
        vuln = session.exec(select(Vulnerability).where(Vulnerability.vuln_id == "CVE-2024-0001")).first()
    assert vuln.cwes == "CWE-119,CWE-787"


def test_store_scan_parses_urls_as_comma_separated(test_db):
    scanner = _make_scanner(test_db)
    scanner._store_scan(GRYPE_JSON_NGINX, "nginx:latest")

    with Session(test_db.engine) as session:
        vuln = session.exec(select(Vulnerability).where(Vulnerability.vuln_id == "CVE-2024-0001")).first()
    assert "nvd.nist.gov" in vuln.urls


def test_store_scan_no_vulnerabilities(test_db):
    empty_json = {**GRYPE_JSON_NGINX, "matches": []}
    scanner = _make_scanner(test_db)
    scanner._store_scan(empty_json, "nginx:latest")

    with Session(test_db.engine) as session:
        scan = session.exec(select(Scan)).first()
        vulns = session.exec(select(Vulnerability)).all()
    assert scan is not None
    assert len(vulns) == 0


# ---------------------------------------------------------------------------
# Error handling
# ---------------------------------------------------------------------------

@patch("server.grype_scanner.subprocess.run")
def test_scan_images_grype_error_does_not_store(mock_run, test_db):
    mock_run.return_value = CompletedProcess(
        args=["grype"], returncode=1, stdout="", stderr="grype: command failed"
    )
    scanner = _make_scanner(test_db, images=[MOCK_DOCKER_IMAGES[0]])
    scanner.scan_images()

    with Session(test_db.engine) as session:
        assert session.exec(select(Scan)).first() is None


@patch("server.grype_scanner.subprocess.run")
def test_scan_images_invalid_json_does_not_store(mock_run, test_db):
    mock_run.return_value = CompletedProcess(
        args=["grype"], returncode=0, stdout="not valid json {{{", stderr=""
    )
    scanner = _make_scanner(test_db, images=[MOCK_DOCKER_IMAGES[0]])
    scanner.scan_images()

    with Session(test_db.engine) as session:
        assert session.exec(select(Scan)).first() is None


# ---------------------------------------------------------------------------
# _parse_datetime
# ---------------------------------------------------------------------------

def test_parse_datetime_valid(test_db):
    scanner = _make_scanner(test_db)
    result = scanner._parse_datetime("2024-01-15T00:00:00Z")
    assert isinstance(result, datetime)
    assert result.year == 2024


def test_parse_datetime_none(test_db):
    scanner = _make_scanner(test_db)
    assert scanner._parse_datetime(None) is None

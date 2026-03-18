import json
from copy import deepcopy
from datetime import datetime
from subprocess import CompletedProcess
from unittest.mock import MagicMock, patch

from sqlmodel import Session, select

from backend.grype_scanner import GrypeScanner, _parse_image_repository
from backend.models import Scan, Vulnerability
from backend.tests.fixtures import GRYPE_JSON_NGINX, MOCK_DOCKER_IMAGES


def _make_scanner(test_db, images=None):
    mock_watcher = MagicMock()
    mock_watcher.list_images.return_value = images if images is not None else MOCK_DOCKER_IMAGES
    return GrypeScanner(watcher=mock_watcher, database=test_db, enable_reference_title_fetch=False)


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


@patch("backend.grype_scanner.subprocess.run")
def test_scan_images_calls_subprocess_with_correct_args(mock_run, test_db):
    mock_run.return_value = _mock_subprocess(GRYPE_JSON_NGINX)
    scanner = _make_scanner(test_db, images=[MOCK_DOCKER_IMAGES[0]])  # nginx only
    scanner.scan_images()
    mock_run.assert_called_once_with(
        ["grype", "nginx:latest", "-o", "json"],
        capture_output=True,
        text=True,
    )


# ---------------------------------------------------------------------------
# Scan persistence
# ---------------------------------------------------------------------------


@patch("backend.grype_scanner.subprocess.run")
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


@patch("backend.grype_scanner.subprocess.run")
def test_scan_image_targeted(mock_run, test_db):
    """scan_image() scans a single image by name and grype_ref."""
    mock_run.return_value = _mock_subprocess(GRYPE_JSON_NGINX)
    scanner = _make_scanner(test_db)
    scanner.scan_image("nginx:latest", "nginx:latest")

    mock_run.assert_called_once_with(
        ["grype", "nginx:latest", "-o", "json"],
        capture_output=True,
        text=True,
    )
    with Session(test_db.engine) as session:
        scan = session.exec(select(Scan)).first()
    assert scan is not None
    assert scan.image_name == "nginx:latest"


@patch("backend.grype_scanner.subprocess.run")
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
    assert vuln.cvss_vector == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"


def test_store_scan_parses_indirect_match(test_db):
    scanner = _make_scanner(test_db)
    scanner._store_scan(GRYPE_JSON_NGINX, "nginx:latest")

    with Session(test_db.engine) as session:
        vuln = session.exec(select(Vulnerability).where(Vulnerability.vuln_id == "CVE-2024-0001")).first()
    assert vuln.match_type == "exact-indirect-match"
    assert vuln.upstream_name == "openssl"


def test_store_scan_parses_direct_match(test_db):
    scanner = _make_scanner(test_db)
    scanner._store_scan(GRYPE_JSON_NGINX, "nginx:latest")

    with Session(test_db.engine) as session:
        vuln = session.exec(select(Vulnerability).where(Vulnerability.vuln_id == "CVE-2024-0002")).first()
    assert vuln.match_type == "exact-direct-match"
    assert vuln.upstream_name is None


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


@patch("backend.grype_scanner.fetch_all_titles")
def test_store_scan_persists_reference_titles(mock_fetch_all, test_db):
    mock_fetch_all.return_value = (
        {"https://nvd.nist.gov/vuln/detail/CVE-2024-0001": "NVD title"},
        {},
    )
    scanner = GrypeScanner(watcher=MagicMock(), database=test_db, enable_reference_title_fetch=True)
    scanner._store_scan(GRYPE_JSON_NGINX, "nginx:latest")

    with Session(test_db.engine) as session:
        vuln = session.exec(select(Vulnerability).where(Vulnerability.vuln_id == "CVE-2024-0001")).first()
    assert vuln.urls_titles is not None
    parsed = json.loads(vuln.urls_titles)
    assert parsed["https://nvd.nist.gov/vuln/detail/CVE-2024-0001"] == "NVD title"


@patch("backend.grype_scanner.fetch_all_titles")
def test_store_scan_persists_cwe_titles(mock_fetch_all, test_db):
    mock_fetch_all.return_value = (
        {},
        {
            "CWE-119": "Improper Restriction of Operations within the Bounds of a Memory Buffer",
            "CWE-787": "Out-of-bounds Write",
        },
    )
    scanner = GrypeScanner(watcher=MagicMock(), database=test_db, enable_reference_title_fetch=True)
    scanner._store_scan(GRYPE_JSON_NGINX, "nginx:latest")

    with Session(test_db.engine) as session:
        vuln = session.exec(select(Vulnerability).where(Vulnerability.vuln_id == "CVE-2024-0001")).first()
    assert vuln.cwe_titles is not None
    parsed = json.loads(vuln.cwe_titles)
    assert parsed["CWE-119"].startswith("Improper Restriction")


@patch("backend.grype_scanner.fetch_all_titles")
def test_store_scan_calls_fetch_all_titles_once(mock_fetch_all, test_db):
    """fetch_all_titles must be called exactly once per scan, not per match."""
    mock_fetch_all.return_value = ({}, {})
    scanner = GrypeScanner(watcher=MagicMock(), database=test_db, enable_reference_title_fetch=True)
    scanner._store_scan(GRYPE_JSON_NGINX, "nginx:latest")
    mock_fetch_all.assert_called_once()


def test_store_scan_no_vulnerabilities(test_db):
    empty_json = {**GRYPE_JSON_NGINX, "matches": []}
    scanner = _make_scanner(test_db)
    scanner._store_scan(empty_json, "nginx:latest")

    with Session(test_db.engine) as session:
        scan = session.exec(select(Scan)).first()
        vulns = session.exec(select(Vulnerability)).all()
    assert scan is not None
    assert len(vulns) == 0


def test_store_scan_stitches_first_seen_for_new_tag_with_same_container(test_db):
    scanner = _make_scanner(test_db)
    scanner._store_scan(deepcopy(GRYPE_JSON_NGINX), "nginx:17", container_names=["web"])

    with Session(test_db.engine) as session:
        prior = session.exec(
            select(Vulnerability)
            .join(Scan, Vulnerability.scan_id == Scan.id)
            .where(Scan.image_name == "nginx:17")
            .where(Vulnerability.vuln_id == "CVE-2024-0001")
        ).first()
    assert prior is not None
    assert prior.first_seen_at is not None
    prior_first_seen = prior.first_seen_at

    scanner._store_scan(deepcopy(GRYPE_JSON_NGINX), "nginx:18", container_names=["web"])

    with Session(test_db.engine) as session:
        stitched = session.exec(
            select(Vulnerability)
            .join(Scan, Vulnerability.scan_id == Scan.id)
            .where(Scan.image_name == "nginx:18")
            .where(Vulnerability.vuln_id == "CVE-2024-0001")
        ).first()
    assert stitched is not None
    assert stitched.first_seen_at == prior_first_seen


def test_store_scan_container_rename_breaks_stitching(test_db):
    scanner = _make_scanner(test_db)
    scanner._store_scan(deepcopy(GRYPE_JSON_NGINX), "nginx:17", container_names=["web-old"])
    scanner._store_scan(deepcopy(GRYPE_JSON_NGINX), "nginx:18", container_names=["web-new"])

    with Session(test_db.engine) as session:
        scan = session.exec(select(Scan).where(Scan.image_name == "nginx:18").order_by(Scan.id.desc())).first()
        assert scan is not None
        vuln = session.exec(
            select(Vulnerability)
            .where(Vulnerability.scan_id == scan.id)
            .where(Vulnerability.vuln_id == "CVE-2024-0001")
        ).first()
    assert vuln is not None
    assert vuln.first_seen_at == scan.scanned_at


def test_store_scan_does_not_stitch_across_different_repository(test_db):
    scanner = _make_scanner(test_db)
    scanner._store_scan(deepcopy(GRYPE_JSON_NGINX), "nginx:17", container_names=["web"])
    scanner._store_scan(deepcopy(GRYPE_JSON_NGINX), "redis:7", container_names=["web"])

    with Session(test_db.engine) as session:
        redis_scan = session.exec(select(Scan).where(Scan.image_name == "redis:7").order_by(Scan.id.desc())).first()
        assert redis_scan is not None
        redis_vuln = session.exec(
            select(Vulnerability)
            .where(Vulnerability.scan_id == redis_scan.id)
            .where(Vulnerability.vuln_id == "CVE-2024-0001")
        ).first()
    assert redis_vuln is not None
    assert redis_vuln.first_seen_at == redis_scan.scanned_at


# ---------------------------------------------------------------------------
# Error handling
# ---------------------------------------------------------------------------


@patch("backend.grype_scanner.subprocess.run")
def test_scan_images_grype_error_does_not_store(mock_run, test_db):
    mock_run.return_value = CompletedProcess(args=["grype"], returncode=1, stdout="", stderr="grype: command failed")
    scanner = _make_scanner(test_db, images=[MOCK_DOCKER_IMAGES[0]])
    scanner.scan_images()

    with Session(test_db.engine) as session:
        assert session.exec(select(Scan)).first() is None


@patch("backend.grype_scanner.subprocess.run")
def test_scan_images_invalid_json_does_not_store(mock_run, test_db):
    mock_run.return_value = CompletedProcess(args=["grype"], returncode=0, stdout="not valid json {{{", stderr="")
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


def test_parse_datetime_go_zero_time(test_db):
    scanner = _make_scanner(test_db)
    # Go emits 0001-01-01T00:00:00Z when DB is uninitialised; treat as absent
    assert scanner._parse_datetime("0001-01-01T00:00:00Z") is None


def test_parse_datetime_invalid_string(test_db):
    scanner = _make_scanner(test_db)
    assert scanner._parse_datetime("not-a-date") is None


# ---------------------------------------------------------------------------
# _parse_image_repository
# ---------------------------------------------------------------------------


def test_parse_image_repository_simple_tag():
    assert _parse_image_repository("nginx:latest") == "nginx"


def test_parse_image_repository_no_tag():
    assert _parse_image_repository("nginx") == "nginx"


def test_parse_image_repository_full_ref_with_tag():
    assert _parse_image_repository("ghcr.io/owner/repo:tag") == "ghcr.io/owner/repo"


def test_parse_image_repository_registry_with_port_no_tag():
    # Last colon is the port separator; remainder contains '/' so tag is absent
    assert _parse_image_repository("registry.com:5000/nginx") == "registry.com:5000/nginx"


def test_parse_image_repository_registry_with_port_and_tag():
    assert _parse_image_repository("myregistry.com:5000/nginx:latest") == "myregistry.com:5000/nginx"

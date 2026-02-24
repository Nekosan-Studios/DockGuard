import json
import logging
import subprocess
from datetime import datetime, timezone

from sqlmodel import Session

from .database import Database, db
from .docker_watcher import DockerWatcher
from .models import Scan, Vulnerability

logger = logging.getLogger(__name__)


def _parse_image_repository(image_ref: str) -> str:
    """Extract repository from image_ref by stripping the tag.

    Examples:
        'nginx:latest'                    -> 'nginx'
        'ghcr.io/owner/repo:tag'          -> 'ghcr.io/owner/repo'
        'myregistry.com:5000/nginx:latest' -> 'myregistry.com:5000/nginx'
        'nginx'                           -> 'nginx'
    """
    last_colon = image_ref.rfind(":")
    if last_colon == -1:
        return image_ref
    if "/" not in image_ref[last_colon + 1:]:
        return image_ref[:last_colon]
    return image_ref


class GrypeScanner:

    def __init__(self, watcher: DockerWatcher | None, database: Database):
        self.watcher = watcher
        self.db = database

    def scan_images(self):
        images = self.watcher.list_images()

        if not images:
            logger.info("No images found to scan.")
            return

        for image in images:
            self.scan_image(image["name"], image["grype_ref"])

    def scan_image(self, image_name: str, grype_ref: str) -> None:
        """Scan a single image and persist results to the database."""
        logger.info("Scanning %s", image_name)
        result = subprocess.run(
            ["grype", grype_ref, "-o", "json", "-q"],
            capture_output=True,
            text=True,
        )

        if result.returncode != 0:
            logger.error("Grype error for %s: %s", image_name, result.stderr.strip())
            return

        try:
            grype_json = json.loads(result.stdout)
        except json.JSONDecodeError as e:
            logger.error("Failed to parse Grype JSON for %s: %s", image_name, e)
            return

        self._store_scan(grype_json, image_name)

    def _store_scan(self, grype_json: dict, image_name: str) -> None:
        source = grype_json.get("source", {})
        target = source.get("target", {})
        distro = grype_json.get("distro", {})
        descriptor = grype_json.get("descriptor", {})
        db_info = descriptor.get("db", {})

        scan = Scan(
            scanned_at=datetime.now(timezone.utc),
            image_name=image_name,
            image_repository=_parse_image_repository(image_name),
            image_digest=target.get("imageID", ""),
            grype_version=descriptor.get("version", ""),
            db_built=self._parse_datetime(db_info.get("built")),
            distro_name=distro.get("name") or None,
            distro_version=distro.get("version") or None,
        )

        vulnerabilities = []
        for match in grype_json.get("matches", []):
            vuln = match.get("vulnerability", {})
            artifact = match.get("artifact", {})
            fix = vuln.get("fix", {})

            cvss_list = vuln.get("cvss", [])
            cvss_base_score = None
            if cvss_list:
                cvss_base_score = cvss_list[0].get("metrics", {}).get("baseScore")

            epss_list = vuln.get("epss", [])
            epss_score = None
            epss_percentile = None
            if epss_list:
                epss_score = epss_list[0].get("epss")
                epss_percentile = epss_list[0].get("percentile")

            cwes_list = vuln.get("cwes", [])
            cwes = ",".join(c.get("cwe", "") for c in cwes_list) if cwes_list else None

            urls_list = vuln.get("urls", [])
            urls = ",".join(urls_list) if urls_list else None

            fix_versions = fix.get("versions", [])
            fixed_version = fix_versions[0] if fix_versions else None

            vulnerabilities.append(Vulnerability(
                vuln_id=vuln.get("id", ""),
                severity=vuln.get("severity", ""),
                description=vuln.get("description") or None,
                data_source=vuln.get("dataSource") or None,
                urls=urls,
                cvss_base_score=cvss_base_score,
                epss_score=epss_score,
                epss_percentile=epss_percentile,
                is_kev=bool(vuln.get("knownExploited")),
                risk_score=vuln.get("risk"),
                cwes=cwes,
                package_name=artifact.get("name", ""),
                installed_version=artifact.get("version", ""),
                fixed_version=fixed_version,
                fix_state=fix.get("state") or None,
                package_type=artifact.get("type") or None,
                package_language=artifact.get("language") or None,
                purl=artifact.get("purl") or None,
            ))

        with Session(self.db.engine) as session:
            session.add(scan)
            session.flush()
            for v in vulnerabilities:
                v.scan_id = scan.id
                session.add(v)
            session.commit()
            logger.info("Stored scan id=%s for %s with %d vulnerabilities", scan.id, image_name, len(vulnerabilities))

    def _parse_datetime(self, value: str | None) -> datetime | None:
        if not value:
            return None
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)-8s %(name)s - %(message)s")
    db.init()  # runs alembic upgrade head
    scanner = GrypeScanner(watcher=DockerWatcher(), database=db)
    scanner.scan_images()

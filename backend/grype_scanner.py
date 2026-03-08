import json
import logging
import subprocess
from datetime import datetime, timezone

from sqlmodel import Session, func, select

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

    def scan_image(self, image_name: str, grype_ref: str, container_name: str | None = None) -> None:
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

        self._store_scan(grype_json, image_name, container_name)

    def _store_scan(self, grype_json: dict, image_name: str, container_name: str | None = None) -> None:
        source = grype_json.get("source", {})
        target = source.get("target", {})
        distro = grype_json.get("distro", {})
        descriptor = grype_json.get("descriptor", {})
        db_info = descriptor.get("db", {})
        # Grype v6+ nests the built date under db.status; fall back to db.built for older versions.
        db_status = db_info.get("status", db_info)

        image_repository = _parse_image_repository(image_name)
        scanned_at = datetime.now(timezone.utc)
        
        # Check if any package has a distro-eol alert
        distro_eol = any(
            any(alert.get("type") == "distro-eol" for alert in pkg.get("alerts", []))
            for pkg in grype_json.get("alertsByPackage", [])
        )

        scan = Scan(
            scanned_at=scanned_at,
            image_name=image_name,
            image_repository=image_repository,
            image_digest=target.get("imageID", ""),
            grype_version=descriptor.get("version", ""),
            db_built=self._parse_datetime(db_status.get("built")),
            distro_name=distro.get("name") or None,
            distro_version=distro.get("version") or None,
            is_distro_eol=distro_eol,
            container_name=container_name,
        )

        with Session(self.db.engine) as session:
            # Build lookup: (vuln_id, package_name, installed_version) -> earliest first_seen_at
            # scoped to this image_repository so "new" is per-repo not per-tag.
            existing_rows = session.exec(
                select(
                    Vulnerability.vuln_id,
                    Vulnerability.package_name,
                    Vulnerability.installed_version,
                    func.min(Vulnerability.first_seen_at),
                )
                .join(Scan, Vulnerability.scan_id == Scan.id)
                .where(Scan.image_repository == image_repository)
                .group_by(
                    Vulnerability.vuln_id,
                    Vulnerability.package_name,
                    Vulnerability.installed_version,
                )
            ).all()
            first_seen_map: dict[tuple[str, str, str], datetime] = {
                (r[0], r[1], r[2]): r[3] for r in existing_rows if r[3] is not None
            }

            # Use a dict keyed by (vuln_id, package_name, installed_version) to
            # deduplicate: grype reports the same CVE+package multiple times when
            # the package is found in more than one filesystem location.  We
            # consolidate those matches into a single row, merging locations.
            vuln_map: dict[tuple[str, str, str], Vulnerability] = {}
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

                vuln_id = vuln.get("id", "")
                package_name = artifact.get("name", "")
                installed_version = artifact.get("version", "")
                key = (vuln_id, package_name, installed_version)

                new_locs = [
                    loc["path"] for loc in artifact.get("locations", []) if loc.get("path")
                ]

                if key in vuln_map:
                    # Merge locations into the existing row
                    existing = vuln_map[key]
                    existing_locs = existing.locations.split("\n") if existing.locations else []
                    merged = existing_locs + [p for p in new_locs if p not in existing_locs]
                    existing.locations = "\n".join(merged) or None
                else:
                    vuln_map[key] = Vulnerability(
                        vuln_id=vuln_id,
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
                        package_name=package_name,
                        installed_version=installed_version,
                        fixed_version=fixed_version,
                        fix_state=fix.get("state") or None,
                        package_type=artifact.get("type") or None,
                        package_language=artifact.get("language") or None,
                        purl=artifact.get("purl") or None,
                        locations="\n".join(new_locs) or None,
                        first_seen_at=first_seen_map.get(key, scanned_at),
                    )
            vulnerabilities = list(vuln_map.values())

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
            dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
            # Grype emits the Go zero time (0001-01-01T00:00:00Z) when the DB
            # is not yet initialised.  Treat it as absent rather than storing a
            # nonsensical date that the frontend renders as "Dec 31, 0001".
            if dt.year == 1:
                return None
            return dt
        except ValueError:
            return None


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)-8s %(name)s - %(message)s")
    db.init()  # runs alembic upgrade head
    scanner = GrypeScanner(watcher=DockerWatcher(), database=db)
    scanner.scan_images()

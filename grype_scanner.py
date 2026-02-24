import json
import subprocess
from datetime import datetime, timezone

from sqlmodel import Session

from database import Database, db
from docker_watcher import DockerWatcher
from models import Scan, Vulnerability


class GrypeScanner:

    def __init__(self, watcher: DockerWatcher, database: Database):
        self.watcher = watcher
        self.db = database

    def scan_images(self):
        images = self.watcher.list_images()

        if not images:
            print("No images found to scan.")
            return

        for image in images:
            name = image["name"]
            ref = image["grype_ref"]

            print(f"--- Launching Grype scan for: {name} ({image['hash']}) ---")
            result = subprocess.run(
                ["grype", ref, "-o", "json", "-q"],
                capture_output=True,
                text=True,
            )
            print(f"--- Grype scan complete for: {name} ---")

            if result.returncode != 0:
                print(f"    Grype error: {result.stderr.strip()}")
                continue

            try:
                grype_json = json.loads(result.stdout)
            except json.JSONDecodeError as e:
                print(f"    Failed to parse Grype JSON output: {e}")
                continue

            self._store_scan(grype_json, name)
            print()

    def _store_scan(self, grype_json: dict, image_name: str) -> None:
        source = grype_json.get("source", {})
        target = source.get("target", {})
        distro = grype_json.get("distro", {})
        descriptor = grype_json.get("descriptor", {})
        db_info = descriptor.get("db", {})

        scan = Scan(
            scanned_at=datetime.now(timezone.utc),
            image_name=image_name,
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
            print(f"    Stored scan id={scan.id} with {len(vulnerabilities)} vulnerabilities.")

    def _parse_datetime(self, value: str | None) -> datetime | None:
        if not value:
            return None
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None


if __name__ == "__main__":
    db.init()  # runs alembic upgrade head
    scanner = GrypeScanner(watcher=DockerWatcher(), database=db)
    scanner.scan_images()

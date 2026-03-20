import asyncio
import json
import logging
import re
import subprocess
import time
from datetime import UTC, datetime

from sqlmodel import Session, func, select

from .api_helpers import _fmt_duration
from .database import Database, db
from .docker_watcher import DockerWatcher
from .models import Scan, ScanContainer, SystemTask, Vulnerability
from .reference_titles import fetch_all_titles
from .vex_discovery import check_vex_for_image

logger = logging.getLogger(__name__)

_ANSI_ESCAPE = re.compile(r"\x1b\[[0-9;]*m")
_GRYPE_LOG_PREFIX = re.compile(r"^\[\d+\]\s+\w+\s+")

_PROGRESS_PHASES = [
    (re.compile(r"load.*db|vulnerability.*db|updating.*db", re.I), "Loading vulnerability database"),
    (re.compile(r"catalog|index.*file|index.*layer", re.I), "Cataloging packages"),
    (re.compile(r"match.*vuln|finding.*vuln", re.I), "Matching vulnerabilities"),
]


def _parse_progress_line(raw: str) -> str | None:
    """Return a user-friendly phase label from a raw grype stderr line, or None to discard."""
    line = _ANSI_ESCAPE.sub("", raw).strip()
    line = _GRYPE_LOG_PREFIX.sub("", line).strip()
    if not line:
        return None
    for pattern, label in _PROGRESS_PHASES:
        if pattern.search(line):
            return label
    return None


def _grype_user_message(error_text: str) -> str:
    """Return a short, user-friendly message from grype's verbose error output."""
    if "TOOMANYREQUESTS" in error_text:
        return "Registry rate limit reached — please try again later."
    first_line = _GRYPE_LOG_PREFIX.sub("", error_text.splitlines()[0]).strip()
    return first_line or error_text


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
    if "/" not in image_ref[last_colon + 1 :]:
        return image_ref[:last_colon]
    return image_ref


class GrypeScanner:
    def __init__(self, watcher: DockerWatcher | None, database: Database, enable_reference_title_fetch: bool = True):
        self.watcher = watcher
        self.db = database
        self.enable_reference_title_fetch = enable_reference_title_fetch

    def scan_images(self):
        images = self.watcher.list_images()

        if not images:
            logger.info("No images found to scan.")
            return

        for image in images:
            try:
                self.scan_image(image["name"], image["grype_ref"])
            except Exception:
                logger.exception("Failed to scan image %s", image["name"])

    async def scan_image_async(
        self,
        image_name: str,
        grype_ref: str,
        semaphore: asyncio.Semaphore,
        container_names: list[str] | None = None,
        task_id: int | None = None,
        is_update_check: bool = False,
        is_preview: bool = False,
    ) -> None:
        """Run a Grype scan asynchronously to avoid blocking the event loop."""
        async with semaphore:
            if task_id:
                with Session(self.db.engine) as session:
                    task = session.get(SystemTask, task_id)
                    if task:
                        task.status = "running"
                        task.started_at = datetime.now(UTC)
                        session.add(task)
                        session.commit()

            await asyncio.to_thread(
                self.scan_image_sync, image_name, grype_ref, container_names, task_id, is_update_check, is_preview
            )

    async def scan_image_streaming_async(
        self,
        image_name: str,
        grype_ref: str,
        semaphore: asyncio.Semaphore,
        task_id: int,
        progress_store: dict[int, list[str]],
        skip_enrichments: bool = False,
    ) -> None:
        """Streaming async scan for preview scans — supports cancellation and progress reporting."""
        async with semaphore:
            with Session(self.db.engine) as session:
                task = session.get(SystemTask, task_id)
                if task:
                    task.status = "running"
                    task.started_at = datetime.now(UTC)
                    session.add(task)
                    session.commit()

            proc = None
            stderr_buffer: list[str] = []
            try:
                proc = await asyncio.create_subprocess_exec(
                    "grype",
                    grype_ref,
                    "-o",
                    "json",
                    "-v",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )

                async def _read_stderr() -> None:
                    assert proc.stderr is not None
                    while True:
                        line = await proc.stderr.readline()
                        if not line:
                            break
                        decoded = line.decode(errors="replace")
                        stderr_buffer.append(decoded)
                        label = _parse_progress_line(decoded)
                        if label:
                            current = progress_store.get(task_id, [])
                            if not current or current[-1] != label:
                                current.append(label)
                                progress_store[task_id] = current

                async def _read_stdout() -> bytes:
                    assert proc.stdout is not None
                    return await proc.stdout.read()

                try:
                    results = await asyncio.wait_for(
                        asyncio.gather(_read_stderr(), _read_stdout()),
                        timeout=300,
                    )
                except TimeoutError:
                    proc.kill()
                    await proc.wait()
                    raise RuntimeError(f"Scan timed out after 5 minutes for {image_name}")

                stdout_data: bytes = results[1]
                await proc.wait()

                if proc.returncode != 0:
                    error_text = _ANSI_ESCAPE.sub("", "".join(stderr_buffer)).strip()
                    if not error_text:
                        error_text = (
                            _ANSI_ESCAPE.sub("", stdout_data.decode(errors="replace")).strip() or "unknown error"
                        )
                    logger.error("Grype error for %s:\n%s", image_name, error_text)
                    raise RuntimeError(_grype_user_message(error_text))

                try:
                    grype_json = json.loads(stdout_data.decode())
                except json.JSONDecodeError as e:
                    logger.error("Failed to parse Grype JSON for %s: %s", image_name, e)
                    raise

                self._store_scan(grype_json, image_name, None, is_preview=True, skip_enrichments=skip_enrichments)

                with Session(self.db.engine) as session:
                    task = session.get(SystemTask, task_id)
                    if task:
                        task.status = "completed"
                        task.finished_at = datetime.now(UTC)
                        task.result_details = f"Scanned image {image_name} successfully."
                        session.add(task)
                        session.commit()

            except asyncio.CancelledError:
                if proc is not None:
                    proc.kill()
                    await proc.wait()
                with Session(self.db.engine) as session:
                    task = session.get(SystemTask, task_id)
                    if task:
                        task.status = "failed"
                        task.finished_at = datetime.now(UTC)
                        task.error_message = "Scan cancelled"
                        session.add(task)
                        session.commit()
                raise

            except Exception as e:
                logger.exception("Error scanning image %s", image_name)
                with Session(self.db.engine) as session:
                    task = session.get(SystemTask, task_id)
                    if task:
                        task.status = "failed"
                        task.finished_at = datetime.now(UTC)
                        task.error_message = str(e)
                        session.add(task)
                        session.commit()

    def scan_image_sync(
        self,
        image_name: str,
        grype_ref: str,
        container_names: list[str] | None = None,
        task_id: int | None = None,
        is_update_check: bool = False,
        is_preview: bool = False,
    ) -> None:
        """Scan a single image, check VEX, and update the task status."""
        t0 = time.perf_counter()
        try:
            self.scan_image(
                image_name, grype_ref, container_names, is_update_check=is_update_check, is_preview=is_preview
            )
            if not is_update_check and not is_preview:
                self._check_vex_for_latest_scan(image_name)

            elapsed = time.perf_counter() - t0
            logger.info("Scan completed: %s in %s", image_name, _fmt_duration(elapsed))

            if task_id:
                with Session(self.db.engine) as session:
                    task = session.get(SystemTask, task_id)
                    if task:
                        task.status = "completed"
                        task.finished_at = datetime.now(UTC)
                        affected = len(container_names or [])
                        if affected:
                            task.result_details = (
                                f"Scanned image {image_name}; captured {affected} affected container(s)."
                                f" ({_fmt_duration(elapsed)})"
                            )
                        else:
                            task.result_details = f"Scanned image {image_name} successfully. ({_fmt_duration(elapsed)})"
                        session.add(task)
                        session.commit()
        except Exception as e:
            logger.exception("Error scanning image %s", image_name)
            if task_id:
                with Session(self.db.engine) as session:
                    task = session.get(SystemTask, task_id)
                    if task:
                        task.status = "failed"
                        task.finished_at = datetime.now(UTC)
                        task.error_message = str(e)
                        session.add(task)
                        session.commit()

    def scan_image(
        self,
        image_name: str,
        grype_ref: str,
        container_names: list[str] | None = None,
        is_update_check: bool = False,
        is_preview: bool = False,
    ) -> None:
        """Execute the grype CLI specifically and persist results to the database."""
        logger.info("Scanning %s", image_name)
        try:
            result = subprocess.run(
                ["grype", grype_ref, "-o", "json"],
                capture_output=True,
                text=True,
                timeout=300,
            )
        except subprocess.TimeoutExpired:
            logger.error("Grype timed out after 300s for %s", image_name)
            raise RuntimeError(f"Scan timed out after 5 minutes for {image_name}")

        if result.returncode != 0:
            # Grype writes errors to stderr; strip ANSI colour codes before logging.
            error_text = _ANSI_ESCAPE.sub("", result.stderr).strip()
            if not error_text:
                error_text = _ANSI_ESCAPE.sub("", result.stdout).strip() or "unknown error"
            logger.error("Grype error for %s:\n%s", image_name, error_text)
            raise RuntimeError(_grype_user_message(error_text))

        try:
            grype_json = json.loads(result.stdout)
        except json.JSONDecodeError as e:
            logger.error("Failed to parse Grype JSON for %s: %s", image_name, e)
            raise

        self._store_scan(
            grype_json, image_name, container_names, is_update_check=is_update_check, is_preview=is_preview
        )

    def _store_scan(
        self,
        grype_json: dict,
        image_name: str,
        container_names: list[str] | None = None,
        is_update_check: bool = False,
        is_preview: bool = False,
        skip_enrichments: bool = False,
    ) -> None:
        source = grype_json.get("source", {})
        target = source.get("target", {})
        distro = grype_json.get("distro", {})
        descriptor = grype_json.get("descriptor", {})
        db_info = descriptor.get("db", {})
        # Grype v6+ nests the built date under db.status; fall back to db.built for older versions.
        db_status = db_info.get("status", db_info)

        image_repository = _parse_image_repository(image_name)
        scanned_at = datetime.now(UTC)

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
            is_update_check=is_update_check,
            is_preview=is_preview,
        )

        normalised_container_names = sorted({name for name in (container_names or []) if name})

        with Session(self.db.engine) as session:
            # Build lookup: (vuln_id, package_name, installed_version) -> earliest first_seen_at
            # scoped to this image_name lineage.
            existing_rows = session.exec(
                select(
                    Vulnerability.vuln_id,
                    Vulnerability.package_name,
                    Vulnerability.installed_version,
                    func.min(Vulnerability.first_seen_at),
                )
                .join(Scan, Vulnerability.scan_id == Scan.id)
                .where(Scan.image_name == image_name)
                .where(Scan.is_update_check == False)  # noqa: E712
                .where(Scan.is_preview == False)  # noqa: E712
                .group_by(
                    Vulnerability.vuln_id,
                    Vulnerability.package_name,
                    Vulnerability.installed_version,
                )
            ).all()
            first_seen_map: dict[tuple[str, str, str], datetime] = {
                (r[0], r[1], r[2]): r[3] for r in existing_rows if r[3] is not None
            }

            # Best-effort lineage stitching for first scan of a new image_name.
            # If this image_name has no prior vulnerability history, inherit
            # first_seen_at from prior scans in the same repository where at
            # least one scan-time container name overlaps.
            #
            # Tradeoff: container names can change in compose/docker and will
            # break this continuity; this is intentional and acceptable.
            if not first_seen_map and normalised_container_names:
                inherited_rows = session.exec(
                    select(
                        Vulnerability.vuln_id,
                        Vulnerability.package_name,
                        Vulnerability.installed_version,
                        func.min(Vulnerability.first_seen_at),
                    )
                    .join(Scan, Vulnerability.scan_id == Scan.id)
                    .join(ScanContainer, ScanContainer.scan_id == Scan.id)
                    .where(Scan.image_repository == image_repository)
                    .where(Scan.image_name != image_name)
                    .where(Scan.is_preview == False)  # noqa: E712
                    .where(ScanContainer.container_name.in_(normalised_container_names))
                    .group_by(
                        Vulnerability.vuln_id,
                        Vulnerability.package_name,
                        Vulnerability.installed_version,
                    )
                ).all()
                for vuln_id, package_name, installed_version, earliest_first_seen in inherited_rows:
                    if earliest_first_seen is None:
                        continue
                    key = (vuln_id, package_name, installed_version)
                    existing_first_seen = first_seen_map.get(key)
                    if existing_first_seen is None:
                        first_seen_map[key] = earliest_first_seen
                    else:
                        first_seen_map[key] = min(existing_first_seen, earliest_first_seen)

            # Fetch all reference titles and CWE names in one pass before the
            # match loop, deduplicating across all vulnerabilities and applying
            # a single global time budget.
            scan_url_titles: dict[str, str] = {}
            scan_cwe_titles: dict[str, str] = {}
            if self.enable_reference_title_fetch and not skip_enrichments:
                all_match_urls = (
                    url for m in grype_json.get("matches", []) for url in m.get("vulnerability", {}).get("urls", [])
                )
                all_match_cwes = (
                    c.get("cwe", "")
                    for m in grype_json.get("matches", [])
                    for c in m.get("vulnerability", {}).get("cwes", [])
                    if c.get("cwe")
                )
                scan_url_titles, scan_cwe_titles = fetch_all_titles(all_match_urls, all_match_cwes)

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
                cvss_vector = None
                if cvss_list:
                    cvss_base_score = cvss_list[0].get("metrics", {}).get("baseScore")
                    cvss_vector = cvss_list[0].get("vector") or None

                epss_list = vuln.get("epss", [])
                epss_score = None
                epss_percentile = None
                if epss_list:
                    epss_score = epss_list[0].get("epss")
                    epss_percentile = epss_list[0].get("percentile")

                cwes_list = vuln.get("cwes", [])
                cwes = ",".join(c.get("cwe", "") for c in cwes_list) if cwes_list else None
                cwe_titles = None
                if cwes_list:
                    cwe_ids = [c.get("cwe", "") for c in cwes_list if c.get("cwe")]
                    cwe_title_map = {cid: scan_cwe_titles[cid] for cid in cwe_ids if cid in scan_cwe_titles}
                    if cwe_title_map:
                        cwe_titles = json.dumps(cwe_title_map, ensure_ascii=False)

                urls_list = vuln.get("urls", [])
                urls = ",".join(urls_list) if urls_list else None
                urls_titles = None
                if urls_list:
                    url_title_map = {u: scan_url_titles[u] for u in urls_list if u in scan_url_titles}
                    if url_title_map:
                        urls_titles = json.dumps(url_title_map, ensure_ascii=False)

                fix_versions = fix.get("versions", [])
                fixed_version = fix_versions[0] if fix_versions else None

                vuln_id = vuln.get("id", "")
                package_name = artifact.get("name", "")
                installed_version = artifact.get("version", "")
                key = (vuln_id, package_name, installed_version)

                match_details = match.get("matchDetails", [])
                match_type = match_details[0].get("type") or None if match_details else None
                upstreams = artifact.get("upstreams", [])
                upstream_name = upstreams[0].get("name") or None if upstreams else None

                new_locs = [loc["path"] for loc in artifact.get("locations", []) if loc.get("path")]

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
                        urls_titles=urls_titles,
                        cvss_base_score=cvss_base_score,
                        cvss_vector=cvss_vector,
                        epss_score=epss_score,
                        epss_percentile=epss_percentile,
                        is_kev=bool(vuln.get("knownExploited")),
                        risk_score=vuln.get("risk"),
                        cwes=cwes,
                        cwe_titles=cwe_titles,
                        package_name=package_name,
                        installed_version=installed_version,
                        fixed_version=fixed_version,
                        fix_state=fix.get("state") or None,
                        package_type=artifact.get("type") or None,
                        package_language=artifact.get("language") or None,
                        purl=artifact.get("purl") or None,
                        locations="\n".join(new_locs) or None,
                        first_seen_at=first_seen_map.get(key, scanned_at),
                        match_type=match_type,
                        upstream_name=upstream_name,
                    )
            vulnerabilities = list(vuln_map.values())

            session.add(scan)
            session.flush()
            for container_name in normalised_container_names:
                session.add(ScanContainer(scan_id=scan.id, container_name=container_name))
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

    def _resolve_repo_digest(self, image_name: str, config_digest: str) -> str:
        """Resolve the OCI manifest digest for an image from Docker's repo digests."""
        try:
            if not self.watcher or not self.watcher.client:
                # instantiate a new one if watcher is not tied to the instance
                watcher = DockerWatcher()
            else:
                watcher = self.watcher

            if not watcher.client:
                return config_digest

            image = watcher.client.images.get(image_name)
            for rd in image.attrs.get("RepoDigests", []):
                if rd.startswith(image_name.split(":")[0]):
                    return rd.split("@", 1)[1]
            if image.attrs.get("RepoDigests"):
                return image.attrs["RepoDigests"][0].split("@", 1)[1]
        except Exception as e:
            logger.warning("Could not resolve repo digest for %s: %s", image_name, e)
        return config_digest

    def _check_vex_for_latest_scan(self, image_name: str) -> None:
        """Check for VEX attestations and apply to the latest scan's vulnerabilities."""
        try:
            with Session(self.db.engine) as session:
                scan = session.exec(
                    select(Scan).where(Scan.image_name == image_name).order_by(Scan.scanned_at.desc())
                ).first()
                if not scan:
                    return

                digest = self._resolve_repo_digest(image_name, scan.image_digest)
                vex_result = check_vex_for_image(image_name, digest)
                now = datetime.now(UTC)

                if vex_result.error:
                    scan.vex_status = "error"
                    scan.vex_error = vex_result.error
                    scan.vex_checked_at = now
                    logger.warning("VEX check error for %s: %s", image_name, vex_result.error)
                elif vex_result.found:
                    scan.vex_status = "found"
                    scan.vex_source = vex_result.source
                    scan.vex_checked_at = now
                    vulns = session.exec(select(Vulnerability).where(Vulnerability.scan_id == scan.id)).all()
                    stmt_map = {s.vuln_id: s for s in vex_result.statements}
                    matched = 0
                    for v in vulns:
                        vex_stmt = stmt_map.get(v.vuln_id)
                        if vex_stmt:
                            v.vex_status = vex_stmt.status
                            v.vex_justification = vex_stmt.justification
                            v.vex_statement = vex_stmt.notes
                            session.add(v)
                            matched += 1
                    logger.info(
                        "VEX found for %s: %d statements, %d matched vulns",
                        image_name,
                        len(vex_result.statements),
                        matched,
                    )
                else:
                    scan.vex_status = "none"
                    scan.vex_checked_at = now

                session.add(scan)
                session.commit()
        except Exception:
            logger.exception("Error checking VEX for %s", image_name)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)-8s %(name)s - %(message)s")
    db.init()  # runs alembic upgrade head
    scanner = GrypeScanner(watcher=DockerWatcher(), database=db)
    scanner.scan_images()

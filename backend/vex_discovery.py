"""OCI registry VEX discovery.

Checks whether an image has VEX (Vulnerability Exploitability eXchange)
attestations attached via the OCI Referrers API.  No external binaries
(cosign, etc.) are required — we speak HTTP directly to the registry.
"""

import base64
import json
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path

import httpx

logger = logging.getLogger(__name__)

_TIMEOUT = 10  # seconds, total per image
_VEX_ARTIFACT_TYPES = {
    "application/vex+json",
    "application/openvex+json",
}
_VEX_PREDICATE_TYPES = {
    "https://openvex.dev/ns/v0.2.0",
    "https://openvex.dev/ns",
    "cosign.sigstore.dev/attestation/vuln/v1",
}
# Sigstore bundles and generic in-toto attestations may contain VEX — fetch and inspect.
_SIGSTORE_BUNDLE_TYPES = {
    "application/vnd.dev.sigstore.bundle.v0.3+json",
    "application/vnd.dev.sigstore.bundle+json;version=0.3",
    # Generic in-toto media type used by cosign when pushing via OCI referrers API;
    # the predicate type is only known after fetching the blob.
    "application/vnd.in-toto+json",
}
_OCI_INDEX_MEDIA = "application/vnd.oci.image.index.v1+json"


def _b64decode(data: str) -> bytes:
    """Decode standard base64 or base64url, tolerating missing padding.

    Some tools (newer Sigstore releases, some CI actions) emit base64url
    (RFC 4648 §5: ``-`` and ``_`` instead of ``+`` and ``/``).  Python's
    stdlib ``base64.b64decode`` rejects those characters unless told
    otherwise, and also requires correct ``=`` padding which is often
    omitted.  This helper normalises both before decoding.
    """
    # Translate url-safe alphabet to standard alphabet
    data = data.strip().replace("-", "+").replace("_", "/")
    # Re-pad to the next multiple of 4
    remainder = len(data) % 4
    if remainder:
        data += "=" * (4 - remainder)
    return base64.b64decode(data)


@dataclass
class VexStatement:
    vuln_id: str
    status: str  # "not_affected", "affected", "fixed", "under_investigation"
    justification: str | None = None
    notes: str | None = None


@dataclass
class VexResult:
    found: bool = False
    statements: list[VexStatement] = field(default_factory=list)
    source: str = ""
    error: str | None = None


def _parse_image_ref(image_name: str) -> tuple[str, str]:
    """Extract (registry, repository) from an image reference.

    Examples:
        nginx:latest           -> (registry-1.docker.io, library/nginx)
        ghcr.io/owner/repo:tag -> (ghcr.io, owner/repo)
        myregistry.com:5000/img:v1 -> (myregistry.com:5000, img)
    """
    # Strip tag/digest
    ref = image_name.split("@")[0]  # remove digest if present
    # Find the last colon that separates name:tag
    last_colon = ref.rfind(":")
    if last_colon != -1 and "/" not in ref[last_colon + 1 :]:
        ref = ref[:last_colon]

    parts = ref.split("/")
    if len(parts) == 1:
        # bare name like "nginx"
        return "registry-1.docker.io", f"library/{parts[0]}"
    if "." in parts[0] or ":" in parts[0] or parts[0] == "localhost":
        registry = parts[0]
        repo = "/".join(parts[1:])
        return registry, repo
    # docker.io implicit
    return "registry-1.docker.io", "/".join(parts)


def _get_docker_auth(registry: str) -> str | None:
    """Read auth from ~/.docker/config.json for the given registry."""
    config_path = Path.home() / ".docker" / "config.json"
    if not config_path.exists():
        return None
    try:
        config = json.loads(config_path.read_text())
    except (json.JSONDecodeError, OSError):
        return None

    auths = config.get("auths") or {}
    # Try exact match, then common variants
    for key in [registry, f"https://{registry}", f"https://{registry}/v2/"]:
        entry = auths.get(key, {})
        if "auth" in entry:
            return entry["auth"]
    return None


def _registry_scheme(registry: str) -> str:
    """Return 'http' for localhost registries, 'https' otherwise."""
    if registry.startswith("localhost") or registry.startswith("127.0.0.1"):
        return "http"
    return "https"


def _get_token(client: httpx.Client, registry: str, repo: str, auth_header: str | None) -> str | None:
    """Get a Bearer token for registry access via the WWW-Authenticate flow."""
    # For Docker Hub, use auth.docker.io
    if registry == "registry-1.docker.io":
        url = f"https://auth.docker.io/token?service=registry.docker.io&scope=repository:{repo}:pull"
        headers = {}
        if auth_header:
            decoded = base64.b64decode(auth_header).decode()
            user, password = decoded.split(":", 1)
            headers["Authorization"] = f"Basic {base64.b64encode(f'{user}:{password}'.encode()).decode()}"
        try:
            resp = client.get(url, headers=headers)
            if resp.status_code == 200:
                return resp.json().get("token")
        except Exception as exc:
            logger.debug("Failed to fetch Docker Hub token: %s", exc)
        return None

    # For other registries, try the WWW-Authenticate challenge
    scheme = _registry_scheme(registry)
    try:
        resp = client.get(f"{scheme}://{registry}/v2/")
        if resp.status_code == 401:
            www_auth = resp.headers.get("www-authenticate", "")
            match = re.search(r'realm="([^"]+)"', www_auth)
            if match:
                realm = match.group(1)
                service_match = re.search(r'service="([^"]+)"', www_auth)
                service = service_match.group(1) if service_match else ""
                token_url = f"{realm}?service={service}&scope=repository:{repo}:pull"
                headers = {}
                if auth_header:
                    headers["Authorization"] = f"Basic {auth_header}"
                token_resp = client.get(token_url, headers=headers)
                if token_resp.status_code == 200:
                    return token_resp.json().get("token")
    except Exception as exc:
        logger.debug("Failed to fetch registry token for %s/%s: %s", registry, repo, exc)
    return None


def _is_vex_artifact(descriptor: dict) -> bool:
    """Check if an OCI descriptor is or may contain a VEX artifact."""
    artifact_type = descriptor.get("artifactType", "")
    if artifact_type in _VEX_ARTIFACT_TYPES:
        return True
    # Check annotations for in-toto attestation predicateType
    annotations = descriptor.get("annotations") or {}
    predicate_type = annotations.get("predicateType", "")
    if predicate_type in _VEX_PREDICATE_TYPES:
        return True
    # Sigstore bundles with an openvex predicate type in annotations
    bundle_predicate = annotations.get("dev.sigstore.bundle.predicateType", "")
    if bundle_predicate in _VEX_PREDICATE_TYPES:
        return True
    # Sigstore bundles need to be fetched to check — include them as candidates
    if artifact_type in _SIGSTORE_BUNDLE_TYPES:
        return True
    # Check if mediaType hints at VEX
    if "vex" in artifact_type.lower():
        return True
    return False


def _normalise_vuln_id(raw: str) -> str:
    """Extract a bare vulnerability identifier from a raw string.

    OpenVEX documents frequently use full URLs as the ``@id`` for a
    vulnerability, e.g.::

        https://nvd.nist.gov/vuln/detail/CVE-2024-12345
        https://github.com/advisories/GHSA-xxxx-yyyy-zzzz
        https://osv.dev/vulnerability/GO-2024-1234

    Grype (and most scanners) store just the short identifier
    (``CVE-2024-12345``, ``GHSA-xxxx-yyyy-zzzz``, ``GO-2024-1234``).
    This helper extracts the trailing path segment when the value looks
    like a URL, and returns it unchanged otherwise.
    """
    if raw.startswith(("http://", "https://")):
        # Last non-empty path segment
        segment = raw.rstrip("/").rsplit("/", 1)[-1]
        if segment:
            return segment
    return raw


def _parse_openvex(doc: dict) -> list[VexStatement]:
    """Parse an OpenVEX document into VexStatements."""
    raw_stmts = doc.get("statements", [])
    logger.debug("_parse_openvex: doc keys=%s, %d raw statement(s)", list(doc.keys())[:15], len(raw_stmts))
    statements = []
    for stmt in raw_stmts:
        status = stmt.get("status", "")
        justification = stmt.get("justification")
        notes = stmt.get("status_notes") or stmt.get("impact_statement")

        vuln_ref = stmt.get("vulnerability", {})
        if isinstance(vuln_ref, str):
            vuln_id = vuln_ref
        else:
            vuln_id = vuln_ref.get("name") or vuln_ref.get("@id") or vuln_ref.get("id", "")
        vuln_id = _normalise_vuln_id(vuln_id)

        if not vuln_id:
            logger.debug("_parse_openvex: skipping statement with no vuln_id: %s", stmt)
            continue

        logger.debug("_parse_openvex: found %s status=%s", vuln_id, status)
        statements.append(
            VexStatement(
                vuln_id=vuln_id,
                status=status,
                justification=justification,
                notes=notes,
            )
        )
    if not raw_stmts:
        logger.debug("_parse_openvex: no 'statements' key or empty list in doc")
    return statements


def _extract_vex_from_blob(blob_data: dict) -> list[VexStatement]:
    """Extract VEX statements from a blob, handling multiple formats:

    1. Plain OpenVEX document (has "statements" key)
    2. In-toto statement wrapper (has "predicate" with VEX inside)
    3. Sigstore bundle (has "dsseEnvelope" with base64-encoded in-toto payload)
    4. Raw DSSE envelope (has top-level "payload"+"payloadType") — produced by
       ``cosign attest``; the payload is a base64-encoded in-toto statement.
    """
    logger.debug("_extract_vex_from_blob: top-level keys=%s", list(blob_data.keys())[:20])

    # Format 4: Raw DSSE envelope (cosign attest output)
    # Top-level keys: "payload" (base64url), "payloadType", "signatures"
    if "payload" in blob_data and "payloadType" in blob_data:
        logger.debug("Format 4 (raw DSSE): payloadType=%s", blob_data.get("payloadType"))
        try:
            payload = _b64decode(blob_data["payload"])
            intoto = json.loads(payload)
            predicate_type = intoto.get("predicateType", "")
            logger.debug("Format 4: decoded in-toto predicateType=%s, keys=%s", predicate_type, list(intoto.keys()))
            if "openvex" in predicate_type or "vex" in predicate_type or predicate_type in _VEX_PREDICATE_TYPES:
                stmts = _parse_openvex(intoto.get("predicate", {}))
                logger.debug("Format 4: parsed %d VEX statement(s)", len(stmts))
                return stmts
            logger.debug("Format 4: predicateType %r not recognised as VEX", predicate_type)
        except Exception:
            logger.debug("Format 4: failed to decode/parse DSSE payload", exc_info=True)

    # Format 3: Sigstore bundle with DSSE envelope
    dsse = blob_data.get("dsseEnvelope")
    if dsse and isinstance(dsse, dict):
        logger.debug("Format 3 (Sigstore bundle): dsseEnvelope keys=%s", list(dsse.keys()))
        try:
            payload = _b64decode(dsse.get("payload", ""))
            intoto = json.loads(payload)
            predicate_type = intoto.get("predicateType", "")
            logger.debug("Format 3: decoded in-toto predicateType=%s", predicate_type)
            if "openvex" in predicate_type or "vex" in predicate_type or predicate_type in _VEX_PREDICATE_TYPES:
                vex_doc = intoto.get("predicate", {})
                stmts = _parse_openvex(vex_doc)
                logger.debug("Format 3: parsed %d VEX statement(s)", len(stmts))
                return stmts
            logger.debug("Format 3: predicateType %r not recognised as VEX", predicate_type)
        except Exception:
            logger.debug("Format 3: failed to decode/parse Sigstore bundle", exc_info=True)

    # Format 2: In-toto attestation wrapper
    if "predicate" in blob_data:
        predicate_type = blob_data.get("predicateType", "")
        logger.debug("Format 2 (in-toto wrapper): predicateType=%s", predicate_type)
        if "openvex" in predicate_type or "vex" in predicate_type or predicate_type in _VEX_PREDICATE_TYPES:
            stmts = _parse_openvex(blob_data["predicate"])
            logger.debug("Format 2: parsed %d VEX statement(s)", len(stmts))
            return stmts
        # Even without a matching predicateType, try parsing the predicate
        stmts = _parse_openvex(blob_data["predicate"])
        logger.debug("Format 2 (unrecognised predicateType): parsed %d VEX statement(s)", len(stmts))
        return stmts

    # Format 1: Plain OpenVEX document
    logger.debug("Format 1 (plain OpenVEX): trying direct parse")
    stmts = _parse_openvex(blob_data)
    logger.debug("Format 1: parsed %d VEX statement(s)", len(stmts))
    return stmts


def check_vex_for_image(image_name: str, image_digest: str) -> VexResult:
    """Check OCI registry for VEX attestations attached to an image.

    This is a synchronous, best-effort call. Timeouts or errors are caught
    and returned in VexResult.error — they never propagate to the caller.
    """
    if not image_digest or not image_digest.startswith("sha256:"):
        return VexResult(error="No valid digest")

    try:
        registry, repo = _parse_image_ref(image_name)
    except Exception as e:
        return VexResult(error=f"Failed to parse image ref: {e}")

    # Use HTTP for localhost registries (common in development/testing)
    scheme = _registry_scheme(registry)

    try:
        with httpx.Client(timeout=_TIMEOUT, follow_redirects=True) as client:
            auth_header = _get_docker_auth(registry)
            token = _get_token(client, registry, repo, auth_header)

            headers = {"Accept": _OCI_INDEX_MEDIA}
            if token:
                headers["Authorization"] = f"Bearer {token}"
            elif auth_header:
                headers["Authorization"] = f"Basic {auth_header}"

            # Try OCI Referrers API.
            url = f"{scheme}://{registry}/v2/{repo}/referrers/{image_digest}"

            # Disable auto-redirect: GHCR returns 303 to a different hostname
            # (github.com) and httpx strips the Authorization header on
            # cross-origin redirects.  We also need to repair a GHCR bug where
            # the Location URL truncates the digest at the algorithm boundary —
            # e.g. ".../sha256%3Aabcdef" arrives as ".../sha256" because GHCR
            # strips the hash regardless of whether the colon is encoded.
            resp = client.get(url, headers=headers, follow_redirects=False)
            if resp.status_code in (301, 302, 303, 307, 308):
                redirect_url = resp.headers.get("location", "")
                if redirect_url:
                    # Repair truncated GHCR Location: if the URL ends with just
                    # the digest algorithm (e.g. "sha256") with no hash, append
                    # the encoded hash that GHCR dropped.
                    algorithm, _, hash_value = image_digest.partition(":")
                    if hash_value and redirect_url.endswith(algorithm):
                        redirect_url = f"{redirect_url}%3A{hash_value}"
                    resp = client.get(redirect_url, headers=headers)

            referrers = []
            if resp.status_code == 200:
                try:
                    data = resp.json()
                    referrers = data.get("manifests") or []
                    logger.debug("Referrers API: found %d referrer(s)", len(referrers))
                except Exception:
                    logger.debug("Referrers API: 200 but failed to parse JSON", exc_info=True)
            elif resp.status_code == 404:
                logger.debug("Referrers API: 404, trying OCI tag fallback")
                # Try fallback: referrers tag scheme
                tag = image_digest.replace(":", "-")
                tag_url = f"{scheme}://{registry}/v2/{repo}/manifests/{tag}"
                fallback_resp = client.get(tag_url, headers=headers)
                if fallback_resp.status_code == 200:
                    try:
                        data = fallback_resp.json()
                        referrers = data.get("manifests") or []
                        logger.debug("OCI tag fallback: found %d referrer(s)", len(referrers))
                    except Exception:
                        logger.debug("OCI tag fallback: 200 but failed to parse JSON", exc_info=True)
                else:
                    logger.debug("OCI tag fallback: status %d", fallback_resp.status_code)
            else:
                logger.debug("Referrers API: unexpected status %d", resp.status_code)

            # Filter for VEX artifacts
            vex_descriptors = [d for d in referrers if _is_vex_artifact(d)]
            logger.debug("VEX descriptors from referrers: %d of %d", len(vex_descriptors), len(referrers))
            for d in referrers:
                logger.debug(
                    "  referrer: artifactType=%s mediaType=%s annotations=%s",
                    d.get("artifactType", ""),
                    d.get("mediaType", ""),
                    d.get("annotations", {}),
                )

            # Fetch and parse VEX documents found via the referrers API / tag scheme
            all_statements: list[VexStatement] = []
            for desc in vex_descriptors:
                digest = desc.get("digest", "")
                if not digest:
                    continue
                logger.debug("Fetching VEX manifest: %s", digest[:30])
                manifest_url = f"{scheme}://{registry}/v2/{repo}/manifests/{digest}"
                manifest_resp = client.get(
                    manifest_url,
                    headers={
                        **headers,
                        "Accept": desc.get("mediaType", "application/vnd.oci.image.manifest.v1+json"),
                    },
                )
                if manifest_resp.status_code != 200:
                    logger.debug("VEX manifest %s: status %d", digest[:30], manifest_resp.status_code)
                    continue
                try:
                    manifest = manifest_resp.json()
                except Exception:
                    logger.debug("VEX manifest %s: not valid JSON", digest[:30], exc_info=True)
                    continue

                # Get layers/blobs from the manifest
                layers = manifest.get("layers") or []
                logger.debug("VEX manifest %s: %d layer(s)", digest[:30], len(layers))
                for layer in layers:
                    blob_digest = layer.get("digest", "")
                    if not blob_digest:
                        continue
                    blob_url = f"{scheme}://{registry}/v2/{repo}/blobs/{blob_digest}"
                    blob_resp = client.get(blob_url, headers=headers)
                    if blob_resp.status_code != 200:
                        logger.debug("Blob %s: status %d", blob_digest[:30], blob_resp.status_code)
                        continue
                    try:
                        blob_data = blob_resp.json()
                    except Exception:
                        logger.debug(
                            "Blob %s: not valid JSON (first 200 chars: %s)",
                            blob_digest[:30],
                            blob_resp.text[:200],
                        )
                        continue

                    stmts = _extract_vex_from_blob(blob_data)
                    logger.debug("Blob %s: extracted %d VEX statement(s)", blob_digest[:30], len(stmts))
                    all_statements.extend(stmts)

            # Cosign legacy .att tag fallback.
            # `cosign attest` stores the attestation as an OCI artifact tagged
            # sha256-{hash}.att.  With a single attestation this is a plain
            # manifest (has "layers").  When multiple attestations exist cosign
            # promotes the tag to an OCI image index (has "manifests"), where
            # each entry is a separate attestation manifest.  We handle both.
            if not all_statements:
                att_tag = image_digest.replace(":", "-") + ".att"
                att_url = f"{scheme}://{registry}/v2/{repo}/manifests/{att_tag}"
                logger.debug("Cosign .att fallback: trying %s", att_url)
                att_resp = client.get(
                    att_url,
                    headers={
                        **headers,
                        "Accept": (
                            "application/vnd.oci.image.index.v1+json,application/vnd.oci.image.manifest.v1+json"
                        ),
                    },
                )
                logger.debug("Cosign .att fallback: status %d", att_resp.status_code)
                if att_resp.status_code == 200:
                    try:
                        att_top = att_resp.json()
                        logger.debug(
                            "Cosign .att manifest: mediaType=%s, keys=%s",
                            att_top.get("mediaType", ""),
                            list(att_top.keys()),
                        )

                        # Collect the list of manifests to process.  If the top
                        # level is an OCI index we fetch each sub-manifest first;
                        # otherwise the top level IS the manifest.
                        if "manifests" in att_top:
                            logger.debug(
                                "Cosign .att: OCI index with %d sub-manifest(s)",
                                len(att_top["manifests"]),
                            )
                            att_manifests = []
                            for sub in att_top["manifests"]:
                                sub_digest = sub.get("digest", "")
                                if not sub_digest:
                                    continue
                                sub_url = f"{scheme}://{registry}/v2/{repo}/manifests/{sub_digest}"
                                sub_resp = client.get(
                                    sub_url,
                                    headers={
                                        **headers,
                                        "Accept": sub.get(
                                            "mediaType",
                                            "application/vnd.oci.image.manifest.v1+json",
                                        ),
                                    },
                                )
                                if sub_resp.status_code == 200:
                                    try:
                                        att_manifests.append(sub_resp.json())
                                    except Exception:
                                        logger.debug(
                                            "Cosign .att: failed to parse sub-manifest %s",
                                            sub_digest,
                                            exc_info=True,
                                        )
                                else:
                                    logger.debug(
                                        "Cosign .att: sub-manifest %s returned status %d",
                                        sub_digest,
                                        sub_resp.status_code,
                                    )
                        else:
                            logger.debug("Cosign .att: single manifest (has layers)")
                            att_manifests = [att_top]

                        logger.debug("Cosign .att: processing %d manifest(s)", len(att_manifests))
                        for i, att_manifest in enumerate(att_manifests):
                            layers = att_manifest.get("layers") or []
                            logger.debug("Cosign .att manifest[%d]: %d layer(s)", i, len(layers))
                            for layer in layers:
                                blob_digest = layer.get("digest", "")
                                layer_media = layer.get("mediaType", "")
                                logger.debug(
                                    "Cosign .att layer: digest=%s mediaType=%s",
                                    blob_digest[:30] if blob_digest else "",
                                    layer_media,
                                )
                                if not blob_digest:
                                    continue
                                blob_url = f"{scheme}://{registry}/v2/{repo}/blobs/{blob_digest}"
                                blob_resp = client.get(blob_url, headers=headers)
                                if blob_resp.status_code != 200:
                                    logger.debug(
                                        "Cosign .att blob fetch: status %d for %s",
                                        blob_resp.status_code,
                                        blob_digest[:30],
                                    )
                                    continue
                                try:
                                    blob_data = blob_resp.json()
                                except Exception:
                                    logger.debug(
                                        "Cosign .att blob: not valid JSON (first 200 chars: %s)",
                                        blob_resp.text[:200],
                                    )
                                    continue
                                stmts = _extract_vex_from_blob(blob_data)
                                logger.debug(
                                    "Cosign .att blob %s: extracted %d VEX statement(s)",
                                    blob_digest[:30],
                                    len(stmts),
                                )
                                all_statements.extend(stmts)
                    except Exception:
                        logger.debug("Cosign .att fallback: unexpected error", exc_info=True)
                else:
                    logger.debug("Cosign .att fallback: tag not found (status %d)", att_resp.status_code)

            if all_statements:
                logger.info(
                    "VEX discovery: found %d statement(s) for %s",
                    len(all_statements),
                    image_name,
                )
                return VexResult(
                    found=True,
                    statements=all_statements,
                    source=f"{scheme}://{registry}/v2/{repo}/referrers/{image_digest}",
                )
            logger.info("VEX discovery: no VEX statements found for %s", image_name)
            return VexResult(found=False, source=url)

    except httpx.TimeoutException:
        logger.warning("VEX discovery: timeout for %s", image_name)
        return VexResult(error="Timeout checking registry for VEX")
    except Exception as e:
        logger.warning("VEX discovery: error for %s: %s", image_name, e, exc_info=True)
        return VexResult(error=str(e))

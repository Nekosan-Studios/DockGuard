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
# Sigstore bundles may contain VEX attestations — we need to fetch and inspect them.
_SIGSTORE_BUNDLE_TYPES = {
    "application/vnd.dev.sigstore.bundle.v0.3+json",
    "application/vnd.dev.sigstore.bundle+json;version=0.3",
}
_OCI_INDEX_MEDIA = "application/vnd.oci.image.index.v1+json"


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
    if last_colon != -1 and "/" not in ref[last_colon + 1:]:
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

    auths = config.get("auths", {})
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
        except Exception:
            pass
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
    except Exception:
        pass
    return None


def _is_vex_artifact(descriptor: dict) -> bool:
    """Check if an OCI descriptor is or may contain a VEX artifact."""
    artifact_type = descriptor.get("artifactType", "")
    if artifact_type in _VEX_ARTIFACT_TYPES:
        return True
    # Check annotations for in-toto attestation predicateType
    annotations = descriptor.get("annotations", {})
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


def _parse_openvex(doc: dict) -> list[VexStatement]:
    """Parse an OpenVEX document into VexStatements."""
    statements = []
    for stmt in doc.get("statements", []):
        status = stmt.get("status", "")
        justification = stmt.get("justification")
        notes = stmt.get("status_notes") or stmt.get("impact_statement")

        vuln_ref = stmt.get("vulnerability", {})
        vuln_id = vuln_ref if isinstance(vuln_ref, str) else vuln_ref.get("name") or vuln_ref.get("id", "")
        if not vuln_id:
            continue

        statements.append(VexStatement(
            vuln_id=vuln_id,
            status=status,
            justification=justification,
            notes=notes,
        ))
    return statements


def _extract_vex_from_blob(blob_data: dict) -> list[VexStatement]:
    """Extract VEX statements from a blob, handling multiple formats:

    1. Plain OpenVEX document (has "statements" key)
    2. In-toto statement wrapper (has "predicate" with VEX inside)
    3. Sigstore bundle (has "dsseEnvelope" with base64-encoded in-toto payload)
    """
    # Format 3: Sigstore bundle with DSSE envelope
    dsse = blob_data.get("dsseEnvelope")
    if dsse and isinstance(dsse, dict):
        try:
            payload = base64.b64decode(dsse.get("payload", ""))
            intoto = json.loads(payload)
            predicate_type = intoto.get("predicateType", "")
            if "openvex" in predicate_type or "vex" in predicate_type or predicate_type in _VEX_PREDICATE_TYPES:
                vex_doc = intoto.get("predicate", {})
                return _parse_openvex(vex_doc)
        except Exception:
            pass

    # Format 2: In-toto attestation wrapper
    if "predicate" in blob_data:
        predicate_type = blob_data.get("predicateType", "")
        if "openvex" in predicate_type or "vex" in predicate_type or predicate_type in _VEX_PREDICATE_TYPES:
            return _parse_openvex(blob_data["predicate"])
        # Even without a matching predicateType, try parsing the predicate
        return _parse_openvex(blob_data["predicate"])

    # Format 1: Plain OpenVEX document
    return _parse_openvex(blob_data)


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

            # Try OCI Referrers API
            url = f"{scheme}://{registry}/v2/{repo}/referrers/{image_digest}"
            resp = client.get(url, headers=headers)

            referrers = []
            if resp.status_code == 200:
                try:
                    data = resp.json()
                    referrers = data.get("manifests", [])
                except Exception:
                    pass
            elif resp.status_code == 404:
                # Try fallback: referrers tag scheme
                tag = image_digest.replace(":", "-")
                tag_url = f"{scheme}://{registry}/v2/{repo}/manifests/{tag}"
                fallback_resp = client.get(tag_url, headers=headers)
                if fallback_resp.status_code == 200:
                    try:
                        data = fallback_resp.json()
                        referrers = data.get("manifests", [])
                    except Exception:
                        pass

            # Filter for VEX artifacts
            vex_descriptors = [d for d in referrers if _is_vex_artifact(d)]
            if not vex_descriptors:
                return VexResult(found=False, source=url)

            # Fetch and parse VEX documents
            all_statements: list[VexStatement] = []
            for desc in vex_descriptors:
                digest = desc.get("digest", "")
                if not digest:
                    continue
                manifest_url = f"{scheme}://{registry}/v2/{repo}/manifests/{digest}"
                manifest_resp = client.get(manifest_url, headers={
                    **headers,
                    "Accept": desc.get("mediaType", "application/vnd.oci.image.manifest.v1+json"),
                })
                if manifest_resp.status_code != 200:
                    continue
                try:
                    manifest = manifest_resp.json()
                except Exception:
                    continue

                # Get layers/blobs from the manifest
                for layer in manifest.get("layers", []):
                    blob_digest = layer.get("digest", "")
                    if not blob_digest:
                        continue
                    blob_url = f"{scheme}://{registry}/v2/{repo}/blobs/{blob_digest}"
                    blob_resp = client.get(blob_url, headers=headers)
                    if blob_resp.status_code != 200:
                        continue
                    try:
                        blob_data = blob_resp.json()
                    except Exception:
                        continue

                    stmts = _extract_vex_from_blob(blob_data)
                    all_statements.extend(stmts)

            if all_statements:
                return VexResult(
                    found=True,
                    statements=all_statements,
                    source=f"{scheme}://{registry}/v2/{repo}/referrers/{image_digest}",
                )
            return VexResult(found=False, source=url)

    except httpx.TimeoutException:
        return VexResult(error="Timeout checking registry for VEX")
    except Exception as e:
        return VexResult(error=str(e))

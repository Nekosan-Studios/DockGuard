"""Registry digest checker.

Queries the registry for the current digest of a tagged image without pulling
the image locally.  Returns None on any error or for unsupported references
(digest-pinned, untagged, etc.).
"""

import logging

import httpx

from .vex_discovery import _get_docker_auth, _get_token, _parse_image_ref, _registry_scheme

logger = logging.getLogger(__name__)

_TIMEOUT = 10

# Multi-format Accept headers so registries return a stable manifest digest
_MANIFEST_ACCEPT = ",".join(
    [
        "application/vnd.docker.distribution.manifest.v2+json",
        "application/vnd.docker.distribution.manifest.list.v2+json",
        "application/vnd.oci.image.manifest.v1+json",
        "application/vnd.oci.image.index.v1+json",
    ]
)


def get_registry_digest(image_name: str) -> str | None:
    """Return the Docker-Content-Digest for *image_name* from the registry.

    Returns None for:
    - digest-pinned references (``image@sha256:...``)
    - bare names without a tag
    - any auth / network / rate-limit error
    """
    # Skip digest-pinned references
    if "@" in image_name:
        logger.debug("Skipping digest-pinned image: %s", image_name)
        return None

    # Determine tag
    ref = image_name
    last_colon = ref.rfind(":")
    if last_colon == -1 or "/" in ref[last_colon + 1 :]:
        # No tag — skip
        logger.debug("Skipping untagged image: %s", image_name)
        return None
    tag = ref[last_colon + 1 :]

    try:
        registry, repo = _parse_image_ref(image_name)
    except Exception as exc:
        logger.debug("Failed to parse image ref %s: %s", image_name, exc)
        return None

    scheme = _registry_scheme(registry)
    auth_header = _get_docker_auth(registry)

    try:
        with httpx.Client(timeout=_TIMEOUT, follow_redirects=True) as client:
            token = _get_token(client, registry, repo, auth_header)

            headers = {"Accept": _MANIFEST_ACCEPT}
            if token:
                headers["Authorization"] = f"Bearer {token}"
            elif auth_header:
                headers["Authorization"] = f"Basic {auth_header}"

            url = f"{scheme}://{registry}/v2/{repo}/manifests/{tag}"

            # Try HEAD first; fall back to GET if not supported
            resp = client.head(url, headers=headers)
            if resp.status_code == 405:
                resp = client.get(url, headers=headers)

            if resp.status_code == 429:
                logger.warning("Rate limited by registry for %s", image_name)
                return None

            if resp.status_code not in (200, 304):
                logger.debug(
                    "Registry returned %d for %s",
                    resp.status_code,
                    image_name,
                )
                return None

            digest = resp.headers.get("Docker-Content-Digest")
            if not digest:
                logger.debug("No Docker-Content-Digest header for %s", image_name)
                return None

            return digest

    except Exception as exc:
        logger.debug("Error fetching registry digest for %s: %s", image_name, exc)
        return None

#!/usr/bin/env python3
"""Check what rate-limit headers Docker Hub returns for a manifest HEAD request.

Usage:
    uv run python scripts/check_ratelimit_headers.py [image:tag ...]

Examples:
    uv run python scripts/check_ratelimit_headers.py
    uv run python scripts/check_ratelimit_headers.py nginx:latest redis:7
"""

import sys

import httpx

sys.path.insert(0, ".")

from backend.vex_discovery import _get_docker_auth, _get_token, _parse_image_ref, _registry_scheme

_MANIFEST_ACCEPT = ",".join(
    [
        "application/vnd.docker.distribution.manifest.v2+json",
        "application/vnd.docker.distribution.manifest.list.v2+json",
        "application/vnd.oci.image.manifest.v1+json",
        "application/vnd.oci.image.index.v1+json",
    ]
)

IMAGES = sys.argv[1:] or ["nginx:latest"]


def check_image(image_name: str) -> None:
    print(f"\n{'=' * 60}")
    print(f"Image: {image_name}")
    print(f"{'=' * 60}")

    registry, repo = _parse_image_ref(image_name)
    last_colon = image_name.rfind(":")
    tag = image_name[last_colon + 1 :] if last_colon != -1 else "latest"

    scheme = _registry_scheme(registry)
    auth_header = _get_docker_auth(registry)
    url = f"{scheme}://{registry}/v2/{repo}/manifests/{tag}"

    print(f"Registry : {registry}")
    print(f"URL      : {url}")
    print(f"Auth     : {'credentials found' if auth_header else 'anonymous (no credentials)'}")

    with httpx.Client(timeout=10, follow_redirects=True) as client:
        token = _get_token(client, registry, repo, auth_header)

        headers = {"Accept": _MANIFEST_ACCEPT}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        elif auth_header:
            headers["Authorization"] = f"Basic {auth_header}"

        print("\n--- HEAD request ---")
        resp = client.head(url, headers=headers)
        print(f"Status   : {resp.status_code}")

        rate_limit_headers = {
            k: v for k, v in resp.headers.items() if "ratelimit" in k.lower() or "rate-limit" in k.lower()
        }

        if rate_limit_headers:
            print("\nRate-limit headers:")
            for k, v in rate_limit_headers.items():
                print(f"  {k}: {v}")
        else:
            print("\nNo rate-limit headers returned.")

        digest = resp.headers.get("Docker-Content-Digest")
        print(f"\nDocker-Content-Digest: {digest or '(not present)'}")

        if resp.status_code == 405:
            print("\n--- HEAD not supported, falling back to GET ---")
            resp = client.get(url, headers=headers)
            print(f"Status   : {resp.status_code}")
            rate_limit_headers = {
                k: v for k, v in resp.headers.items() if "ratelimit" in k.lower() or "rate-limit" in k.lower()
            }
            if rate_limit_headers:
                print("\nRate-limit headers:")
                for k, v in rate_limit_headers.items():
                    print(f"  {k}: {v}")
            else:
                print("No rate-limit headers returned.")


for image in IMAGES:
    try:
        check_image(image)
    except Exception as e:
        print(f"Error checking {image}: {e}")

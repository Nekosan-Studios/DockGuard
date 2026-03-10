"""
Static test data — Grype JSON payloads and mock Docker image lists.
"""

GRYPE_JSON_NGINX = {
    "source": {
        "type": "image",
        "target": {
            "userInput": "nginx:latest",
            "imageID": "sha256:aaaa000000000000000000000000000000000000000000000000000000000000",
            "tags": ["nginx:latest"],
            "repoDigests": ["nginx@sha256:aaaa000000000000000000000000000000000000000000000000000000000000"],
            "architecture": "amd64",
            "os": "linux",
        },
    },
    "distro": {"name": "debian", "version": "12", "idLike": []},
    "descriptor": {
        "name": "grype",
        "version": "0.85.0",
        "db": {"built": "2024-01-15T00:00:00Z"},
    },
    "matches": [
        {
            "vulnerability": {
                "id": "CVE-2024-0001",
                "severity": "Critical",
                "description": "A critical buffer overflow vulnerability.",
                "dataSource": "https://nvd.nist.gov/vuln/detail/CVE-2024-0001",
                "urls": ["https://nvd.nist.gov/vuln/detail/CVE-2024-0001", "https://example.com/advisory"],
                "cvss": [{"metrics": {"baseScore": 9.8}, "version": "3.1", "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
                "epss": [{"epss": 0.94, "percentile": 0.99, "date": "2024-01-15"}],
                "knownExploited": [{"cve": "CVE-2024-0001", "vendorProject": "Example"}],
                "cwes": [{"cwe": "CWE-119", "source": "nvd", "type": "primary"}, {"cwe": "CWE-787", "source": "nvd", "type": "secondary"}],
                "risk": 9.5,
                "fix": {"versions": ["1.2.3"], "state": "fixed"},
            },
            "artifact": {
                "name": "libssl",
                "version": "1.1.1",
                "type": "deb",
                "language": "",
                "purl": "pkg:deb/debian/libssl@1.1.1?arch=amd64&distro=debian-12&upstream=openssl",
                "upstreams": [{"name": "openssl"}],
                "locations": [
                    {"path": "/usr/lib/x86_64-linux-gnu/libssl.so.1.1", "layerID": "sha256:aaaa01"},
                    {"path": "/usr/lib/x86_64-linux-gnu/libcrypto.so.1.1", "layerID": "sha256:aaaa01"},
                ],
            },
            "matchDetails": [
                {
                    "type": "exact-indirect-match",
                    "matcher": "dpkg-matcher",
                    "searchedBy": {
                        "distro": {"type": "debian", "version": "12"},
                        "package": {"name": "openssl", "version": "1.1.1"},
                        "namespace": "debian:distro:debian:12",
                    },
                    "found": {"vulnerabilityID": "CVE-2024-0001", "versionConstraint": "none (unknown)"},
                }
            ],
            "relatedVulnerabilities": [],
        },
        {
            "vulnerability": {
                "id": "CVE-2024-0002",
                "severity": "High",
                "description": "A high severity use-after-free vulnerability.",
                "dataSource": "https://nvd.nist.gov/vuln/detail/CVE-2024-0002",
                "urls": [],
                "cvss": [{"metrics": {"baseScore": 7.5}, "version": "3.1", "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"}],
                "epss": [{"epss": 0.12, "percentile": 0.75, "date": "2024-01-15"}],
                "knownExploited": [],
                "cwes": [{"cwe": "CWE-416", "source": "nvd", "type": "primary"}],
                "risk": 6.8,
                "fix": {"versions": [], "state": "not-fixed"},
            },
            "artifact": {
                "name": "curl",
                "version": "7.88.0",
                "type": "deb",
                "language": "",
                "purl": "pkg:deb/debian/curl@7.88.0",
                "upstreams": [],
                "locations": [
                    {"path": "/usr/bin/curl", "layerID": "sha256:aaaa02"},
                ],
            },
            "matchDetails": [
                {
                    "type": "exact-direct-match",
                    "matcher": "dpkg-matcher",
                    "searchedBy": {
                        "distro": {"type": "debian", "version": "12"},
                        "package": {"name": "curl", "version": "7.88.0"},
                        "namespace": "debian:distro:debian:12",
                    },
                    "found": {"vulnerabilityID": "CVE-2024-0002", "versionConstraint": "none (unknown)"},
                }
            ],
            "relatedVulnerabilities": [],
        },
        {
            "vulnerability": {
                "id": "CVE-2024-0003",
                "severity": "Medium",
                "description": "A medium severity information disclosure.",
                "dataSource": "https://nvd.nist.gov/vuln/detail/CVE-2024-0003",
                "urls": [],
                "cvss": [{"metrics": {"baseScore": 5.3}, "version": "3.1", "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"}],
                "epss": [{"epss": 0.02, "percentile": 0.40, "date": "2024-01-15"}],
                "knownExploited": [],
                "cwes": [],
                "risk": 3.1,
                "fix": {"versions": ["2.0.0"], "state": "fixed"},
            },
            "artifact": {
                "name": "zlib",
                "version": "1.2.11",
                "type": "deb",
                "language": "",
                "purl": "pkg:deb/debian/zlib@1.2.11",
                "upstreams": [],
                "locations": [
                    {"path": "/lib/x86_64-linux-gnu/libz.so.1.2.11", "layerID": "sha256:aaaa03"},
                    {"path": "/lib/x86_64-linux-gnu/libz.so.1", "layerID": "sha256:aaaa03"},
                    {"path": "/usr/lib/x86_64-linux-gnu/libz.a", "layerID": "sha256:aaaa03"},
                ],
            },
            "matchDetails": [
                {
                    "type": "exact-direct-match",
                    "matcher": "dpkg-matcher",
                    "searchedBy": {
                        "distro": {"type": "debian", "version": "12"},
                        "package": {"name": "zlib", "version": "1.2.11"},
                        "namespace": "debian:distro:debian:12",
                    },
                    "found": {"vulnerabilityID": "CVE-2024-0003", "versionConstraint": "none (unknown)"},
                }
            ],
            "relatedVulnerabilities": [],
        },
    ],
}

GRYPE_JSON_NGINX_V2 = {
    **GRYPE_JSON_NGINX,
    "source": {
        **GRYPE_JSON_NGINX["source"],
        "target": {
            **GRYPE_JSON_NGINX["source"]["target"],
            "imageID": "sha256:bbbb000000000000000000000000000000000000000000000000000000000000",
        },
    },
    # Only 2 vulns — CVE-2024-0003 was fixed in this version
    "matches": GRYPE_JSON_NGINX["matches"][:2],
}

GRYPE_JSON_REDIS = {
    "source": {
        "type": "image",
        "target": {
            "userInput": "redis:7",
            "imageID": "sha256:cccc000000000000000000000000000000000000000000000000000000000000",
            "tags": ["redis:7"],
            "repoDigests": [],
            "architecture": "amd64",
            "os": "linux",
        },
    },
    "distro": {"name": "debian", "version": "12", "idLike": []},
    "descriptor": {
        "name": "grype",
        "version": "0.85.0",
        "db": {"built": "2024-01-15T00:00:00Z"},
    },
    "matches": [
        {
            "vulnerability": {
                "id": "CVE-2024-0010",
                "severity": "Critical",
                "description": "Critical RCE in redis.",
                "dataSource": "https://nvd.nist.gov/vuln/detail/CVE-2024-0010",
                "urls": [],
                "cvss": [{"metrics": {"baseScore": 9.1}, "version": "3.1", "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"}],
                "epss": [{"epss": 0.55, "percentile": 0.95, "date": "2024-01-15"}],
                "knownExploited": [],
                "cwes": [{"cwe": "CWE-94", "source": "nvd", "type": "primary"}],
                "risk": 8.9,
                "fix": {"versions": ["7.0.15"], "state": "fixed"},
            },
            "artifact": {
                "name": "redis-server",
                "version": "7.0.11",
                "type": "deb",
                "language": "",
                "purl": "pkg:deb/debian/redis-server@7.0.11",
                "locations": [
                    {"path": "/usr/bin/redis-server", "layerID": "sha256:cccc01"},
                ],
            },
        },
        {
            "vulnerability": {
                "id": "CVE-2024-0011",
                "severity": "Critical",
                "description": "Critical integer overflow in redis.",
                "dataSource": "https://nvd.nist.gov/vuln/detail/CVE-2024-0011",
                "urls": [],
                "cvss": [{"metrics": {"baseScore": 9.0}, "version": "3.1", "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"}],
                "epss": [{"epss": 0.30, "percentile": 0.88, "date": "2024-01-15"}],
                "knownExploited": [],
                "cwes": [{"cwe": "CWE-190", "source": "nvd", "type": "primary"}],
                "risk": 8.5,
                "fix": {"versions": [], "state": "not-fixed"},
            },
            "artifact": {
                "name": "redis-server",
                "version": "7.0.11",
                "type": "deb",
                "language": "",
                "purl": "pkg:deb/debian/redis-server@7.0.11",
                "locations": [
                    {"path": "/usr/bin/redis-server", "layerID": "sha256:cccc02"},
                ],
            },
        },
    ],
}

MOCK_DOCKER_IMAGES = [
    {
        "name": "nginx:latest",
        "grype_ref": "nginx:latest",
        "hash": "aaaa00000000",
        "image_id": "sha256:aaaa000000000000000000000000000000000000000000000000000000000000",
        "running": False,
    },
    {
        "name": "redis:7",
        "grype_ref": "redis:7",
        "hash": "cccc00000000",
        "image_id": "sha256:cccc000000000000000000000000000000000000000000000000000000000000",
        "running": True,
    },
]

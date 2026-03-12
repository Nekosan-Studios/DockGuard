"""Tests for VEX discovery module."""

from unittest.mock import MagicMock, patch

import base64
import json

from backend.vex_discovery import (
    _b64decode,
    _extract_vex_from_blob,
    _is_vex_artifact,
    _parse_image_ref,
    _parse_openvex,
    check_vex_for_image,
)


class TestParseImageRef:
    def test_bare_name(self):
        assert _parse_image_ref("nginx:latest") == ("registry-1.docker.io", "library/nginx")

    def test_bare_name_no_tag(self):
        assert _parse_image_ref("nginx") == ("registry-1.docker.io", "library/nginx")

    def test_docker_hub_user_repo(self):
        assert _parse_image_ref("myuser/myimage:v1") == ("registry-1.docker.io", "myuser/myimage")

    def test_ghcr(self):
        assert _parse_image_ref("ghcr.io/owner/repo:latest") == ("ghcr.io", "owner/repo")

    def test_custom_registry_with_port(self):
        assert _parse_image_ref("myregistry.com:5000/myimage:v1") == ("myregistry.com:5000", "myimage")

    def test_nested_repo(self):
        assert _parse_image_ref("ghcr.io/org/team/repo:tag") == ("ghcr.io", "org/team/repo")


class TestIsVexArtifact:
    def test_openvex_artifact_type(self):
        assert _is_vex_artifact({"artifactType": "application/vex+json"}) is True

    def test_openvex_json_artifact_type(self):
        assert _is_vex_artifact({"artifactType": "application/openvex+json"}) is True

    def test_sigstore_predicate(self):
        desc = {
            "artifactType": "application/vnd.in-toto+json",
            "annotations": {"predicateType": "https://openvex.dev/ns/v0.2.0"},
        }
        assert _is_vex_artifact(desc) is True

    def test_non_vex_artifact(self):
        assert _is_vex_artifact({"artifactType": "application/vnd.oci.image.manifest.v1+json"}) is False

    def test_vex_in_artifact_type(self):
        assert _is_vex_artifact({"artifactType": "application/custom-vex+json"}) is True


class TestParseOpenvex:
    def test_basic_openvex_document(self):
        doc = {
            "statements": [
                {
                    "vulnerability": {"name": "CVE-2024-1234"},
                    "status": "not_affected",
                    "justification": "vulnerable_code_not_present",
                    "status_notes": "The vulnerable function is not called.",
                },
                {
                    "vulnerability": "CVE-2024-5678",
                    "status": "under_investigation",
                },
            ]
        }
        stmts = _parse_openvex(doc)
        assert len(stmts) == 2
        assert stmts[0].vuln_id == "CVE-2024-1234"
        assert stmts[0].status == "not_affected"
        assert stmts[0].justification == "vulnerable_code_not_present"
        assert stmts[0].notes == "The vulnerable function is not called."
        assert stmts[1].vuln_id == "CVE-2024-5678"
        assert stmts[1].status == "under_investigation"
        assert stmts[1].justification is None

    def test_empty_document(self):
        assert _parse_openvex({}) == []
        assert _parse_openvex({"statements": []}) == []

    def test_missing_vuln_id_skipped(self):
        doc = {
            "statements": [
                {"vulnerability": {}, "status": "not_affected"},
                {"vulnerability": {"name": "CVE-2024-9999"}, "status": "affected"},
            ]
        }
        stmts = _parse_openvex(doc)
        assert len(stmts) == 1
        assert stmts[0].vuln_id == "CVE-2024-9999"


class TestB64Decode:
    """Tests for the _b64decode helper."""

    def test_standard_base64(self):
        assert _b64decode(base64.b64encode(b"hello").decode()) == b"hello"

    def test_base64url_characters(self):
        """URL-safe alphabet (- and _) must be accepted."""
        # Produce a byte string that encodes to + and / in standard base64
        raw = bytes(range(200, 210))
        standard = base64.b64encode(raw).decode()
        urlsafe = standard.replace("+", "-").replace("/", "_")
        assert _b64decode(urlsafe) == raw

    def test_missing_padding_tolerated(self):
        """Payloads without trailing = must still decode correctly."""
        raw = b"no padding needed here"
        unpadded = base64.b64encode(raw).decode().rstrip("=")
        assert _b64decode(unpadded) == raw

    def test_whitespace_stripped(self):
        assert _b64decode("  " + base64.b64encode(b"trim").decode() + "\n") == b"trim"


class TestExtractVexFromBlob:
    """Tests for _extract_vex_from_blob covering all supported wire formats."""

    def _make_intoto(self, statements: list) -> dict:
        return {
            "_type": "https://in-toto.io/Statement/v0.1",
            "predicateType": "https://openvex.dev/ns/v0.2.0",
            "subject": [],
            "predicate": {"statements": statements},
        }

    def test_raw_dsse_envelope_cosign_attest(self):
        """Raw DSSE envelope produced by `cosign attest --type openvex`.

        Top-level keys are 'payload' (base64-encoded in-toto statement) and
        'payloadType'.  This is the format stored in .att OCI layer blobs.
        """
        intoto = self._make_intoto(
            [{"vulnerability": {"name": "CVE-2024-1111"}, "status": "not_affected"}]
        )
        blob = {
            "payload": base64.b64encode(json.dumps(intoto).encode()).decode(),
            "payloadType": "application/vnd.in-toto+json",
            "signatures": [{"sig": "fakesig", "cert": "fakecert"}],
        }
        stmts = _extract_vex_from_blob(blob)
        assert len(stmts) == 1
        assert stmts[0].vuln_id == "CVE-2024-1111"
        assert stmts[0].status == "not_affected"

    def test_raw_dsse_non_vex_predicate_skipped(self):
        """A raw DSSE with a non-VEX predicateType should yield no statements."""
        intoto = {
            "_type": "https://in-toto.io/Statement/v0.1",
            "predicateType": "https://slsa.dev/provenance/v1",
            "subject": [],
            "predicate": {"builder": {}},
        }
        blob = {
            "payload": base64.b64encode(json.dumps(intoto).encode()).decode(),
            "payloadType": "application/vnd.in-toto+json",
            "signatures": [],
        }
        stmts = _extract_vex_from_blob(blob)
        assert stmts == []

    def test_sigstore_bundle_dsse_envelope(self):
        """Sigstore bundle format: DSSE nested under 'dsseEnvelope' key."""
        intoto = self._make_intoto(
            [{"vulnerability": {"name": "CVE-2024-2222"}, "status": "fixed"}]
        )
        blob = {
            "dsseEnvelope": {
                "payload": base64.b64encode(json.dumps(intoto).encode()).decode(),
                "payloadType": "application/vnd.in-toto+json",
            }
        }
        stmts = _extract_vex_from_blob(blob)
        assert len(stmts) == 1
        assert stmts[0].vuln_id == "CVE-2024-2222"
        assert stmts[0].status == "fixed"

    def test_intoto_wrapper(self):
        """In-toto statement already decoded (has 'predicate' key at top level)."""
        blob = {
            "predicateType": "https://openvex.dev/ns/v0.2.0",
            "predicate": {
                "statements": [
                    {"vulnerability": {"name": "CVE-2024-3333"}, "status": "affected"}
                ]
            },
        }
        stmts = _extract_vex_from_blob(blob)
        assert len(stmts) == 1
        assert stmts[0].vuln_id == "CVE-2024-3333"

    def test_plain_openvex(self):
        """Plain OpenVEX document with top-level 'statements' array."""
        blob = {
            "statements": [
                {"vulnerability": "CVE-2024-4444", "status": "under_investigation"}
            ]
        }
        stmts = _extract_vex_from_blob(blob)
        assert len(stmts) == 1
        assert stmts[0].vuln_id == "CVE-2024-4444"


class TestCheckVexForImage:
    def test_no_digest(self):
        result = check_vex_for_image("nginx:latest", "")
        assert result.found is False
        assert result.error == "No valid digest"

    def test_invalid_digest(self):
        result = check_vex_for_image("nginx:latest", "not-a-digest")
        assert result.found is False
        assert result.error == "No valid digest"

    @patch("backend.vex_discovery.httpx.Client")
    @patch("backend.vex_discovery._get_docker_auth", return_value=None)
    def test_no_referrers_found(self, mock_auth, MockClient):
        """Test when the referrers API returns empty manifests."""
        mock_client = MagicMock()
        MockClient.return_value.__enter__ = MagicMock(return_value=mock_client)
        MockClient.return_value.__exit__ = MagicMock(return_value=False)

        # Token request
        mock_token_resp = MagicMock()
        mock_token_resp.status_code = 200
        mock_token_resp.json.return_value = {"token": "test-token"}

        # Referrers API response: empty
        mock_referrers_resp = MagicMock()
        mock_referrers_resp.status_code = 200
        mock_referrers_resp.json.return_value = {"manifests": []}

        # .att tag: not found either
        mock_att_resp = MagicMock()
        mock_att_resp.status_code = 404

        mock_client.get.side_effect = [mock_token_resp, mock_referrers_resp, mock_att_resp]

        result = check_vex_for_image("nginx:latest", "sha256:abc123")
        assert result.found is False
        assert result.error is None

    @patch("backend.vex_discovery.httpx.Client")
    @patch("backend.vex_discovery._get_docker_auth", return_value=None)
    def test_vex_found_and_parsed(self, mock_auth, MockClient):
        """Test when VEX attestation is found and parsed successfully."""
        mock_client = MagicMock()
        MockClient.return_value.__enter__ = MagicMock(return_value=mock_client)
        MockClient.return_value.__exit__ = MagicMock(return_value=False)

        # Token
        mock_token_resp = MagicMock()
        mock_token_resp.status_code = 200
        mock_token_resp.json.return_value = {"token": "test-token"}

        # Referrers: one VEX artifact
        mock_referrers_resp = MagicMock()
        mock_referrers_resp.status_code = 200
        mock_referrers_resp.json.return_value = {
            "manifests": [
                {
                    "artifactType": "application/vex+json",
                    "digest": "sha256:vexdigest",
                    "mediaType": "application/vnd.oci.image.manifest.v1+json",
                }
            ]
        }

        # Manifest
        mock_manifest_resp = MagicMock()
        mock_manifest_resp.status_code = 200
        mock_manifest_resp.json.return_value = {
            "layers": [{"digest": "sha256:blobdigest", "mediaType": "application/vex+json"}]
        }

        # VEX blob
        vex_doc = {
            "statements": [
                {
                    "vulnerability": {"name": "CVE-2024-1234"},
                    "status": "not_affected",
                    "justification": "vulnerable_code_not_present",
                }
            ]
        }
        mock_blob_resp = MagicMock()
        mock_blob_resp.status_code = 200
        mock_blob_resp.json.return_value = vex_doc

        mock_client.get.side_effect = [
            mock_token_resp,
            mock_referrers_resp,
            mock_manifest_resp,
            mock_blob_resp,
        ]

        result = check_vex_for_image("nginx:latest", "sha256:abc123")
        assert result.found is True
        assert len(result.statements) == 1
        assert result.statements[0].vuln_id == "CVE-2024-1234"
        assert result.statements[0].status == "not_affected"

    @patch("backend.vex_discovery.httpx.Client")
    @patch("backend.vex_discovery._get_docker_auth", return_value=None)
    def test_ghcr_303_redirect_followed_with_auth(self, mock_auth, MockClient):
        """Test that a 303 redirect (e.g. GHCR → github.com) is followed with
        the Authorization header intact and the referrers list is parsed."""
        mock_client = MagicMock()
        MockClient.return_value.__enter__ = MagicMock(return_value=mock_client)
        MockClient.return_value.__exit__ = MagicMock(return_value=False)

        # Simulate GHCR token flow: GET /v2/ → 401, then GET /token → 200
        mock_challenge_resp = MagicMock()
        mock_challenge_resp.status_code = 401
        mock_challenge_resp.headers = {
            "www-authenticate": 'Bearer realm="https://ghcr.io/token",service="ghcr.io"'
        }

        mock_token_resp = MagicMock()
        mock_token_resp.status_code = 200
        mock_token_resp.json.return_value = {"token": "test-bearer-token"}

        # Referrers API: 303 See Other (GHCR behaviour).
        # The Location URL intentionally omits the hash (simulating the GHCR
        # server-side bug) — the code under test must repair it.
        mock_referrers_resp = MagicMock()
        mock_referrers_resp.status_code = 303
        mock_referrers_resp.headers = {
            "location": "https://github.com/-/v2/packages/container/package/owner%2Frepo%2Freferrers%2Fsha256"
        }

        # Redirected referrers response with one VEX artifact
        mock_redirect_resp = MagicMock()
        mock_redirect_resp.status_code = 200
        mock_redirect_resp.json.return_value = {
            "manifests": [
                {
                    "artifactType": "application/vex+json",
                    "digest": "sha256:vexdigest",
                    "mediaType": "application/vnd.oci.image.manifest.v1+json",
                }
            ]
        }

        # Manifest
        mock_manifest_resp = MagicMock()
        mock_manifest_resp.status_code = 200
        mock_manifest_resp.json.return_value = {
            "layers": [{"digest": "sha256:blobdigest", "mediaType": "application/vex+json"}]
        }

        # VEX blob
        mock_blob_resp = MagicMock()
        mock_blob_resp.status_code = 200
        mock_blob_resp.json.return_value = {
            "statements": [
                {
                    "vulnerability": {"name": "CVE-2024-1234"},
                    "status": "not_affected",
                    "justification": "vulnerable_code_not_present",
                }
            ]
        }

        mock_client.get.side_effect = [
            mock_challenge_resp,   # GET /v2/ → 401 challenge
            mock_token_resp,       # GET /token → 200, returns bearer token
            mock_referrers_resp,   # GET /referrers → 303
            mock_redirect_resp,    # manual follow of redirect → 200
            mock_manifest_resp,
            mock_blob_resp,
        ]

        result = check_vex_for_image("ghcr.io/owner/repo:latest", "sha256:abc123")
        assert result.found is True
        assert len(result.statements) == 1
        assert result.statements[0].vuln_id == "CVE-2024-1234"

        calls = mock_client.get.call_args_list
        # call[2] is the referrers request, call[3] is the manual redirect follow

        # The redirect URL must have the hash appended (GHCR truncation repair)
        redirect_call_url = calls[3][0][0]
        assert redirect_call_url == (
            "https://github.com/-/v2/packages/container/package/owner%2Frepo%2Freferrers%2Fsha256%3Aabc123"
        ), f"GHCR truncated redirect URL was not repaired; got: {redirect_call_url}"

        # Authorization header must survive the cross-origin redirect
        redirect_call_kwargs = calls[3][1]
        assert redirect_call_kwargs.get("headers", {}).get("Authorization") == "Bearer test-bearer-token", (
            "Authorization header must be forwarded to the redirect target"
        )

    @patch("backend.vex_discovery.httpx.Client")
    @patch("backend.vex_discovery._get_docker_auth", return_value=None)
    def test_referrers_404_fallback(self, mock_auth, MockClient):
        """Test fallback to tag scheme when referrers API returns 404."""
        mock_client = MagicMock()
        MockClient.return_value.__enter__ = MagicMock(return_value=mock_client)
        MockClient.return_value.__exit__ = MagicMock(return_value=False)

        # Token
        mock_token_resp = MagicMock()
        mock_token_resp.status_code = 200
        mock_token_resp.json.return_value = {"token": "test-token"}

        # Referrers API: 404
        mock_referrers_resp = MagicMock()
        mock_referrers_resp.status_code = 404

        # Fallback tag scheme: empty
        mock_fallback_resp = MagicMock()
        mock_fallback_resp.status_code = 200
        mock_fallback_resp.json.return_value = {"manifests": []}

        # .att tag: also not found
        mock_att_resp = MagicMock()
        mock_att_resp.status_code = 404

        mock_client.get.side_effect = [
            mock_token_resp,
            mock_referrers_resp,   # referrers API → 404
            mock_fallback_resp,    # OCI tag scheme → 200, empty manifests
            mock_att_resp,         # cosign .att tag → 404
        ]

        result = check_vex_for_image("nginx:latest", "sha256:abc123")
        assert result.found is False
        assert result.error is None

    @patch("backend.vex_discovery.httpx.Client")
    @patch("backend.vex_discovery._get_docker_auth", return_value=None)
    def test_cosign_att_tag_fallback(self, mock_auth, MockClient):
        """Test cosign legacy .att tag fallback (sha256-{hash}.att).

        cosign attest stores attestations as a standalone OCI manifest tagged
        sha256-{hash}.att rather than through the OCI referrers API. DockGuard
        must fetch that manifest directly and parse its layer blobs for VEX.
        """
        mock_client = MagicMock()
        MockClient.return_value.__enter__ = MagicMock(return_value=mock_client)
        MockClient.return_value.__exit__ = MagicMock(return_value=False)

        # Token (Docker Hub single-call flow)
        mock_token_resp = MagicMock()
        mock_token_resp.status_code = 200
        mock_token_resp.json.return_value = {"token": "test-token"}

        # Referrers API: 404 — registry doesn't know about referrers
        mock_referrers_resp = MagicMock()
        mock_referrers_resp.status_code = 404

        # OCI tag scheme (sha256-abc123): 404
        mock_oci_tag_resp = MagicMock()
        mock_oci_tag_resp.status_code = 404

        # Cosign .att manifest (sha256-abc123.att): found
        mock_att_resp = MagicMock()
        mock_att_resp.status_code = 200
        mock_att_resp.json.return_value = {
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "layers": [
                {
                    "mediaType": "application/vnd.dsse.envelope.v1+json",
                    "digest": "sha256:attblobdigest",
                    "size": 512,
                }
            ],
        }

        # Attestation blob: in-toto statement wrapping an OpenVEX predicate
        mock_blob_resp = MagicMock()
        mock_blob_resp.status_code = 200
        mock_blob_resp.json.return_value = {
            "predicateType": "https://openvex.dev/ns/v0.2.0",
            "predicate": {
                "statements": [
                    {
                        "vulnerability": {"name": "CVE-2024-9999"},
                        "status": "not_affected",
                        "justification": "vulnerable_code_not_present",
                    }
                ]
            },
        }

        mock_client.get.side_effect = [
            mock_token_resp,
            mock_referrers_resp,   # referrers API → 404
            mock_oci_tag_resp,     # OCI tag scheme → 404
            mock_att_resp,         # cosign .att tag → 200
            mock_blob_resp,        # attestation blob → 200
        ]

        result = check_vex_for_image("nginx:latest", "sha256:abc123")
        assert result.found is True
        assert len(result.statements) == 1
        assert result.statements[0].vuln_id == "CVE-2024-9999"
        assert result.statements[0].status == "not_affected"

        # Confirm the .att tag URL was constructed correctly
        att_call_url = mock_client.get.call_args_list[3][0][0]
        assert att_call_url.endswith("manifests/sha256-abc123.att"), (
            f"Expected .att tag URL, got: {att_call_url}"
        )

    @patch("backend.vex_discovery.httpx.Client")
    @patch("backend.vex_discovery._get_docker_auth", return_value=None)
    def test_cosign_att_tag_oci_index(self, mock_auth, MockClient):
        """Test .att tag that is an OCI index (multiple attestations).

        When cosign has pushed more than one attestation for an image (e.g.
        provenance + VEX) it promotes the sha256-{hash}.att tag to an OCI
        image index.  Each entry in the index is a separate manifest.  We
        must fetch each sub-manifest and scan its layers.
        """
        mock_client = MagicMock()
        MockClient.return_value.__enter__ = MagicMock(return_value=mock_client)
        MockClient.return_value.__exit__ = MagicMock(return_value=False)

        mock_token_resp = MagicMock()
        mock_token_resp.status_code = 200
        mock_token_resp.json.return_value = {"token": "test-token"}

        mock_referrers_resp = MagicMock()
        mock_referrers_resp.status_code = 404

        mock_oci_tag_resp = MagicMock()
        mock_oci_tag_resp.status_code = 404

        # .att tag → OCI image index with two entries
        mock_att_index_resp = MagicMock()
        mock_att_index_resp.status_code = 200
        mock_att_index_resp.json.return_value = {
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.index.v1+json",
            "manifests": [
                {
                    "mediaType": "application/vnd.oci.image.manifest.v1+json",
                    "digest": "sha256:provdigest",
                    "size": 256,
                },
                {
                    "mediaType": "application/vnd.oci.image.manifest.v1+json",
                    "digest": "sha256:vexdigest",
                    "size": 512,
                },
            ],
        }

        # First sub-manifest: provenance (non-VEX), has a layer with SLSA predicate
        mock_prov_manifest_resp = MagicMock()
        mock_prov_manifest_resp.status_code = 200
        mock_prov_manifest_resp.json.return_value = {
            "layers": [{"digest": "sha256:provblob", "mediaType": "application/vnd.dsse.envelope.v1+json"}]
        }

        mock_prov_blob_resp = MagicMock()
        mock_prov_blob_resp.status_code = 200
        # SLSA provenance raw DSSE — _extract_vex_from_blob must skip this
        slsa_intoto = {
            "_type": "https://in-toto.io/Statement/v0.1",
            "predicateType": "https://slsa.dev/provenance/v1",
            "subject": [],
            "predicate": {"builder": {"id": "https://github.com/Actions"}},
        }
        mock_prov_blob_resp.json.return_value = {
            "payload": base64.b64encode(json.dumps(slsa_intoto).encode()).decode(),
            "payloadType": "application/vnd.in-toto+json",
            "signatures": [],
        }

        # Second sub-manifest: VEX
        mock_vex_manifest_resp = MagicMock()
        mock_vex_manifest_resp.status_code = 200
        mock_vex_manifest_resp.json.return_value = {
            "layers": [{"digest": "sha256:vexblob", "mediaType": "application/vnd.dsse.envelope.v1+json"}]
        }

        mock_vex_blob_resp = MagicMock()
        mock_vex_blob_resp.status_code = 200
        vex_intoto = {
            "_type": "https://in-toto.io/Statement/v0.1",
            "predicateType": "https://openvex.dev/ns/v0.2.0",
            "subject": [],
            "predicate": {
                "statements": [
                    {"vulnerability": {"name": "CVE-2024-7777"}, "status": "not_affected"}
                ]
            },
        }
        mock_vex_blob_resp.json.return_value = {
            "payload": base64.b64encode(json.dumps(vex_intoto).encode()).decode(),
            "payloadType": "application/vnd.in-toto+json",
            "signatures": [],
        }

        # All sub-manifests are fetched first (index expansion), then blobs
        mock_client.get.side_effect = [
            mock_token_resp,
            mock_referrers_resp,       # referrers API → 404
            mock_oci_tag_resp,         # OCI tag scheme → 404
            mock_att_index_resp,       # .att tag → OCI index
            mock_prov_manifest_resp,   # fetch sub-manifest 1 (provenance)
            mock_vex_manifest_resp,    # fetch sub-manifest 2 (VEX)
            mock_prov_blob_resp,       # process blob from manifest 1 — skipped (SLSA)
            mock_vex_blob_resp,        # process blob from manifest 2 — VEX found
        ]

        result = check_vex_for_image("nginx:latest", "sha256:abc123")
        assert result.found is True
        assert len(result.statements) == 1
        assert result.statements[0].vuln_id == "CVE-2024-7777"
        assert result.statements[0].status == "not_affected"

    @patch("backend.vex_discovery.httpx.Client")
    @patch("backend.vex_discovery._get_docker_auth", return_value=None)
    def test_timeout_handled(self, _mock_auth, MockClient):
        """Test that timeouts are caught gracefully."""
        import httpx

        mock_client = MagicMock()
        MockClient.return_value.__enter__ = MagicMock(return_value=mock_client)
        MockClient.return_value.__exit__ = MagicMock(return_value=False)

        mock_client.get.side_effect = httpx.TimeoutException("Connection timed out")

        result = check_vex_for_image("nginx:latest", "sha256:abc123")
        assert result.found is False
        assert result.error == "Timeout checking registry for VEX"

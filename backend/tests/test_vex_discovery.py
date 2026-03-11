"""Tests for VEX discovery module."""

from unittest.mock import MagicMock, patch

from backend.vex_discovery import (
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

        mock_client.get.side_effect = [mock_token_resp, mock_referrers_resp]

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

        # Referrers API: 303 See Other (GHCR behaviour)
        mock_referrers_resp = MagicMock()
        mock_referrers_resp.status_code = 303
        mock_referrers_resp.headers = {
            "location": "https://github.com/-/v2/packages/container/package/owner%2Frepo%2Freferrers%2Fsha256%3Aabc123"
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
        referrers_call_url = calls[2][0][0]
        assert "%3A" in referrers_call_url, "digest colon should be %-encoded in the referrers URL"

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

        mock_client.get.side_effect = [mock_token_resp, mock_referrers_resp, mock_fallback_resp]

        result = check_vex_for_image("nginx:latest", "sha256:abc123")
        assert result.found is False
        assert result.error is None

    @patch("backend.vex_discovery.httpx.Client")
    @patch("backend.vex_discovery._get_docker_auth", return_value=None)
    def test_timeout_handled(self, mock_auth, MockClient):
        """Test that timeouts are caught gracefully."""
        import httpx

        mock_client = MagicMock()
        MockClient.return_value.__enter__ = MagicMock(return_value=mock_client)
        MockClient.return_value.__exit__ = MagicMock(return_value=False)

        mock_client.get.side_effect = httpx.TimeoutException("Connection timed out")

        result = check_vex_for_image("nginx:latest", "sha256:abc123")
        assert result.found is False
        assert result.error == "Timeout checking registry for VEX"

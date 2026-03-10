def test_patch_settings(api_client):
    client, test_db, _ = api_client
    response = client.patch("/settings", json={"settings": {"MAX_CONCURRENT_SCANS": "5"}})
    assert response.status_code == 200, f"Got {response.status_code}: {response.text}"


# ---------------------------------------------------------------------------
# GET /settings
# ---------------------------------------------------------------------------

def test_get_settings_returns_all_known_keys(api_client):
    client, _, _ = api_client
    response = client.get("/settings")
    assert response.status_code == 200
    data = response.json()
    assert "SCAN_INTERVAL_SECONDS" in data
    assert "MAX_CONCURRENT_SCANS" in data
    assert "DB_CHECK_INTERVAL_SECONDS" in data
    assert "DATA_RETENTION_DAYS" in data


def test_get_settings_default_source(api_client):
    client, _, _ = api_client
    data = client.get("/settings").json()
    assert data["SCAN_INTERVAL_SECONDS"]["source"] == "default"
    assert data["SCAN_INTERVAL_SECONDS"]["editable"] is True


def test_get_settings_db_source_after_patch(api_client):
    client, _, _ = api_client
    client.patch("/settings", json={"settings": {"SCAN_INTERVAL_SECONDS": "120"}})
    data = client.get("/settings").json()
    assert data["SCAN_INTERVAL_SECONDS"]["value"] == "120"
    assert data["SCAN_INTERVAL_SECONDS"]["source"] == "db"


# ---------------------------------------------------------------------------
# PATCH /settings — error cases
# ---------------------------------------------------------------------------

def test_patch_settings_unknown_key_returns_400(api_client):
    client, _, _ = api_client
    response = client.patch("/settings", json={"settings": {"UNKNOWN_KEY": "5"}})
    assert response.status_code == 400
    assert "Unknown setting" in response.json()["detail"]


def test_patch_settings_env_var_override_returns_400(api_client, monkeypatch):
    client, _, _ = api_client
    monkeypatch.setenv("SCAN_INTERVAL_SECONDS", "120")
    response = client.patch("/settings", json={"settings": {"SCAN_INTERVAL_SECONDS": "300"}})
    assert response.status_code == 400
    assert "overridden by an environment variable" in response.json()["detail"]

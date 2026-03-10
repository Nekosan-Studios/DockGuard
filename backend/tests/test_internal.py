from backend.tests.conftest import seed_scan, VULN_CRITICAL


# ---------------------------------------------------------------------------
# GET /db/tables
# ---------------------------------------------------------------------------

def test_get_db_tables_returns_app_tables(api_client):
    client, _, _ = api_client
    response = client.get("/db/tables")
    assert response.status_code == 200
    tables = response.json()["tables"]
    assert "scan" in tables
    assert "vulnerability" in tables
    assert "setting" in tables


def test_get_db_tables_excludes_alembic(api_client):
    client, _, _ = api_client
    tables = client.get("/db/tables").json()["tables"]
    assert not any("alembic" in t for t in tables)


# ---------------------------------------------------------------------------
# GET /db/table/{table_name}
# ---------------------------------------------------------------------------

def test_get_db_table_rows_returns_data(api_client):
    client, test_db, _ = api_client
    seed_scan(test_db, "nginx:latest", "sha256:aaaa", [VULN_CRITICAL])

    response = client.get("/db/table/scan")
    assert response.status_code == 200
    data = response.json()
    assert data["table"] == "scan"
    assert data["count"] == 1
    assert "image_name" in data["columns"]
    assert data["rows"][0]["image_name"] == "nginx:latest"


def test_get_db_table_rows_empty_table(api_client):
    client, _, _ = api_client
    response = client.get("/db/table/setting")
    assert response.status_code == 200
    assert response.json()["count"] == 0


def test_get_db_table_rows_not_found(api_client):
    client, _, _ = api_client
    response = client.get("/db/table/nonexistent_table")
    assert response.status_code == 404
    assert "not found" in response.json()["detail"]

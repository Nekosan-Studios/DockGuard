
def test_patch_settings(api_client):
    client, test_db, _ = api_client
    # Let's hit the endpoint that fails
    response = client.patch("/settings", json={"settings": {"MAX_CONCURRENT_SCANS": "5"}})
    
    # If 500, response.json() might fail, let's see why
    assert response.status_code == 200, f"Got {response.status_code}: {response.text}"

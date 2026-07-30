from backend.analyzer import app as analyzer_app


def test_dashboard_endpoint_returns_backend_metrics():
    client = analyzer_app.app.test_client()
    response = client.get("/api/dashboard")

    assert response.status_code == 200

    data = response.get_json()
    assert "events" in data
    assert "threats" in data
    assert "devices" in data
    assert "alerts" in data
    assert isinstance(data["events"], int)
    assert isinstance(data["threats"], int)
    assert isinstance(data["devices"], int)
    assert isinstance(data["alerts"], int)

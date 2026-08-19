from fastapi.testclient import TestClient
from main import app

client = TestClient(app)

def test_scan_url_safe():
    response = client.post("/scan-url", json={"url": "https://google.com"})
    assert response.status_code == 200
    assert response.json()["threat_level"] == "SAFE"

def test_scan_url_typosquatting():
    response = client.post("/scan-url", json={"url": "https://googIe.com"})
    assert response.status_code == 200
    assert response.json()["typosquatting_alert"] == True
    assert response.json()["threat_level"] == "CRITICAL"
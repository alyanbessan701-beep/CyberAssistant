import main
from fastapi.testclient import TestClient

client = TestClient(main.app)


def mock_safe_services(monkeypatch):
    async def fake_virustotal(domain: str) -> dict:
        return {
            "malicious": 0,
            "suspicious": 0,
            "available": True,
        }

    async def fake_phishtank(target_url: str) -> dict:
        return {
            "in_database": False,
            "valid": False,
            "available": True,
        }

    monkeypatch.setattr(
        main, "check_virustotal", fake_virustotal
    )
    monkeypatch.setattr(
        main, "check_phishtank", fake_phishtank
    )


def test_scan_url_safe(monkeypatch):
    mock_safe_services(monkeypatch)

    response = client.post(
        "/scan-url",
        params={"url": "https://google.com"},
    )

    assert response.status_code == 200
    assert response.json()["threat_level"] == "SAFE"
    assert response.json()["is_malicious"] is False
    assert response.json()["scan_complete"] is True


def test_scan_url_typosquatting(monkeypatch):
    mock_safe_services(monkeypatch)

    response = client.post(
        "/scan-url",
        params={"url": "https://gooogle.com"},
    )

    assert response.status_code == 200
    assert response.json()["typosquatting_alert"] is True
    assert response.json()["threat_level"] == "CRITICAL"
    assert response.json()["is_malicious"] is True


def test_scan_url_unknown_if_virustotal_unavailable(monkeypatch):
    async def fake_virustotal(domain: str) -> dict:
        return {
            "malicious": 0,
            "suspicious": 0,
            "available": False,
        }

    async def fake_phishtank(target_url: str) -> dict:
        return {
            "in_database": False,
            "valid": False,
            "available": True,
        }

    monkeypatch.setattr(
        main, "check_virustotal", fake_virustotal
    )
    monkeypatch.setattr(
        main, "check_phishtank", fake_phishtank
    )

    response = client.post(
        "/scan-url",
        params={"url": "https://google.com"},
    )

    assert response.status_code == 200
    assert response.json()["threat_level"] == "UNKNOWN"
    assert response.json()["scan_complete"] is False
    assert response.json()["virustotal_available"] is False

def test_scan_url_unknown_if_phishtank_unavailable(monkeypatch):
    async def fake_virustotal(domain: str) -> dict:
        return {
            "malicious": 0,
            "suspicious": 0,
            "available": True,
        }

    async def fake_phishtank(target_url: str) -> dict:
        return {
            "in_database": False,
            "valid": False,
            "available": False,
        }

    monkeypatch.setattr(
        main, "check_virustotal", fake_virustotal
    )
    monkeypatch.setattr(
        main, "check_phishtank", fake_phishtank
    )

    response = client.post(
        "/scan-url",
        params={"url": "https://google.com"},
    )

    assert response.status_code == 200
    assert response.json()["threat_level"] == "UNKNOWN"
    assert response.json()["scan_complete"] is False
    assert response.json()["phishtank_available"] is False


def test_phishtank_invalid_record_not_flagged(monkeypatch):
    async def fake_virustotal(domain: str) -> dict:
        return {
            "malicious": 0,
            "suspicious": 0,
            "available": True,
        }

    async def fake_phishtank(target_url: str) -> dict:
        return {
            "in_database": True,
            "valid": False,
            "verified": False,
            "available": True,
        }

    monkeypatch.setattr(
        main, "check_virustotal", fake_virustotal
    )
    monkeypatch.setattr(
        main, "check_phishtank", fake_phishtank
    )

    response = client.post(
        "/scan-url",
        params={"url": "https://www.wikipedia.org/"},
    )

    assert response.status_code == 200
    assert response.json()["phishtank_detected"] is False
    assert response.json()["threat_level"] == "SAFE"
    assert response.json()["scan_complete"] is True

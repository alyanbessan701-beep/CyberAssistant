from fastapi.testclient import TestClient
from main import app

client = TestClient(app)


def test_sos_is_not_reported_as_sent():
    response = client.post(
        "/trigger-sos",
        json={
            "user_id": "test_user_001",
            "threat_type": "SOCIAL_ENGINEERING",
            "threat_details": "Test emergency alert",
            "location": "Test location",
        },
    )

    assert response.status_code == 200

    result = response.json()
    assert result["success"] is False
    assert result["alert_details"]["status"] == "NOT_SENT"
    assert result["alert_details"]["user_id"] == "test_user_001"

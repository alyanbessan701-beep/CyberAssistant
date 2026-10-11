import main
from fastapi.testclient import TestClient

client = TestClient(main.app)


def test_scan_voice_rejects_unsupported_extension():
    response = client.post(
        "/scan-nlp-voice",
        files={
            "file": (
                "test.txt",
                b"not an audio file",
                "text/plain",
            )
        },
    )

    assert response.status_code == 400


def test_scan_voice_success(monkeypatch):
    monkeypatch.setattr(
        main,
        "transcribe_audio",
        lambda path: "This is a safe test message.",
    )

    monkeypatch.setattr(
        main,
        "extract_spoken_domains",
        lambda text: ["example.com"],
    )

    monkeypatch.setattr(
        main,
        "analyze_social_engineering",
        lambda text: {
            "is_social_engineering": False,
            "threat_level": "SAFE",
            "risk_score": 0.1,
            "detected_triggers": [],
        },
    )

    response = client.post(
        "/scan-nlp-voice",
        files={
            "file": (
                "test.wav",
                b"fake audio test data",
                "audio/wav",
            )
        },
    )

    assert response.status_code == 200

    result = response.json()
    assert result["filename"] == "test.wav"
    assert result["transcription"] == "This is a safe test message."
    assert result["extracted_domains"] == ["example.com"]
    assert result["social_engineering_detected"] is False
    assert result["threat_level"] == "SAFE"

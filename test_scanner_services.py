import asyncio
import scanner_services


class FakeResponse:
    def __init__(self, status_code, payload):
        self.status_code = status_code
        self.payload = payload

    def json(self):
        return self.payload


class FakeAsyncClient:
    def __init__(self, response):
        self.response = response

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    async def get(self, *args, **kwargs):
        return self.response

    async def post(self, *args, **kwargs):
        return self.response


def install_fake_response(monkeypatch, response):
    monkeypatch.setattr(
        scanner_services.httpx,
        "AsyncClient",
        lambda *args, **kwargs: FakeAsyncClient(response),
    )


def test_virustotal_success(monkeypatch):
    monkeypatch.setattr(
        scanner_services.settings,
        "VIRUSTOTAL_API_KEY",
        "test-key",
    )

    install_fake_response(
        monkeypatch,
        FakeResponse(
            200,
            {
                "data": {
                    "attributes": {
                        "last_analysis_stats": {
                            "malicious": 2,
                            "suspicious": 1,
                        }
                    }
                }
            },
        ),
    )

    result = asyncio.run(
        scanner_services.check_virustotal("example.com")
    )

    assert result["malicious"] == 2
    assert result["suspicious"] == 1
    assert result["available"] is True


def test_virustotal_http_error(monkeypatch):
    monkeypatch.setattr(
        scanner_services.settings,
        "VIRUSTOTAL_API_KEY",
        "test-key",
    )

    install_fake_response(
        monkeypatch,
        FakeResponse(401, {}),
    )

    result = asyncio.run(
        scanner_services.check_virustotal("example.com")
    )

    assert result["available"] is False


def test_phishtank_success(monkeypatch):
    install_fake_response(
        monkeypatch,
        FakeResponse(
            200,
            {
                "results": {
                    "in_database": True,
                    "valid": True,
                }
            },
        ),
    )

    result = asyncio.run(
        scanner_services.check_phishtank(
            "https://example.com/test"
        )
    )

    assert result["in_database"] is True
    assert result["valid"] is True
    assert result["available"] is True


def test_phishtank_http_error(monkeypatch):
    install_fake_response(
        monkeypatch,
        FakeResponse(503, {}),
    )

    result = asyncio.run(
        scanner_services.check_phishtank(
            "https://example.com/test"
        )
    )

    assert result["available"] is False

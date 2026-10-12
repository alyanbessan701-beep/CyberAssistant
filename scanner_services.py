import httpx
from config import settings


async def check_virustotal(domain: str) -> dict:
    api_key = settings.VIRUSTOTAL_API_KEY

    if not api_key:
        return {
            "malicious": 0,
            "suspicious": 0,
            "available": False,
        }

    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    headers = {"x-apikey": api_key}

    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            response = await client.get(url, headers=headers)

        if response.status_code != 200:
            return {
                "malicious": 0,
                "suspicious": 0,
                "available": False,
            }

        data = response.json()["data"]["attributes"]["last_analysis_stats"]

        return {
            "malicious": data.get("malicious", 0),
            "suspicious": data.get("suspicious", 0),
            "available": True,
        }

    except (httpx.RequestError, ValueError, KeyError, TypeError):
        return {
            "malicious": 0,
            "suspicious": 0,
            "available": False,
        }


async def check_phishtank(target_url: str) -> dict:
    default_result = {
        "in_database": False,
        "valid": False,
        "verified": False,
        "available": False,
    }

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.post(
                "https://checkurl.phishtank.com/checkurl/",
                data={
                    "url": target_url,
                    "format": "json",
                },
                headers={
                    "User-Agent": "phishtank/CyberAssistant",
                },
            )

        if response.status_code != 200:
            return default_result

        payload = response.json()

        if not isinstance(payload, dict):
            return default_result

        results = payload.get("results")

        if not isinstance(results, dict):
            return default_result

        return {
            "in_database": results.get("in_database") is True,
            "valid": results.get("valid") is True,
            "verified": results.get("verified") is True,
            "available": True,
        }

    except (httpx.RequestError, ValueError, TypeError):
        return default_result
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
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            response = await client.post(
                "https://checkurl.phishtank.com/checkurl/",
                data={
                    "url": target_url,
                    "format": "json",
                },
            )

        if response.status_code != 200:
            return {
                "in_database": False,
                "valid": False,
                "available": False,
            }

        results = response.json().get("results")

        if not isinstance(results, dict):
            return {
                "in_database": False,
                "valid": False,
                "available": False,
            }

        return {
            "in_database": results.get("in_database", False),
            "valid": results.get("valid", False),
            "available": True,
        }

    except (httpx.RequestError, ValueError, TypeError):
        return {
            "in_database": False,
            "valid": False,
            "available": False,
        }
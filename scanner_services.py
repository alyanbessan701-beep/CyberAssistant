import httpx
import asyncio

VIRUSTOTAL_API_KEY = "YOUR_VT_API_KEY"

async def check_virustotal(domain: str) -> dict:
    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(url, headers=headers, timeout=5.0)
            if response.status_code == 200:
                stats = response.json()['data']['attributes']['last_analysis_stats']
                return {"malicious": stats.get("malicious", 0), "suspicious": stats.get("suspicious", 0)}
        except Exception:
            pass
    return {"malicious": 0, "suspicious": 0}

async def check_phishtank(target_url: str) -> dict:
    async with httpx.AsyncClient() as client:
        try:
            res = await client.post("https://checkurl.phishtank.com/checkurl/", data={"url": target_url, "format": "json"}, timeout=5.0)
            if res.status_code == 200 and "results" in res.json():
                return {"in_database": res.json()["results"].get("in_database", False), "valid": res.json()["results"].get("valid", False)}
        except Exception:
            pass
    return {"in_database": False, "valid": False}
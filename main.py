from fastapi import FastAPI
from pydantic import BaseModel
import asyncio
from url_parser import parse_and_clean_url
from heuristics import detect_typosquatting
from scanner_services import check_virustotal, check_phishtank

app = FastAPI(title="CyberAssistant Scanner Engine")

class URLRequest(BaseModel):
    url: str

@app.post("/scan-url")
async def scan_url_endpoint(payload: URLRequest):
    parsed_data = parse_and_clean_url(payload.url)
    domain = parsed_data["full_domain"]
    
    vt_task = check_virustotal(domain)
    pt_task = check_phishtank(payload.url)
    
    vt_res, pt_res = await asyncio.gather(vt_task, pt_task)
    heuristic_res = detect_typosquatting(domain)
    
    threat_level = "SAFE"
    if vt_res["malicious"] > 0 or pt_res["valid"] or heuristic_res["typosquatting_detected"]:
        threat_level = "CRITICAL"
    elif vt_res["suspicious"] > 0:
        threat_level = "SUSPICIOUS"
        
    return {
        "url": payload.url,
        "domain": domain,
        "threat_level": threat_level,
        "virustotal_hits": vt_res["malicious"],
        "phishtank_detected": pt_res["valid"],
        "typosquatting_alert": heuristic_res["typosquatting_detected"],
        "impersonated_brand": heuristic_res["suspected_brand_impersonated"]
    }
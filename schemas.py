from pydantic import BaseModel
from typing import List, Optional

class URLScanResponse(BaseModel):
    url: str
    domain: str
    threat_level: str
    is_malicious: bool
    virustotal_hits: int
    phishtank_detected: bool
    typosquatting_alert: bool
    scan_complete: bool
    virustotal_available: bool
    phishtank_available: bool

class VoiceScanResponse(BaseModel):
    filename: str
    transcription: str
    extracted_domains: List[str]
    threat_level: str
    confidence_score: float
    social_engineering_detected: bool
    detected_triggers: List[str]
class SOSAlertRequest(BaseModel):
    user_id: str
    threat_type: str
    threat_details: str
    location: Optional[str] = "Unknown"
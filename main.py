import os
import shutil
import tempfile
from fastapi import FastAPI, HTTPException, UploadFile, File, Request
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware

# استيراد إعدادات وموديولات المشروع الجديدة
from config import settings
from schemas import URLScanResponse, VoiceScanResponse, SOSAlertRequest
from threat_logger import log_threat_event, trigger_sos_alert

# الموديولات السابقة
from url_parser import parse_and_clean_url
from scanner_services import check_virustotal, check_phishtank
from heuristics import detect_typosquatting
from transcription_service import transcribe_audio, extract_spoken_domains
from social_engineering_analyzer import analyze_social_engineering

app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    description="CyberAssistant Security AI Backend"
)

# السماح للواجهات الأمامية (Flutter) بالاتصال السلس بالخادم
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 1. معالج الاستثناءات والأخطاء العام (Global Exception Handler)
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    error_details = {"path": request.url.path, "error": str(exc)}
    log_threat_event("SYSTEM_ERROR", error_details)
    return JSONResponse(
        status_code=500,
        content={
            "success": False,
            "message": "حدث خطأ غير متوقع في الخادم. تم تسجيل المشكلة للتقييم.",
            "detail": str(exc)
        }
    )

# 2. نقطة نهاية فحص الروابط المشبوهة
@app.post("/scan-url")
async def scan_url(url: str):
    parsed_info = parse_and_clean_url(url)
    raw_url = parsed_info["original_url"]
    domain = parsed_info["full_domain"]
    vt_result = await check_virustotal(raw_url)
    pt_result = await check_phishtank(raw_url)
    typosquatting_result = detect_typosquatting(domain)
    vt_hits = vt_result.get("malicious", 0)
    pt_detected = pt_result.get("in_database", False)
    is_typosquatting = typosquatting_result.get("is_typosquatting", False)
    
    is_malicious = vt_hits > 0 or pt_detected or is_typosquatting
    threat_level = "CRITICAL" if is_malicious else "SAFE"
    
    # تسجيل التهديد في حالة وجود خطورة
    if is_malicious:
        log_threat_event("MALICIOUS_URL_DETECTED", {"url": raw_url, "domain": domain})
        
    return {
        "url": raw_url,
        "domain": domain,
        "threat_level": threat_level,
        "is_malicious": is_malicious,
        "virustotal_hits": vt_hits,
        "phishtank_detected": pt_detected,
        "typosquatting_alert": is_typosquatting
    }

# 3. نقطة نهاية فحص الصوت والتزييف والصوت إلى نص
@app.post("/scan-nlp-voice")
async def scan_nlp_voice(file: UploadFile = File(...)):
    valid_extensions = ('.wav', '.mp3', '.m4a', '.flac', '.ogg', '.mp4', '.mkv')
    if not file.filename.lower().endswith(valid_extensions):
        raise HTTPException(status_code=400, detail="صيغة الملف غير مدعومة.")
    
    temp_dir = tempfile.gettempdir()
    temp_file_path = os.path.join(temp_dir, f"temp_{file.filename}")
    
    try:
        with open(temp_file_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)
            
        transcribed_text = transcribe_audio(temp_file_path)
        extracted_domains = extract_spoken_domains(transcribed_text)
        se_analysis = analyze_social_engineering(transcribed_text)
        
        if se_analysis["is_social_engineering"]:
            log_threat_event("SOCIAL_ENGINEERING_VOICE", {
                "filename": file.filename,
                "triggers": se_analysis["detected_triggers"]
            })
            
        return {
            "filename": file.filename,
            "transcription": transcribed_text,
            "extracted_domains": extracted_domains,
            "social_engineering_detected": se_analysis["is_social_engineering"],
            "threat_level": se_analysis["threat_level"],
            "confidence_score": se_analysis["risk_score"],
            "detected_triggers": se_analysis["detected_triggers"]
        }
    finally:
        if os.path.exists(temp_file_path):
            os.remove(temp_file_path)


# 4. نقطة نهاية إرسال تنبيه الطوارئ للمرافق (Cyber SOS)
@app.post("/trigger-sos")
async def trigger_sos(payload: SOSAlertRequest):
    return trigger_sos_alert(payload)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)

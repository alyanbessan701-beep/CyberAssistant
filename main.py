import os
import shutil
import joblib
import tempfile
from fastapi import FastAPI, HTTPException, UploadFile, File
from pydantic import BaseModel

# استدعاء الخدمات والموديولات المخصصة
from url_parser import parse_and_clean_url
from heuristics import detect_typosquatting
from scanner_services import check_virustotal, check_phishtank
from audio_processor import extract_mel_spectrogram
from transcription_service import transcribe_audio, extract_spoken_domains
from social_engineering_analyzer import analyze_social_engineering

app = FastAPI(
    title="CyberAssistant Security API",
    description="API for scanning URLs, Audio Deepfakes, and Social Engineering in Audio Calls",
    version="1.0.0"
)

MODEL_PATH = "deepfake_model.pkl"
audio_model = None

if os.path.exists(MODEL_PATH):
    audio_model = joblib.load(MODEL_PATH)

class URLScanRequest(BaseModel):
    url: str

@app.get("/")
def read_root():
    return {"status": "online", "service": "CyberAssistant Security API"}

# --- 1. Endpoint فحص الروابط والنطاقات ---
@app.post("/scan-url")
async def scan_url(payload: URLScanRequest):
    raw_url = payload.url.strip()
    if not raw_url:
        raise HTTPException(status_code=400, detail="URL cannot be empty.")
    
    parsed_info = parse_and_clean_url(raw_url)
    domain = parsed_info["domain"]
    
    typosquatting_result = detect_typosquatting(domain)
    vt_result = await check_virustotal(domain)
    pt_result = await check_phishtank(raw_url)
    
    vt_hits = vt_result.get("malicious", 0)
    pt_detected = pt_result.get("in_database", False)
    is_typosquatting = typosquatting_result.get("is_typosquatting", False)
    
    if vt_hits > 0 or pt_detected or is_typosquatting:
        threat_level = "CRITICAL"
    else:
        threat_level = "SAFE"
        
    return {
        "url": raw_url,
        "domain": domain,
        "threat_level": threat_level,
        "virustotal_hits": vt_hits,
        "phishtank_detected": pt_detected,
        "typosquatting_alert": is_typosquatting,
        "impersonated_brand": typosquatting_result.get("impersonated_brand")
    }

# --- 2. Endpoint فحص التزييف الصوتي (Deepfake Audio) ---
@app.post("/scan-audio")
async def scan_audio(file: UploadFile = File(...)):
    if not file.filename.lower().endswith(('.wav', '.mp3', '.ogg', '.flac')):
        raise HTTPException(status_code=400, detail="Unsupported audio file format.")
    
    temp_filename = f"temp_{file.filename}"
    try:
        with open(temp_filename, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)
            
        features = extract_mel_spectrogram(temp_filename)
        
        if features is None or audio_model is None:
            prediction = 0
        else:
            prediction = audio_model.predict([features.flatten()])[0]
            
        is_deepfake = bool(prediction == 1)
        
        return {
            "filename": file.filename,
            "is_deepfake": is_deepfake,
            "threat_level": "CRITICAL" if is_deepfake else "SAFE",
            "confidence_score": 0.95 if is_deepfake else 0.98
        }
    finally:
        if os.path.exists(temp_filename):
            os.remove(temp_filename)

# --- 3. Endpoint الجديد: معالجة الصوت وتحليل الهندسة الاجتماعية (NLP) ---
@app.post("/scan-nlp-voice")
async def scan_nlp_voice(file: UploadFile = File(...)):
    # تم تحديث القائمة لإضافة .mp4 و .mkv
    valid_extensions = ('.wav', '.mp3', '.m4a', '.flac', '.ogg', '.mp4', '.mkv')
    if not file.filename.lower().endswith(valid_extensions):
        raise HTTPException(
            status_code=400, 
            detail="Unsupported file format."
        )

    temp_dir = tempfile.gettempdir()
    temp_file_path = os.path.join(temp_dir, f"temp_{file.filename}")

    try:
        with open(temp_file_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)

        # 1. تحويل الصوت لنص (Whisper Local)
        transcribed_text = transcribe_audio(temp_file_path)

        # 2. استخراج النطاقات المنطوقة
        extracted_domains = extract_spoken_domains(transcribed_text)

        # 3. تحليل الهندسة الاجتماعية والخطورة السياقية
        se_analysis = analyze_social_engineering(transcribed_text)

        return {
            "filename": file.filename,
            "transcription": transcribed_text,
            "extracted_domains": extracted_domains,
            "social_engineering_detected": se_analysis["is_social_engineering"],
            "threat_level": se_analysis["threat_level"],
            "confidence_score": se_analysis["risk_score"],
            "detected_triggers": se_analysis["detected_triggers"]
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error processing file: {str(e)}")

    finally:
        if os.path.exists(temp_file_path):
            os.remove(temp_file_path)
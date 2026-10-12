import os
import shutil
import tempfile

from fastapi import (
    FastAPI,
    HTTPException,
    UploadFile,
    File,
    Request,
)
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware

# إعدادات المشروع ومخططات الاستجابة
from config import settings
from schemas import (
    URLScanResponse,
    VoiceScanResponse,
    SOSAlertRequest,
)

# تسجيل التهديدات وطلبات الطوارئ
from threat_logger import (
    log_threat_event,
    trigger_sos_alert,
)

# خدمات فحص الروابط
from url_parser import parse_and_clean_url
from scanner_services import (
    check_virustotal,
    check_phishtank,
)
from heuristics import detect_typosquatting

# خدمات معالجة الصوت وتحليل الهندسة الاجتماعية
from transcription_service import (
    transcribe_audio,
    extract_spoken_domains,
)
from social_engineering_analyzer import (
    analyze_social_engineering,
)


# =========================================================
# 1. إنشاء تطبيق FastAPI
# =========================================================

app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    description="CyberAssistant Security AI Backend",
)


# =========================================================
# 2. إعداد CORS
# =========================================================

# السماح بالطلبات من المصادر المختلفة أثناء التطوير.
# عند تجهيز واجهة Flutter Web للإنتاج، يُفضّل تحديد
# المصادر المسموح بها بدل استخدام "*".
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


# =========================================================
# 3. معالج الأخطاء العام
# =========================================================

@app.exception_handler(Exception)
async def global_exception_handler(
    request: Request,
    exc: Exception,
):
    # تسجيل تفاصيل الخطأ داخل سجل الخادم
    error_details = {
        "path": request.url.path,
        "error": str(exc),
    }

    log_threat_event(
        "SYSTEM_ERROR",
        error_details,
    )

    # عدم إظهار تفاصيل الخطأ الداخلية للمستخدم
    return JSONResponse(
        status_code=500,
        content={
            "success": False,
            "message": (
                "حدث خطأ غير متوقع في الخادم. "
                "تم تسجيل المشكلة للتقييم."
            ),
        },
    )


# =========================================================
# 4. فحص الروابط المشبوهة
# =========================================================

@app.post(
    "/scan-url",
    response_model=URLScanResponse,
)
async def scan_url(url: str):
    # تحليل الرابط واستخراج النطاق
    parsed_info = parse_and_clean_url(url)

    raw_url = parsed_info["original_url"]
    domain = parsed_info["full_domain"]

    # تنفيذ عمليات الفحص الخارجية
    vt_result = await check_virustotal(domain)
    pt_result = await check_phishtank(raw_url)

    # الكشف المحلي عن النطاقات المشابهة
    typosquatting_result = detect_typosquatting(domain)

    # استخراج نتائج الخدمات
    vt_hits = vt_result.get("malicious", 0)
    pt_detected = (
    pt_result.get("in_database", False)
    and pt_result.get("verified", False)
    and pt_result.get("valid", False)
)
    is_typosquatting = typosquatting_result.get(
        "typosquatting_detected",
        False,
    )

    # التحقق من توافر خدمات الفحص
    vt_available = vt_result.get("available", False)
    pt_available = pt_result.get("available", False)

    scan_complete = (
        vt_available and pt_available
    )

    # تحديد ما إذا تم اكتشاف مؤشر تهديد
    is_malicious = (
        vt_hits > 0
        or pt_detected
        or is_typosquatting
    )

    # تحديد مستوى الخطورة
    if is_malicious:
        threat_level = "CRITICAL"

        # تسجيل اكتشاف تهديد
        log_threat_event(
            "MALICIOUS_URL_DETECTED",
            {
                "url": raw_url,
                "domain": domain,
            },
        )

    elif scan_complete:
        threat_level = "SAFE"

    else:
        # تعذّر إكمال إحدى عمليات الفحص الخارجية
        threat_level = "UNKNOWN"

    # إرجاع النتيجة مع حالة كل خدمة
    return {
        "url": raw_url,
        "domain": domain,
        "threat_level": threat_level,
        "is_malicious": is_malicious,
        "virustotal_hits": vt_hits,
        "phishtank_detected": pt_detected,
        "typosquatting_alert": is_typosquatting,
        "scan_complete": scan_complete,
        "virustotal_available": vt_available,
        "phishtank_available": pt_available,
    }


# =========================================================
# 5. فحص الصوت وتحويله إلى نص وتحليل الهندسة الاجتماعية
# =========================================================

@app.post(
    "/scan-nlp-voice",
    response_model=VoiceScanResponse,
)
async def scan_nlp_voice(
    file: UploadFile = File(...),
):
    # صيغ الملفات المدعومة في المسار الحالي
    valid_extensions = (
        ".wav",
        ".mp3",
        ".m4a",
        ".flac",
        ".ogg",
        ".mp4",
        ".mkv",
    )

    filename = file.filename or ""
    extension = os.path.splitext(filename)[1].lower()

    if extension not in valid_extensions:
        await file.close()

        raise HTTPException(
            status_code=400,
            detail="صيغة الملف غير مدعومة.",
        )

    temp_file_path = None

    try:
        # إنشاء ملف مؤقت باسم عشوائي لتجنب تعارض الأسماء
        with tempfile.NamedTemporaryFile(
            prefix="cyberassistant_",
            suffix=extension,
            delete=False,
        ) as temp_file:
            temp_file_path = temp_file.name

        # نسخ الملف المرفوع إلى الملف المؤقت
        with open(temp_file_path, "wb") as buffer:
            shutil.copyfileobj(
                file.file,
                buffer,
            )

        # تحويل الصوت إلى نص
        transcribed_text = transcribe_audio(
            temp_file_path
        )

        # استخراج النطاقات المذكورة في الصوت
        extracted_domains = extract_spoken_domains(
            transcribed_text
        )

        # تحليل النص لاكتشاف الهندسة الاجتماعية
        se_analysis = analyze_social_engineering(
            transcribed_text
        )

        # تسجيل المحاولات المشتبه بها
        if se_analysis["is_social_engineering"]:
            log_threat_event(
                "SOCIAL_ENGINEERING_VOICE",
                {
                    "filename": filename,
                    "triggers": se_analysis[
                        "detected_triggers"
                    ],
                },
            )

        # إرجاع نتيجة تحليل الصوت
        return {
            "filename": filename,
            "transcription": transcribed_text,
            "extracted_domains": extracted_domains,
            "social_engineering_detected": (
                se_analysis["is_social_engineering"]
            ),
            "threat_level": se_analysis["threat_level"],
            "confidence_score": se_analysis["risk_score"],
            "detected_triggers": (
                se_analysis["detected_triggers"]
            ),
        }

    finally:
        # حذف الملف المؤقت حتى عند حدوث خطأ
        if (
            temp_file_path is not None
            and os.path.exists(temp_file_path)
        ):
            os.remove(temp_file_path)

        await file.close()


# =========================================================
# 6. طلب تنبيه الطوارئ Cyber SOS
# =========================================================

@app.post("/trigger-sos")
async def trigger_sos(
    payload: SOSAlertRequest,
):
    return trigger_sos_alert(payload)


# =========================================================
# 7. تشغيل الخادم عند تشغيل الملف مباشرة
# =========================================================

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "main:app",
        host="127.0.0.1",
        port=8000,
        reload=True,
    )
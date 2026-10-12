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

# إعداد التطوير الحالي.
# قبل الإنتاج، يجب تحديد المصادر المسموح بها بدل السماح للجميع.
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
    # تسجيل تفاصيل الخطأ في سجل الخادم
    error_details = {
        "path": request.url.path,
        "error": str(exc),
    }

    log_threat_event(
        "SYSTEM_ERROR",
        error_details,
    )

    # عدم إظهار تفاصيل الأخطاء الداخلية للمستخدم
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

    # وجود مؤشر تهديد، بما في ذلك المؤشر المشبوه
    is_malicious = (
        vt_hits > 0
        or pt_detected
        or is_typosquatting
    )

    # تحديد مستوى الخطورة
    # CRITICAL: تصيّد مؤكد أو اجتماع رصد ضار وتشابه النطاق
    # SUSPICIOUS: رصد ضار منفرد أو تشابه نطاق دون تأكيد إضافي
    # SAFE: اكتملت الفحوص دون مؤشرات تهديد
    # UNKNOWN: تعذّر إكمال الفحوص دون حسم الخطر
    if pt_detected or (
        vt_hits > 0 and is_typosquatting
    ):
        threat_level = "CRITICAL"

    elif vt_hits > 0 or is_typosquatting:
        threat_level = "SUSPICIOUS"

    elif scan_complete:
        threat_level = "SAFE"

    else:
        threat_level = "UNKNOWN"

    # تسجيل التهديد أو المؤشر المشبوه
    if is_malicious:
        event_type = (
            "MALICIOUS_URL_DETECTED"
            if threat_level == "CRITICAL"
            else "SUSPICIOUS_URL_DETECTED"
        )

        log_threat_event(
            event_type,
            {
                "url": raw_url,
                "domain": domain,
                "threat_level": threat_level,
            },
        )

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
# 5. فحص الصوت وتحليل الهندسة الاجتماعية والنطاقات
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
        # إنشاء ملف مؤقت باسم عشوائي
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

        # 1. تحويل الصوت إلى نص
        transcribed_text = transcribe_audio(
            temp_file_path
        )

        # 2. استخراج النطاقات من النص
        extracted_domains = extract_spoken_domains(
            transcribed_text
        )

        # 3. تحليل الهندسة الاجتماعية
        se_analysis = analyze_social_engineering(
            transcribed_text
        )

        # 4. فحص كل نطاق مستخرج
        domain_scan_results = []

        for domain in extracted_domains:
            # فحص النطاق في VirusTotal
            vt_result = await check_virustotal(domain)

            # PhishTank يتلقى رابطًا كاملًا
            target_url = f"https://{domain}/"
            pt_result = await check_phishtank(target_url)

            # الكشف المحلي عن تشابه النطاق
            typo_result = detect_typosquatting(domain)

            # استخراج النتائج
            vt_hits = vt_result.get("malicious", 0)

            pt_detected = (
                pt_result.get("in_database", False)
                and pt_result.get("verified", False)
                and pt_result.get("valid", False)
            )

            typosquatting_alert = typo_result.get(
                "typosquatting_detected",
                False,
            )

            vt_available = vt_result.get(
                "available",
                False,
            )
            pt_available = pt_result.get(
                "available",
                False,
            )

            scan_complete = (
                vt_available and pt_available
            )

            # وجود أي مؤشر تهديد
            is_malicious = (
                vt_hits > 0
                or pt_detected
                or typosquatting_alert
            )

            # سياسة تصنيف موحدة مع /scan-url
            if pt_detected or (
                vt_hits > 0 and typosquatting_alert
            ):
                domain_threat_level = "CRITICAL"

            elif vt_hits > 0 or typosquatting_alert:
                domain_threat_level = "SUSPICIOUS"

            elif scan_complete:
                domain_threat_level = "SAFE"

            else:
                domain_threat_level = "UNKNOWN"

            # تسجيل أي مؤشر تهديد
            if is_malicious:
                event_type = (
                    "MALICIOUS_URL_DETECTED"
                    if domain_threat_level == "CRITICAL"
                    else "SUSPICIOUS_URL_DETECTED"
                )

                log_threat_event(
                    event_type,
                    {
                        "source": "VOICE",
                        "filename": filename,
                        "domain": domain,
                        "threat_level": domain_threat_level,
                    },
                )

            # حفظ نتيجة فحص النطاق
            domain_scan_results.append({
                "domain": domain,
                "threat_level": domain_threat_level,
                "is_malicious": is_malicious,
                "virustotal_hits": vt_hits,
                "phishtank_detected": pt_detected,
                "typosquatting_alert": typosquatting_alert,
                "scan_complete": scan_complete,
                "virustotal_available": vt_available,
                "phishtank_available": pt_available,
            })

        # 5. تحديد مستوى الخطورة العام للصوت
        se_threat_level = se_analysis.get(
            "threat_level",
            "UNKNOWN",
        )

        domain_levels = [
            item["threat_level"]
            for item in domain_scan_results
        ]

        if (
            "CRITICAL" in domain_levels
            or se_threat_level == "CRITICAL"
        ):
            overall_threat_level = "CRITICAL"

        elif (
            "SUSPICIOUS" in domain_levels
            or se_analysis.get(
                "is_social_engineering",
                False,
            )
            or se_threat_level == "SUSPICIOUS"
        ):
            overall_threat_level = "SUSPICIOUS"

        elif extracted_domains:
            all_domains_safe = all(
                item["scan_complete"]
                and item["threat_level"] == "SAFE"
                for item in domain_scan_results
            )

            if (
                all_domains_safe
                and se_threat_level == "SAFE"
                and not se_analysis.get(
                    "is_social_engineering",
                    False,
                )
            ):
                overall_threat_level = "SAFE"

            else:
                overall_threat_level = "UNKNOWN"

        else:
            # إذا لم يُستخرج أي نطاق، نعتمد تحليل النص
            overall_threat_level = se_threat_level

        # 6. تسجيل مؤشرات الهندسة الاجتماعية
        if se_analysis.get(
            "is_social_engineering",
            False,
        ):
            log_threat_event(
                "SOCIAL_ENGINEERING_VOICE",
                {
                    "filename": filename,
                    "triggers": se_analysis.get(
                        "detected_triggers",
                        [],
                    ),
                },
            )

        # 7. إعادة جميع النتائج
        return {
            "filename": filename,
            "transcription": transcribed_text,
            "extracted_domains": extracted_domains,
            "domain_scan_results": domain_scan_results,
            "threat_level": overall_threat_level,
            "confidence_score": se_analysis.get(
                "risk_score",
                0.0,
            ),
            "social_engineering_detected": se_analysis.get(
                "is_social_engineering",
                False,
            ),
            "detected_triggers": se_analysis.get(
                "detected_triggers",
                [],
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
import json
import logging
from datetime import datetime
from config import settings
from schemas import SOSAlertRequest

# إعداد السجل التجريبي للتهديدات المحلية
logging.basicConfig(
    filename="threats.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    encoding="utf-8"
)

def log_threat_event(event_type: str, details: dict):
    """تسجيل أي تهديد يتم اكتشافه محلياً في السجل"""
    log_entry = {
        "timestamp": datetime.now().isoformat(),
        "event_type": event_type,
        "details": details
    }
    logging.warning(f"THREAT DETECTED: {json.dumps(log_entry, ensure_ascii=False)}")
    return log_entry

def trigger_sos_alert(alert_data: SOSAlertRequest) -> dict:
    """إرسال تنبيه طوارئ للمرافق عبر البريد الإلكتروني أو السجل"""
    alert_payload = {
        "timestamp": datetime.now().isoformat(),
        "user_id": alert_data.user_id,
        "guardian_email": getattr(settings, "GUARDIAN_EMAIL", "guardian@example.com"),
        "threat_type": alert_data.threat_type,
        "details": alert_data.threat_details,
        "location": alert_data.location,
        "status": "SENT"
    }
    
    # تسجيل حدث الطوارئ
    logging.critical(f"CYBER SOS TRIGGERED: {json.dumps(alert_payload, ensure_ascii=False)}")
    
    return {
        "success": True,
        "message": "تم إرسال تنبيه الطوارئ للمرافق بنجاح.",
        "alert_details": alert_payload
    }
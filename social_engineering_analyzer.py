import re
from typing import Dict, List

# قاموس الأنماط والكلمات المفتاحية للهندسة الاجتماعية مع أوزان الخطورة
SE_KEYWORDS_WEIGHTS = {
    # الفئة 1: التحقق والرموز الحساسة
    "otp": 35,
    "one time password": 35,
    "verification code": 30,
    "passcode": 25,
    "password": 30,
    "pin number": 30,
    "cvv": 35,
    
    # الفئة 2: المعاملات المالية وتحويل الأموال
    "wire transfer": 25,
    "send money": 20,
    "bank account": 20,
    "credit card": 20,
    "gift card": 25,
    "crypto": 15,
    "bitcoin": 15,

    # الفئة 3: الضغط النفسي وتظاهر الشخصية (Urgency & Impersonation)
    "urgent": 15,
    "immediately": 15,
    "account suspended": 20,
    "technical support": 15,
    "security team": 15,
    "helpdesk": 10,
    "verify your identity": 20,
    "confirm your details": 15
}

# أفعال الطلب والإجبار السياقية (Action Verbs)
ACTION_VERBS = ["send", "give", "share", "verify", "transfer", "provide", "update"]

def analyze_social_engineering(text: str) -> Dict:
    text_lower = text.lower()
    matched_triggers: List[str] = []
    total_score = 0

    # 1. المطابقة المبنية على الأنماط والكلمات المفتاحية
    for trigger, weight in SE_KEYWORDS_WEIGHTS.items():
        if trigger in text_lower:
            matched_triggers.append(trigger)
            total_score += weight

    # 2. التحليل السياقي الخفيف لرصد أفعال الطلب والإجبار
    words = re.findall(r'\b\w+\b', text_lower)
    for verb in ACTION_VERBS:
        if verb in words:
            total_score += 5

    # 3. حساب درجة الخطورة واختيار Threat Level
    risk_score = min(total_score, 100)
    
    if risk_score >= 60:
        risk_level = "CRITICAL"
    elif risk_score >= 30:
        risk_level = "SUSPICIOUS"
    else:
        risk_level = "SAFE"

    return {
        "risk_score": risk_score / 100.0,
        "threat_level": risk_level,
        "detected_triggers": list(set(matched_triggers)),
        "is_social_engineering": risk_score >= 30
    }
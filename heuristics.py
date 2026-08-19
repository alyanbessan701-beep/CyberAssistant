from Levenshtein import distance

PROTECTED_DOMAINS = ["bank.com", "paypal.com", "google.com", "university.edu.jo"]

def detect_typosquatting(target_domain: str) -> dict:
    is_suspicious = False
    matched_brand = None
    
    for brand in PROTECTED_DOMAINS:
        dist = distance(target_domain.lower(), brand.lower())
        if 1 <= dist <= 2:
            is_suspicious = True
            matched_brand = brand
            break
            
    return {
        "typosquatting_detected": is_suspicious,
        "suspected_brand_impersonated": matched_brand
    }
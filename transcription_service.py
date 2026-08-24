import re
import os
import whisper
import tldextract

# تحميل نموذج Whisper المحلي
model = whisper.load_model("base")

def transcribe_audio(file_path: str) -> str:
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"Audio file not found at: {file_path}")
    
    result = model.transcribe(file_path)
    return result.get("text", "").strip()

def extract_spoken_domains(text: str) -> list:
    # تحويل الصيغ الصوتية للنطاقات (مثل dot إلى .)
    cleaned_text = re.sub(r'\b(dot|point)\b', '.', text, flags=re.IGNORECASE)
    cleaned_text = re.sub(r'\b(at)\b', '@', cleaned_text, flags=re.IGNORECASE)
    cleaned_text = re.sub(r'\s+', '', cleaned_text)

    domain_pattern = r'(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}'
    found_matches = re.findall(domain_pattern, cleaned_text)
    
    valid_domains = []
    for match in found_matches:
        extracted = tldextract.extract(match)
        if extracted.domain and extracted.suffix:
            valid_domains.append(f"{extracted.domain}.{extracted.suffix}")
            
    return list(set(valid_domains))
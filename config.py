import os
from dotenv import load_dotenv

load_dotenv()

class Settings:
    PROJECT_NAME: str = "CyberAssistant AI Backend"
    VERSION: str = "1.0.0"
    HOST: str = os.getenv("HOST", "0.0.0.0")
    PORT: int = int(os.getenv("PORT", 8000))
    DEBUG: bool = os.getenv("DEBUG", "True").lower() == "true"

    VIRUSTOTAL_API_KEY: str = os.getenv("VIRUSTOTAL_API_KEY", "")
    GUARDIAN_EMAIL: str = os.getenv("GUARDIAN_EMAIL_ALERT", "")

    WHISPER_MODEL: str = os.getenv("WHISPER_MODEL_TYPE", "base")

settings = Settings()
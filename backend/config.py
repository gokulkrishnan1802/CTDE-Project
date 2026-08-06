from pydantic_settings import BaseSettings
from typing import Optional


class Settings(BaseSettings):
    # App
    APP_NAME: str = "CyberTrust Decision Engine"
    APP_VERSION: str = "1.0.0"
    DEBUG: bool = False

    # Database
    DATABASE_URL: str = "sqlite:///./ctde.db"

    # JWT
    SECRET_KEY: str = "change-this-secret-key-in-production-use-openssl-rand"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24 * 7  # 7 days

    # External APIs (optional — graceful fallback when absent)
    VIRUSTOTAL_API_KEY: Optional[str] = None
    GOOGLE_SAFE_BROWSING_API_KEY: Optional[str] = None
    URLSCAN_API_KEY: Optional[str] = None
    ABUSEIPDB_API_KEY: Optional[str] = None

    # AI Provider (optional — rule-based fallback when absent)
    OPENAI_API_KEY: Optional[str] = None
    OPENAI_MODEL: str = "gpt-4o-mini"
    GOOGLE_API_KEY: Optional[str] = None
    GOOGLE_MODEL: str = "gemini-1.5-flash"

    # HTTP
    HTTP_TIMEOUT: float = 15.0
    HTTP_MAX_REDIRECTS: int = 10

    # Reports
    REPORTS_DIR: str = "reports"

    class Config:
        env_file = ".env"
        case_sensitive = True


settings = Settings()

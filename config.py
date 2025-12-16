import os
from typing import List, Optional
from pydantic import Field, validator
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    # Authentication & Security
    SECRET_KEY: str = Field(default="your-secret-key-change-in-production", env="SECRET_KEY")
    ALGORITHM: str = Field(default="HS256")
    ACCESS_TOKEN_EXPIRE_MINUTES: int = Field(default=30)
    REFRESH_TOKEN_EXPIRE_DAYS: int = Field(default=7)

    # Password Security
    PASSWORD_MIN_LENGTH: int = Field(default=8)
    PASSWORD_REQUIRE_UPPERCASE: bool = Field(default=True)
    PASSWORD_REQUIRE_LOWERCASE: bool = Field(default=True)
    PASSWORD_REQUIRE_DIGITS: bool = Field(default=True)
    PASSWORD_REQUIRE_SPECIAL_CHARS: bool = Field(default=True)

    # CORS & Security
    ALLOWED_ORIGINS: List[str] = Field(default_factory=lambda: ["http://localhost:3000", "http://localhost:8080"])
    ALLOWED_METHODS: List[str] = Field(default_factory=lambda: ["GET", "POST", "PUT", "DELETE"])
    ALLOWED_HEADERS: List[str] = Field(default_factory=lambda: ["*"])
    ALLOW_CREDENTIALS: bool = Field(default=True)

    # Security Headers
    ENABLE_SECURITY_HEADERS: bool = Field(default=True)
    ENABLE_HTTPS_REDIRECT: bool = Field(default=False)
    TRUSTED_HOSTS: List[str] = Field(default_factory=lambda: ["localhost", "127.0.0.1"])

    # Session Management
    SESSION_MAX_CONCURRENT: int = Field(default=3)  # Max concurrent sessions per user
    SESSION_TIMEOUT_MINUTES: int = Field(default=480)  # 8 hours

    # Input Validation
    MAX_USERNAME_LENGTH: int = Field(default=50)
    MAX_PASSWORD_LENGTH: int = Field(default=128)
    MAX_SECTOR_NAME_LENGTH: int = Field(default=50)
    ALLOWED_SECTOR_CHARS: str = Field(default="a-zA-Z0-9 _-")

    # Gemini API
    GEMINI_API_KEY: str = Field(default="", env="GEMINI_API_KEY")

    # Rate Limiting
    RATE_LIMIT_REQUESTS: int = Field(default=5)
    RATE_LIMIT_WINDOW_MINUTES: int = Field(default=1)

    # Data Collection
    SEARCH_MAX_RESULTS: int = Field(default=10)

    # Environment
    ENVIRONMENT: str = Field(default="development", env="ENVIRONMENT")

    @validator('SECRET_KEY')
    def validate_secret_key(cls, v):
        if len(v) < 32:
            raise ValueError('SECRET_KEY must be at least 32 characters long')
        return v

    @validator('ALLOWED_ORIGINS')
    def validate_origins(cls, v):
        # In production, don't allow wildcard origins
        if "*" in v and cls.ENVIRONMENT == "production":
            raise ValueError("Wildcard origins not allowed in production")
        return v

    class Config:
        env_file = ".env"

settings = Settings()

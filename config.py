import os
from pydantic import Field
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    # Authentication
    SECRET_KEY: str = Field(default="your-secret-key-change-in-production", env="SECRET_KEY")
    ALGORITHM: str = Field(default="HS256")
    ACCESS_TOKEN_EXPIRE_MINUTES: int = Field(default=30)

    # Gemini API
    GEMINI_API_KEY: str = Field(default="", env="GEMINI_API_KEY")

    # Rate Limiting
    RATE_LIMIT_REQUESTS: int = Field(default=5)
    RATE_LIMIT_WINDOW_MINUTES: int = Field(default=1)

    # Data Collection
    SEARCH_MAX_RESULTS: int = Field(default=10)

    class Config:
        env_file = ".env"

settings = Settings()

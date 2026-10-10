"""
backend/app/config.py

Application configuration and environment settings management.
"""

from typing import List, Union
from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings with environment variable overrides."""

    PROJECT_NAME: str = "AWS IAM Vulnerability Scanner and Visualizer"
    VERSION: str = "1.0.0"
    ENVIRONMENT: str = "development"
    DEBUG: bool = False

    # Database Configuration
    # Defaults to SQLite async for zero configuration local testing and development
    DATABASE_URL: str = "sqlite+aiosqlite:///./test.db"
    DB_ECHO: bool = False

    # CORS Configuration
    CORS_ORIGINS: List[str] = ["*"]

    # API Prefix
    API_V1_PREFIX: str = "/api"

    @field_validator("CORS_ORIGINS", mode="before")
    @classmethod
    def assemble_cors_origins(cls, v: Union[str, List[str]]) -> List[str]:
        if isinstance(v, str) and not v.startswith("["):
            return [i.strip() for i in v.split(",") if i.strip()]
        elif isinstance(v, (list, str)):
            return v  # type: ignore[return-value]
        return ["*"]

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore"
    )


settings = Settings()

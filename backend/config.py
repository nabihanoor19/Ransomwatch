from pydantic_settings import BaseSettings, SettingsConfigDict
from functools import lru_cache

class Settings(BaseSettings):
    # JWT Settings
    SECRET_KEY: str = "temporary-dev-secret-key-change-in-production-12345"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30

    # Database
    DATABASE_URL: str = "sqlite:///./ransomwatch.db"

    # Automatically read from .env if present
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )

# Cache the settings instance so we don't re-read the .env file on every import
@lru_cache
def get_settings() -> Settings:
    return Settings()

settings = get_settings()
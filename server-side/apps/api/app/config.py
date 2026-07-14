from functools import lru_cache
from pathlib import Path

from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


def _read_secret_file(path: str | None) -> str | None:
    if not path:
        return None
    file_path = Path(path)
    if not file_path.is_file():
        return None
    value = file_path.read_text(encoding="utf-8").strip()
    return value or None


class Settings(BaseSettings):
    model_config = SettingsConfigDict(extra="ignore")

    app_name: str = "VoWiFi Scan API"
    app_version: str = "0.1.0"
    api_v1_prefix: str = "/api/v1"
    enable_docs: bool = False

    # database_url as string or file.
    database_url: str | None = Field(
        default=None, description="SQLAlchemy async database URL"
    )
    database_url_file: str | None = None

    default_limit: int = 50
    max_limit: int = 200

    # directory holding the chached takeout files.
    takeout_dir: str = "/takeout"

    # SQLAlchemy pool tuning for high read concurrency.
    db_pool_size: int = 40
    db_max_overflow: int = 80
    db_pool_timeout_seconds: int = 30
    db_pool_recycle_seconds: int = 1800
    db_slow_query_ms: int = 1000

    # optional API auth key (direct value or file-backed).
    api_key: str | None = None
    api_key_file: str | None = None

    enable_rate_limit: bool = True
    rate_limit_requests_per_minute: int = 120
    # how long a client stays blocked (seconds) after exceeding the rate limit.
    rate_limit_timeout_seconds: float = 60.0

    log_level: str = "INFO"

    @field_validator("api_v1_prefix")
    @classmethod
    def validate_api_prefix(cls, value: str) -> str:
        if not value.startswith("/"):
            raise ValueError('api_v1_prefix must start with "/"')
        return value.rstrip("/") or "/"

    @model_validator(mode="after")
    def validate_limits(self):
        if self.default_limit < 1:
            raise ValueError("default_limit must be >= 1")
        if self.max_limit < 1:
            raise ValueError("max_limit must be >= 1")
        if self.max_limit < self.default_limit:
            raise ValueError("max_limit must be >= default_limit")
        if self.rate_limit_requests_per_minute < 1:
            raise ValueError("rate_limit_requests_per_minute must be >= 1")
        if self.rate_limit_timeout_seconds <= 0:
            raise ValueError("rate_limit_timeout_seconds must be > 0")
        if self.db_pool_size < 1:
            raise ValueError("db_pool_size must be >= 1")
        if self.db_max_overflow < 0:
            raise ValueError("db_max_overflow must be >= 0")
        if self.db_pool_timeout_seconds < 1:
            raise ValueError("db_pool_timeout_seconds must be >= 1")
        if self.db_pool_recycle_seconds < 1:
            raise ValueError("db_pool_recycle_seconds must be >= 1")
        if self.db_slow_query_ms < 1:
            raise ValueError("db_slow_query_ms must be >= 1")
        return self

    @property
    def resolved_database_url(self) -> str:
        file_value = _read_secret_file(self.database_url_file)
        direct_value = self.database_url.strip() if self.database_url else None
        resolved = file_value or direct_value
        if not resolved:
            raise RuntimeError("DATABASE_URL or DATABASE_URL_FILE must be set")
        return resolved

    @property
    def resolved_api_key(self) -> str | None:
        file_value = _read_secret_file(self.api_key_file)
        direct_value = self.api_key.strip() if self.api_key else None
        resolved = file_value or direct_value
        return resolved or None


@lru_cache
def get_settings() -> Settings:
    return Settings()

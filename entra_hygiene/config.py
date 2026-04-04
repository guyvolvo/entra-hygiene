from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=Path(__file__).resolve().parent.parent / ".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    tenant_id: str = ""
    client_id: str = ""
    client_secret: str = ""

    stale_days: int = 90
    secret_expiry_warning_days: int = 30

    scan_interval_hours: int = 6
    metrics_port: int = 5454


settings = Settings()

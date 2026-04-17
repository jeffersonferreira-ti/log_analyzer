"""Project configuration."""

from dataclasses import dataclass
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent


@dataclass(frozen=True)
class Settings:
    """Static application settings for the initial project setup."""

    app_name: str = "Log Analyzer"
    app_version: str = "0.1.0"
    samples_dir: Path = BASE_DIR / "data" / "samples"
    output_dir: Path = BASE_DIR / "data" / "output"


settings = Settings()

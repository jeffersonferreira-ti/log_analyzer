"""Application entry point for Log Analyzer."""

from app.ingestor.log_ingestor import LogIngestor
from config import settings


def main() -> None:
    """Load raw log files from the local sample directory."""
    ingestor = LogIngestor()
    log_files, failed_files = ingestor.load_from_directory(settings.samples_dir)

    print(f"{settings.app_name} is ready.")
    print(f"Loaded {len(log_files)} log files ({failed_files} failed)")


if __name__ == "__main__":
    main()

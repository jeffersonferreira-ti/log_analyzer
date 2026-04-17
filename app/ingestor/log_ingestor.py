"""Utilities for loading raw log files from a local directory."""

from pathlib import Path

from app.models.log_models import RawLogFile


class LogIngestor:
    """Load supported log files from disk for later processing."""

    SUPPORTED_EXTENSIONS = {".log", ".txt"}

    def load_from_directory(self, directory: str | Path) -> tuple[list[RawLogFile], int]:
        """Return loaded log files and a count of files that could not be read."""
        target_dir = Path(directory)

        if not target_dir.exists() or not target_dir.is_dir():
            return [], 0

        loaded_logs: list[RawLogFile] = []
        failed_files = 0

        for file_path in sorted(target_dir.iterdir()):
            if not file_path.is_file():
                continue

            if file_path.suffix.lower() not in self.SUPPORTED_EXTENSIONS:
                continue

            try:
                raw_content = file_path.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError):
                failed_files += 1
                continue

            loaded_logs.append(
                RawLogFile(
                    file_name=file_path.name,
                    file_path=str(file_path.resolve()),
                    raw_content=raw_content,
                )
            )

        return loaded_logs, failed_files

"""Base interfaces for log ingestion."""


class LogIngestor:
    """Minimal placeholder for future ingestion implementations."""

    def read(self, source: str) -> list[str]:
        """Return raw log lines from a source."""
        raise NotImplementedError

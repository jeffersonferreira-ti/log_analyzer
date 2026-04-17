"""Base interfaces for log parsing."""


class LogParser:
    """Minimal placeholder for future parser implementations."""

    def parse(self, line: str) -> dict:
        """Convert a raw log line into a structured record."""
        raise NotImplementedError

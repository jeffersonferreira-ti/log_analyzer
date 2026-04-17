"""Base interfaces for log analysis."""


class LogAnalyzer:
    """Minimal placeholder for future analysis implementations."""

    def analyze(self, records: list[dict]) -> list[dict]:
        """Inspect parsed records and return findings."""
        raise NotImplementedError

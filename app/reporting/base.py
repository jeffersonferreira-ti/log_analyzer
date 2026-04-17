"""Base interfaces for reporting."""


class ReportBuilder:
    """Minimal placeholder for future report generation."""

    def build(self, findings: list[dict]) -> str:
        """Create a report output from analysis findings."""
        raise NotImplementedError

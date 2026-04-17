"""Utilities for parsing raw log files into structured entries."""

from __future__ import annotations

from app.parser.base import BaseLogParser


class LogParser(BaseLogParser):
    """Parse raw log files line by line into structured log entries."""
    parser_name = "generic"

"""Shared utilities and common functionality for the Skwaq vulnerability assessment copilot."""

from .finding import Finding, AnalysisResult
from .utils import get_timestamp, detect_language, is_code_file, normalize_language

__all__ = [
    "Finding",
    "AnalysisResult",
    "get_timestamp",
    "detect_language",
    "is_code_file",
    "normalize_language",
]

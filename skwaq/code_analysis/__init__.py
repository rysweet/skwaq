"""Code analysis module for the Skwaq vulnerability assessment copilot.

This module provides functionality for analyzing source code to identify potential
security vulnerabilities using pattern matching, semantic analysis, and AST-based techniques.
"""

from .analyzer import CodeAnalyzer
from .patterns import VulnerabilityPatternRegistry

__all__ = ["CodeAnalyzer", "VulnerabilityPatternRegistry"]

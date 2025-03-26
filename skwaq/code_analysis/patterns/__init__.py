"""Vulnerability pattern management module.

This module handles the registration, storage, and matching of vulnerability patterns
for detecting security issues in source code.
"""

from .registry import VulnerabilityPatternRegistry
from .matcher import PatternMatcher

__all__ = ["VulnerabilityPatternRegistry", "PatternMatcher"]

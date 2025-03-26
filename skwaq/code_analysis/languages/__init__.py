"""Language-specific analysis module.

This module provides language-specific analyzers for detecting vulnerabilities
in different programming languages like Python, JavaScript, Java, etc.
"""

from .base import LanguageAnalyzer
from .python import PythonAnalyzer
from .javascript import JavaScriptAnalyzer
from .java import JavaAnalyzer
from .csharp import CSharpAnalyzer
from .php import PHPAnalyzer

__all__ = [
    "LanguageAnalyzer",
    "PythonAnalyzer",
    "JavaScriptAnalyzer",
    "JavaAnalyzer",
    "CSharpAnalyzer",
    "PHPAnalyzer",
]

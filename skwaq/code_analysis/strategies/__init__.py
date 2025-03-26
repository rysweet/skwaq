"""Analysis strategy module.

This module defines different strategies for analyzing code to detect vulnerabilities,
including pattern matching, semantic analysis, and AST-based analysis.
"""

from .base import AnalysisStrategy
from .pattern_matching import PatternMatchingStrategy
from .semantic_analysis import SemanticAnalysisStrategy
from .ast_analysis import ASTAnalysisStrategy

__all__ = [
    "AnalysisStrategy",
    "PatternMatchingStrategy",
    "SemanticAnalysisStrategy",
    "ASTAnalysisStrategy",
]

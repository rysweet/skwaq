"""Code analysis module for the Skwaq vulnerability assessment copilot.

This module implements static code analysis capabilities for identifying potential
vulnerabilities in source code, with integration for vulnerability pattern matching.

NOTE: This file provides backward compatibility APIs for the original implementation.
New code should use the modules in code_analysis/ directory instead.
"""

import asyncio
from typing import Dict, List, Optional, Any, Union

from ..utils.logging import get_logger, LogEvent
from ..code_analysis.analyzer import CodeAnalyzer
from ..code_analysis.patterns.registry import VulnerabilityPatternRegistry

logger = get_logger(__name__)


@LogEvent("repo_analysis")
async def analyze_repository(
    repo_id: int, 
    analysis_options: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """Analyze a repository for potential vulnerabilities.
    
    Args:
        repo_id: ID of the repository node in the graph
        analysis_options: Optional dictionary with analysis configuration
        
    Returns:
        Dictionary with analysis results and statistics
    """
    analyzer = CodeAnalyzer()
    return await analyzer.analyze_repository(repo_id, analysis_options)


@LogEvent("vulnerability_pattern_registration")
async def register_vulnerability_pattern(
    name: str, 
    description: str, 
    regex_pattern: Optional[str] = None,
    language: Optional[str] = None,
    severity: str = "Medium",
    cwe_id: Optional[str] = None,
    examples: Optional[List[Dict[str, str]]] = None,
) -> int:
    """Register a new vulnerability pattern.
    
    Args:
        name: Name of the vulnerability pattern
        description: Description of the vulnerability and its impact
        regex_pattern: Optional regex pattern for pattern matching
        language: Optional programming language the pattern applies to
        severity: Severity level (Low, Medium, High)
        cwe_id: Optional CWE ID associated with this vulnerability
        examples: Optional list of code examples with "code" and "language" keys
        
    Returns:
        ID of the created pattern node
    """
    registry = VulnerabilityPatternRegistry()
    return await registry.register_pattern(
        name=name,
        description=description,
        regex_pattern=regex_pattern,
        language=language,
        severity=severity,
        cwe_id=cwe_id,
        examples=examples,
    )


@LogEvent("pattern_generation")
async def generate_vulnerability_patterns() -> List[int]:
    """Generate vulnerability patterns from the CWE database.
    
    Returns:
        List of created pattern IDs
    """
    registry = VulnerabilityPatternRegistry()
    return await registry.generate_patterns_from_cwe()
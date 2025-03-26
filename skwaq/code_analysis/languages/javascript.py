"""JavaScript/TypeScript language analyzer for the Skwaq vulnerability assessment copilot.

This module provides JavaScript and TypeScript-specific vulnerability detection capabilities
by implementing language-specific analysis techniques.
"""

import re
from typing import Dict, List, Any, Optional, Set

from ...shared.finding import Finding
from ...utils.logging import get_logger
from .base import LanguageAnalyzer

logger = get_logger(__name__)


class JavaScriptAnalyzer(LanguageAnalyzer):
    """JavaScript/TypeScript code analyzer for vulnerability detection.

    This class implements JavaScript and TypeScript-specific analysis techniques
    to identify potential security vulnerabilities in JS/TS code.
    """

    def __init__(self):
        """Initialize the JavaScript/TypeScript analyzer."""
        super().__init__()
        self._setup_patterns()

    def get_language_name(self) -> str:
        """Get the name of the programming language.

        Returns:
            Language name
        """
        return "JavaScript"

    def get_file_extensions(self) -> Set[str]:
        """Get the set of file extensions supported by this analyzer.

        Returns:
            Set of supported file extensions
        """
        return {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}

    def _setup_patterns(self) -> None:
        """Set up built-in vulnerability patterns for JavaScript/TypeScript."""
        # SQL Injection patterns
        self.patterns["sql_injection"] = {
            "name": "SQL Injection",
            "description": "SQL query constructed with user input",
            "regex_pattern": r'(?:query|execute)\s*\(\s*[\'"]SELECT|UPDATE|INSERT|DELETE.+[\'"]\s*\+\s*|\$\{',
            "severity": "High",
            "confidence": 0.8,
        }

        # DOM XSS patterns
        self.patterns["dom_xss"] = {
            "name": "DOM-based XSS",
            "description": "Potential DOM-based XSS vulnerability",
            "regex_pattern": r'(?:innerHTML|outerHTML|document\.write|\\$\([\'"][^\'"]*[\'"]\\)\.html)\s*=\s*(?![\'"]\s*\+)',
            "severity": "High",
            "confidence": 0.7,
        }

        # Prototype Pollution patterns
        self.patterns["prototype_pollution"] = {
            "name": "Prototype Pollution",
            "description": "Potential prototype pollution vulnerability",
            "regex_pattern": r"(?:Object\.assign|jQuery\.extend|_\.merge)\s*\(\s*[^,]+\s*,\s*(?:[^{]|{[^}]*\[\s*[^]]*\])",
            "severity": "Medium",
            "confidence": 0.6,
        }

        # Path Traversal patterns
        self.patterns["path_traversal"] = {
            "name": "Path Traversal",
            "description": "Potential path traversal vulnerability in file operations",
            "regex_pattern": r'(?:fs\.(?:readFile|readdir|createReadStream|writeFile)|path\.(?:join|resolve))\s*\(\s*(?:[\'"][^\'"]*[\'"]\s*\+|\$\{)',
            "severity": "Medium",
            "confidence": 0.7,
        }

        # Hardcoded Secrets patterns
        self.patterns["hardcoded_secrets"] = {
            "name": "Hardcoded Secrets",
            "description": "Hardcoded credentials or API keys",
            "regex_pattern": r'(?:password|secret|apiKey|api_key|token|auth)\s*[:=]\s*[\'"][^\'"]{8,}[\'"]',
            "severity": "Medium",
            "confidence": 0.6,
        }

    def analyze_ast(self, file_id: int, content: str) -> List[Finding]:
        """Analyze JavaScript/TypeScript code for common vulnerabilities using AST-like techniques.

        Args:
            file_id: ID of the file in the database
            content: Content of the file

        Returns:
            List of findings
        """
        findings = []

        # Apply all registered patterns
        for pattern_name, pattern in self.patterns.items():
            pattern_findings = self.match_pattern(file_id, content, pattern_name)
            findings.extend(pattern_findings)

        # Check for eval and Function constructor
        eval_pattern_strings = [
            r"eval\s*\(\s*([^)]+)\s*\)",
            r"new\s+Function\s*\(\s*([^)]+)\s*\)",
            r'setTimeout\s*\(\s*[\'"]',
            r'setInterval\s*\(\s*[\'"]',
        ]

        for pattern_str in eval_pattern_strings:
            pattern = re.compile(pattern_str, re.MULTILINE)
            for match in pattern.finditer(content):
                line_number = content[: match.start()].count("\n") + 1
                findings.append(
                    Finding(
                        type="ast_analysis",
                        vulnerability_type="Code Injection",
                        description="Potentially unsafe code execution with dynamic input",
                        file_id=file_id,
                        line_number=line_number,
                        matched_text=match.group(0),
                        severity="High",
                        confidence=0.8,
                        suggestion="Avoid using eval() or new Function() with untrusted input. Use safer alternatives.",
                    )
                )

        # Check for DOM XSS
        dom_xss_pattern_strings = [
            r'(?:innerHTML|outerHTML|document\.write|\\$\([\'"][^\'"]*[\'"]\\)\.html)\s*=\s*(?![\'"]\s*\+)',
            r'location(?:\.href|\[[\'"]\s*href\s*[\'"]\])\s*=',
        ]

        for pattern_str in dom_xss_pattern_strings:
            pattern = re.compile(pattern_str, re.MULTILINE)
            for match in pattern.finditer(content):
                line_number = content[: match.start()].count("\n") + 1
                findings.append(
                    Finding(
                        type="ast_analysis",
                        vulnerability_type="Cross-Site Scripting (XSS)",
                        description="Potential DOM-based XSS vulnerability",
                        file_id=file_id,
                        line_number=line_number,
                        matched_text=match.group(0),
                        severity="High",
                        confidence=0.7,
                        suggestion="Use textContent instead of innerHTML, or sanitize input with a library like DOMPurify.",
                    )
                )

        # Check for SQL injection in various JS/TS libraries
        sql_pattern_strings = [
            r'(?:query|execute)\s*\(\s*[\'"]SELECT|UPDATE|INSERT|DELETE.+\$\{',
            r'(?:query|execute)\s*\(\s*[\'"]SELECT|UPDATE|INSERT|DELETE.+\'\s*\+\s*',
        ]

        for pattern_str in sql_pattern_strings:
            pattern = re.compile(pattern_str, re.MULTILINE | re.IGNORECASE)
            for match in pattern.finditer(content):
                line_number = content[: match.start()].count("\n") + 1
                findings.append(
                    Finding(
                        type="ast_analysis",
                        vulnerability_type="SQL Injection",
                        description="Potential SQL injection vulnerability in database query",
                        file_id=file_id,
                        line_number=line_number,
                        matched_text=match.group(0),
                        severity="High",
                        confidence=0.7,
                        suggestion="Use parameterized queries or prepared statements instead of string concatenation/interpolation.",
                    )
                )

        # Check for prototype pollution
        proto_pattern_strings = [
            r"Object\.assign\s*\(\s*[^,]+\s*,",
            r"for\s*\(\s*(?:var|let|const)?\s*\w+\s+in\s+",
        ]

        for pattern_str in proto_pattern_strings:
            pattern = re.compile(pattern_str, re.MULTILINE)
            for match in pattern.finditer(content):
                line_number = content[: match.start()].count("\n") + 1
                findings.append(
                    Finding(
                        type="ast_analysis",
                        vulnerability_type="Prototype Pollution",
                        description="Potential prototype pollution vulnerability",
                        file_id=file_id,
                        line_number=line_number,
                        matched_text=match.group(0),
                        severity="Medium",
                        confidence=0.6,
                        suggestion="Use Object.hasOwnProperty checks when iterating over object properties, and consider using Object.create(null) for maps.",
                    )
                )

        return findings

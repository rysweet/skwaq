"""C# language analyzer for the Skwaq vulnerability assessment copilot.

This module provides C#-specific vulnerability detection capabilities
by implementing language-specific analysis techniques and integrating with Blarify.
"""

import re
from typing import Dict, List, Any, Optional, Set

from ...shared.finding import Finding
from ...utils.logging import get_logger
from .base import LanguageAnalyzer

logger = get_logger(__name__)


class CSharpAnalyzer(LanguageAnalyzer):
    """C#-specific code analyzer for vulnerability detection.

    This class implements C#-specific analysis techniques to identify
    potential security vulnerabilities in C# code.
    """

    def __init__(self):
        """Initialize the C# analyzer."""
        super().__init__()
        self._setup_patterns()

    def get_language_name(self) -> str:
        """Get the name of the programming language.

        Returns:
            Language name
        """
        return "C#"

    def get_file_extensions(self) -> Set[str]:
        """Get the set of file extensions supported by this analyzer.

        Returns:
            Set of supported file extensions
        """
        return {".cs"}

    def _setup_patterns(self) -> None:
        """Set up built-in vulnerability patterns for C#."""
        # SQL Injection patterns
        self.patterns["sql_injection"] = {
            "name": "SQL Injection",
            "description": "SQL query constructed with user input",
            "regex_pattern": r'new\s+SqlCommand\s*\(\s*(?:@?".*"\s*\+|string\.Format|[^"]*\+\s*|@\$".*\{)',
            "severity": "High",
            "confidence": 0.8,
        }

        # Command Injection patterns
        self.patterns["command_injection"] = {
            "name": "Command Injection",
            "description": "Command execution with user input",
            "regex_pattern": r'(?:Process\.Start|System\.Diagnostics\.Process\.Start)\s*\(\s*(?:@?\".*\"\s*\+|string\.Format|@\$\".*\{)',
            "severity": "High",
            "confidence": 0.8,
        }

        # XSS prevention bypass
        self.patterns["xss_prevention_bypass"] = {
            "name": "XSS Prevention Bypass",
            "description": "Potential XSS vulnerability through HtmlString or Raw method",
            "regex_pattern": r'(?:Html\.Raw|new\s+HtmlString)\s*\(',
            "severity": "Medium",
            "confidence": 0.7,
        }

        # Path Traversal patterns
        self.patterns["path_traversal"] = {
            "name": "Path Traversal",
            "description": "Potential path traversal vulnerability in file operations",
            "regex_pattern": r'(?:File\.(?:ReadAllText|ReadAllBytes|OpenRead|OpenWrite)|Path\.Combine)\s*\(\s*(?:@?\".*\"\s*\+|string\.Format|@\$\".*\{)',
            "severity": "High",
            "confidence": 0.7,
        }

        # Insecure Deserialization
        self.patterns["insecure_deserialization"] = {
            "name": "Insecure Deserialization",
            "description": "Potentially unsafe deserialization of user-controlled data",
            "regex_pattern": r'(?:BinaryFormatter|LosFormatter|NetDataContractSerializer|XmlSerializer)\.Deserialize',
            "severity": "High",
            "confidence": 0.8,
        }

        # Hardcoded Secrets patterns
        self.patterns["hardcoded_secrets"] = {
            "name": "Hardcoded Secrets",
            "description": "Hardcoded credentials or API keys",
            "regex_pattern": r'(?:password|secret|api[_-]?key|token|credential)\s*=\s*@?\"[^\"]{8,}\"',
            "severity": "Medium",
            "confidence": 0.6,
        }

        # CSRF Protection Disabled
        self.patterns["csrf_disabled"] = {
            "name": "CSRF Protection Disabled",
            "description": "CSRF protection is explicitly disabled",
            "regex_pattern": r'\[\s*ValidateAntiForgeryToken\s*\(\s*false\s*\)\s*\]|\[(?:AllowAnonymous|HttpGet)\](?!\s*\[\s*ValidateAntiForgeryToken\s*\])',
            "severity": "Medium",
            "confidence": 0.7,
        }

    def analyze_ast(self, file_id: int, content: str) -> List[Finding]:
        """Analyze C# code for common vulnerabilities using AST-like techniques.

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

        # Check for dynamic code execution
        eval_pattern = re.compile(r"CodeDom\.Compiler|System\.Reflection\.Assembly\.Load", re.MULTILINE)
        for match in eval_pattern.finditer(content):
            line_number = content[: match.start()].count("\n") + 1
            findings.append(
                Finding(
                    type="ast_analysis",
                    vulnerability_type="Code Injection",
                    description="Potentially unsafe dynamic code execution",
                    file_id=file_id,
                    line_number=line_number,
                    matched_text=match.group(0),
                    severity="High",
                    confidence=0.8,
                    suggestion="Avoid dynamic code execution with untrusted input. Use safer alternatives.",
                )
            )

        # Check for weak crypto
        weak_crypto_pattern = re.compile(r"(?:MD5|SHA1|DES|RC2)(?:CryptoServiceProvider|Cng)", re.MULTILINE)
        for match in weak_crypto_pattern.finditer(content):
            line_number = content[: match.start()].count("\n") + 1
            findings.append(
                Finding(
                    type="ast_analysis",
                    vulnerability_type="Weak Cryptography",
                    description="Use of outdated or weak cryptographic algorithm",
                    file_id=file_id,
                    line_number=line_number,
                    matched_text=match.group(0),
                    severity="Medium",
                    confidence=0.7,
                    suggestion="Use modern cryptography such as AES with appropriate key sizes and secure modes.",
                )
            )

        # Check for unsafe LDAP queries
        ldap_pattern = re.compile(r"DirectorySearcher\s*\(\s*\".*\"\s*\+", re.MULTILINE)
        for match in ldap_pattern.finditer(content):
            line_number = content[: match.start()].count("\n") + 1
            findings.append(
                Finding(
                    type="ast_analysis",
                    vulnerability_type="LDAP Injection",
                    description="Potential LDAP injection in directory search query",
                    file_id=file_id,
                    line_number=line_number,
                    matched_text=match.group(0),
                    severity="High",
                    confidence=0.7,
                    suggestion="Escape special characters in LDAP filters. Consider using parameterized methods.",
                )
            )

        # Check for request validation bypass
        validation_bypass_pattern = re.compile(r"\[ValidateInput\(\s*false\s*\)\]|\[AllowHtml\]", re.MULTILINE)
        for match in validation_bypass_pattern.finditer(content):
            line_number = content[: match.start()].count("\n") + 1
            findings.append(
                Finding(
                    type="ast_analysis",
                    vulnerability_type="Request Validation Bypass",
                    description="Request validation explicitly disabled",
                    file_id=file_id,
                    line_number=line_number,
                    matched_text=match.group(0),
                    severity="Medium",
                    confidence=0.7,
                    suggestion="Avoid disabling request validation. If necessary, implement custom validation.",
                )
            )

        return findings
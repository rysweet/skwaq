"""Python language analyzer for the Skwaq vulnerability assessment copilot.

This module provides Python-specific vulnerability detection capabilities
by implementing language-specific analysis techniques.
"""

import re
from typing import Dict, List, Any, Optional, Set

from ...shared.finding import Finding
from ...utils.logging import get_logger
from .base import LanguageAnalyzer

logger = get_logger(__name__)


class PythonAnalyzer(LanguageAnalyzer):
    """Python-specific code analyzer for vulnerability detection.
    
    This class implements Python-specific analysis techniques to identify
    potential security vulnerabilities in Python code.
    """
    
    def __init__(self):
        """Initialize the Python analyzer."""
        super().__init__()
        self._setup_patterns()
    
    def get_language_name(self) -> str:
        """Get the name of the programming language.
        
        Returns:
            Language name
        """
        return "Python"
    
    def get_file_extensions(self) -> Set[str]:
        """Get the set of file extensions supported by this analyzer.
        
        Returns:
            Set of supported file extensions
        """
        return {".py", ".pyx", ".pyi", ".pyw"}
    
    def _setup_patterns(self) -> None:
        """Set up built-in vulnerability patterns for Python."""
        # SQL Injection patterns
        self.patterns["sql_injection"] = {
            "name": "SQL Injection",
            "description": "SQL query constructed with user input",
            "regex_pattern": r'execute\s*\(\s*(?:f["\']SELECT|UPDATE|INSERT|DELETE.+\{([^}]+)\}|[\'"].+[\'"]\s*(?:\+|\.format|\%))',
            "severity": "High",
            "confidence": 0.8
        }
        
        # Command Injection patterns
        self.patterns["command_injection"] = {
            "name": "Command Injection",
            "description": "Command execution with user input",
            "regex_pattern": r'(?:subprocess\.(?:call|run|Popen)|os\.(?:system|popen|exec[lv][ep]?))\s*\(\s*(?:f["\']|[\'"]\s*\+\s*|[\'"]\s*\.format)',
            "severity": "High",
            "confidence": 0.8
        }
        
        # Insecure Deserialization patterns
        self.patterns["insecure_deserialization"] = {
            "name": "Insecure Deserialization",
            "description": "Unsafe deserialization of potentially untrusted data",
            "regex_pattern": r'(?:pickle|marshal|yaml)\.(?:loads?|unsafe_load)\s*\(',
            "severity": "High",
            "confidence": 0.7
        }
        
        # Path Traversal patterns
        self.patterns["path_traversal"] = {
            "name": "Path Traversal",
            "description": "Potential path traversal vulnerability in file operations",
            "regex_pattern": r'(?:open|os\.path\.(?:join|abspath)|pathlib\.Path)\s*\(\s*(?:[\'"][^\'"]*[\'"]\s*\+|f[\'"][^\'"]*\{)',
            "severity": "Medium",
            "confidence": 0.6
        }
        
        # Hardcoded Secrets patterns
        self.patterns["hardcoded_secrets"] = {
            "name": "Hardcoded Secrets",
            "description": "Hardcoded credentials or API keys",
            "regex_pattern": r'(?:password|secret|api_key|apikey|token|auth)\s*=\s*[\'"][^\'"]{8,}[\'"]',
            "severity": "Medium",
            "confidence": 0.6
        }
    
    def analyze_ast(self, file_id: int, content: str) -> List[Finding]:
        """Analyze Python code for common vulnerabilities using AST-like techniques.
        
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
        
        # Check for dangerous eval usage
        eval_pattern = re.compile(r'eval\s*\(\s*([^)]+)\s*\)', re.MULTILINE)
        for match in eval_pattern.finditer(content):
            line_number = content[:match.start()].count('\n') + 1
            findings.append(Finding(
                type="ast_analysis",
                vulnerability_type="Code Injection",
                description="Potentially unsafe use of eval() with dynamic input",
                file_id=file_id,
                line_number=line_number,
                matched_text=match.group(0),
                severity="High",
                confidence=0.8,
                suggestion="Avoid using eval() with untrusted input. Use safer alternatives."
            ))
        
        # Check for SQL injection in various DB libraries
        sql_patterns = [
            # Raw SQL queries
            re.compile(r'execute\s*\(\s*f["\']SELECT|UPDATE|INSERT|DELETE.+\{([^}]+)\}', re.MULTILINE | re.IGNORECASE),
            re.compile(r'execute\s*\(\s*["\']SELECT|UPDATE|INSERT|DELETE.+\%\(|\%s|\$\d+', re.MULTILINE | re.IGNORECASE),
            # Django raw queries
            re.compile(r'raw\s*\(\s*f["\']SELECT|UPDATE|INSERT|DELETE', re.MULTILINE | re.IGNORECASE),
        ]
        
        for pattern in sql_patterns:
            for match in pattern.finditer(content):
                line_number = content[:match.start()].count('\n') + 1
                findings.append(Finding(
                    type="ast_analysis",
                    vulnerability_type="SQL Injection",
                    description="Potential SQL injection vulnerability in database query",
                    file_id=file_id,
                    line_number=line_number,
                    matched_text=match.group(0),
                    severity="High",
                    confidence=0.7,
                    suggestion="Use parameterized queries or ORM methods instead of string formatting in SQL queries."
                ))
        
        # Check for command injection
        cmd_patterns = [
            re.compile(r'subprocess\.(?:call|run|Popen)\s*\(\s*(?:f["\']|[\'"]\s*\+\s*|[\'"]\s*\.format)', re.MULTILINE),
            re.compile(r'os\.(?:system|popen|exec[lv][ep]?)\s*\(\s*(?:f["\']|[\'"]\s*\+\s*|[\'"]\s*\.format)', re.MULTILINE),
        ]
        
        for pattern in cmd_patterns:
            for match in pattern.finditer(content):
                line_number = content[:match.start()].count('\n') + 1
                findings.append(Finding(
                    type="ast_analysis",
                    vulnerability_type="Command Injection",
                    description="Potential command injection vulnerability in subprocess/os call",
                    file_id=file_id,
                    line_number=line_number,
                    matched_text=match.group(0),
                    severity="High",
                    confidence=0.8,
                    suggestion="Avoid using string formatting with shell commands. Use subprocess with shell=False and pass arguments as a list."
                ))
        
        # Check for pickle/marshal/yaml deserialization
        deserial_patterns = [
            re.compile(r'pickle\.(?:loads|load)\s*\(', re.MULTILINE),
            re.compile(r'marshal\.(?:loads|load)\s*\(', re.MULTILINE),
            re.compile(r'yaml\.(?:load|unsafe_load)\s*\(', re.MULTILINE),
        ]
        
        for pattern in deserial_patterns:
            for match in pattern.finditer(content):
                line_number = content[:match.start()].count('\n') + 1
                findings.append(Finding(
                    type="ast_analysis",
                    vulnerability_type="Insecure Deserialization",
                    description="Unsafe deserialization of potentially untrusted data",
                    file_id=file_id,
                    line_number=line_number,
                    matched_text=match.group(0),
                    severity="High",
                    confidence=0.7,
                    suggestion="Use safer alternatives like JSON. If you must use these modules, ensure data comes from trusted sources."
                ))
        
        return findings
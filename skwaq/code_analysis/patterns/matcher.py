"""Pattern matching module for vulnerability detection.

This module handles pattern matching operations for detecting vulnerabilities
in source code files.
"""

import re
from typing import Dict, List, Any, Optional

from ...shared.finding import Finding
from ...utils.logging import get_logger

logger = get_logger(__name__)


class PatternMatcher:
    """Pattern matcher for vulnerability detection.
    
    This class handles the application of regular expression patterns
    to detect potential vulnerabilities in source code.
    """
    
    def __init__(self) -> None:
        """Initialize the pattern matcher."""
        self.compiled_patterns: Dict[str, re.Pattern] = {}
    
    def compile_pattern(self, name: str, regex_pattern: str) -> bool:
        """Compile a regular expression pattern.
        
        Args:
            name: Name of the pattern
            regex_pattern: Regular expression pattern string
            
        Returns:
            True if compilation succeeded, False otherwise
        """
        try:
            if not regex_pattern:
                logger.warning(f"Empty regex pattern for '{name}'")
                return False
                
            self.compiled_patterns[name] = re.compile(
                regex_pattern, re.MULTILINE | re.DOTALL
            )
            return True
            
        except re.error as e:
            logger.error(f"Failed to compile regex pattern '{name}': {e}")
            return False
    
    def match_pattern(
        self,
        file_id: int,
        content: str,
        pattern_def: Dict[str, Any]
    ) -> List[Finding]:
        """Match a pattern against file content.
        
        Args:
            file_id: ID of the file in the database
            content: Content to match against
            pattern_def: Pattern definition dictionary
            
        Returns:
            List of findings
        """
        pattern_name = pattern_def.get("name", "Unknown Pattern")
        regex_pattern = pattern_def.get("regex_pattern", "")
        description = pattern_def.get("description", "")
        pattern_id = pattern_def.get("pattern_id")
        severity = pattern_def.get("severity", "Medium")
        
        # Compile pattern if not already compiled
        if pattern_name not in self.compiled_patterns:
            if not self.compile_pattern(pattern_name, regex_pattern):
                return []
        
        # Get compiled pattern
        regex = self.compiled_patterns[pattern_name]
        findings = []
        
        try:
            # Apply the pattern
            matches = list(regex.finditer(content))
            
            # Process matches
            for match in matches:
                # Extract matching code
                match_text = match.group(0)
                
                # Get line number (approximate)
                line_number = content[:match.start()].count('\n') + 1
                
                # Create finding
                finding = Finding(
                    type="pattern_match",
                    vulnerability_type=pattern_name,
                    description=description,
                    line_number=line_number,
                    matched_text=match_text,
                    file_id=file_id,
                    severity=severity,
                    confidence=0.7,  # Pattern matches have moderate confidence
                    pattern_id=pattern_id,
                    pattern_name=pattern_name
                )
                
                findings.append(finding)
                
        except Exception as e:
            logger.error(f"Error matching pattern '{pattern_name}': {e}")
            
        return findings
    
    def match_patterns(
        self,
        file_id: int,
        content: str,
        patterns: List[Dict[str, Any]]
    ) -> List[Finding]:
        """Match multiple patterns against file content.
        
        Args:
            file_id: ID of the file in the database
            content: Content to match against
            patterns: List of pattern definitions
            
        Returns:
            List of findings
        """
        findings = []
        
        for pattern in patterns:
            pattern_findings = self.match_pattern(file_id, content, pattern)
            findings.extend(pattern_findings)
            
        return findings
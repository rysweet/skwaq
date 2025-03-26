"""Finding data model for the Skwaq vulnerability assessment copilot.

This module defines the data model for vulnerability findings detected by the analysis
strategies, providing a consistent structure for representing and storing findings.
"""

from dataclasses import dataclass, field
from typing import Dict, Any, Optional, List


@dataclass
class Finding:
    """Represents a potential vulnerability finding in source code.
    
    This class provides a standardized structure for representing vulnerability
    findings across different analysis strategies and languages.
    """
    
    type: str  # Type of finding (pattern_match, semantic_analysis, ast_analysis)
    vulnerability_type: str  # Category of vulnerability (SQL Injection, XSS, etc.)
    description: str  # Description of the vulnerability
    file_id: int  # ID of the file in the database
    line_number: int  # Line number where the vulnerability was found
    severity: str = "Medium"  # Severity level (Low, Medium, High)
    confidence: float = 0.5  # Confidence in the finding (0.0-1.0)
    matched_text: Optional[str] = None  # The text that matched the pattern
    pattern_id: Optional[int] = None  # ID of the pattern that matched
    pattern_name: Optional[str] = None  # Name of the pattern that matched
    suggestion: Optional[str] = None  # Suggestion for fixing the vulnerability
    metadata: Dict[str, Any] = field(default_factory=dict)  # Additional metadata

    def to_dict(self) -> Dict[str, Any]:
        """Convert the finding to a dictionary.
        
        Returns:
            Dictionary representation of the finding
        """
        result = {
            "type": self.type,
            "vulnerability_type": self.vulnerability_type,
            "description": self.description,
            "line_number": self.line_number,
            "severity": self.severity,
            "confidence": self.confidence,
        }
        
        # Add optional fields if they exist
        if self.matched_text:
            result["matched_text"] = self.matched_text
        
        if self.pattern_id:
            result["pattern_id"] = self.pattern_id
        
        if self.pattern_name:
            result["pattern_name"] = self.pattern_name
        
        if self.suggestion:
            result["suggestion"] = self.suggestion
        
        if self.metadata:
            result["metadata"] = self.metadata
        
        return result
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Finding":
        """Create a finding from a dictionary.
        
        Args:
            data: Dictionary with finding data
            
        Returns:
            Finding instance
        """
        # Extract required fields
        required_args = {
            "type": data["type"],
            "vulnerability_type": data["vulnerability_type"],
            "description": data["description"],
            "file_id": data["file_id"],
            "line_number": data["line_number"],
        }
        
        # Extract optional fields
        optional_args = {}
        
        if "severity" in data:
            optional_args["severity"] = data["severity"]
            
        if "confidence" in data:
            optional_args["confidence"] = data["confidence"]
            
        if "matched_text" in data:
            optional_args["matched_text"] = data["matched_text"]
            
        if "pattern_id" in data:
            optional_args["pattern_id"] = data["pattern_id"]
            
        if "pattern_name" in data:
            optional_args["pattern_name"] = data["pattern_name"]
            
        if "suggestion" in data:
            optional_args["suggestion"] = data["suggestion"]
            
        # Extract metadata (all other fields)
        metadata = {}
        for key, value in data.items():
            if key not in required_args and key not in optional_args and key != "metadata":
                metadata[key] = value
                
        if "metadata" in data:
            metadata.update(data["metadata"])
            
        if metadata:
            optional_args["metadata"] = metadata
        
        return cls(**required_args, **optional_args)


@dataclass
class AnalysisResult:
    """Results of a code analysis operation.
    
    This class collects findings and metadata from a code analysis operation.
    """
    
    file_id: int  # ID of the file in the database
    findings: List[Finding] = field(default_factory=list)  # List of findings
    metadata: Dict[str, Any] = field(default_factory=dict)  # Analysis metadata
    
    @property
    def vulnerabilities_found(self) -> int:
        """Number of vulnerabilities found.
        
        Returns:
            Count of vulnerabilities
        """
        return len([f for f in self.findings 
                   if f.type in ("semantic_analysis", "ast_analysis")])
    
    @property
    def patterns_matched(self) -> int:
        """Number of patterns matched.
        
        Returns:
            Count of pattern matches
        """
        return len([f for f in self.findings if f.type == "pattern_match"])
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert the analysis result to a dictionary.
        
        Returns:
            Dictionary representation of the analysis result
        """
        return {
            "vulnerabilities_found": self.vulnerabilities_found,
            "patterns_matched": self.patterns_matched,
            "findings": [f.to_dict() for f in self.findings],
            "file_id": self.file_id,
            "metadata": self.metadata
        }
    
    def add_finding(self, finding: Finding) -> None:
        """Add a finding to the results.
        
        Args:
            finding: Finding to add
        """
        self.findings.append(finding)
        
    def add_findings(self, findings: List[Finding]) -> None:
        """Add multiple findings to the results.
        
        Args:
            findings: List of findings to add
        """
        self.findings.extend(findings)
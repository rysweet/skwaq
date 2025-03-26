"""AST-based analysis strategy for vulnerability detection.

This module implements the AST-based analysis strategy for detecting vulnerabilities
in source code using Abstract Syntax Tree parsing and pattern recognition.
"""

from typing import Dict, List, Any, Optional, Type

from ...shared.finding import Finding
from ...utils.logging import get_logger
from ..languages.base import LanguageAnalyzer
from .base import AnalysisStrategy

logger = get_logger(__name__)


class ASTAnalysisStrategy(AnalysisStrategy):
    """AST-based analysis strategy for vulnerability detection.
    
    This class implements a vulnerability detection strategy that uses
    language-specific analyzers to parse code into Abstract Syntax Trees
    and identify potential security vulnerabilities.
    """
    
    def __init__(self):
        """Initialize the AST analysis strategy."""
        super().__init__()
        self.language_analyzers: Dict[str, LanguageAnalyzer] = {}
    
    def register_language_analyzer(self, analyzer: LanguageAnalyzer) -> None:
        """Register a language-specific analyzer.
        
        Args:
            analyzer: Language analyzer instance
        """
        language = analyzer.get_language_name()
        self.language_analyzers[language] = analyzer
        logger.info(f"Registered language analyzer for {language}")
    
    def get_language_analyzer(self, language: str) -> Optional[LanguageAnalyzer]:
        """Get a language analyzer by language name.
        
        Args:
            language: Language name
            
        Returns:
            Language analyzer instance or None if not found
        """
        # Try exact match first
        if language in self.language_analyzers:
            return self.language_analyzers[language]
        
        # Try case-insensitive match
        for lang, analyzer in self.language_analyzers.items():
            if lang.lower() == language.lower():
                return analyzer
        
        # Try partial match for combined languages (e.g., "JavaScript/React")
        for lang, analyzer in self.language_analyzers.items():
            if lang in language or language in lang:
                return analyzer
        
        return None
    
    async def analyze(
        self, 
        file_id: int, 
        content: str, 
        language: str,
        options: Optional[Dict[str, Any]] = None
    ) -> List[Finding]:
        """Analyze a file for potential vulnerabilities using AST analysis.
        
        Args:
            file_id: ID of the file node in the graph
            content: Content of the file
            language: Programming language of the file
            options: Optional dictionary with analysis configuration
            
        Returns:
            List of findings
        """
        logger.debug(f"Performing AST analysis for file ID {file_id}")
        
        # AST analysis is language-specific
        supported_languages = {
            "Python", "JavaScript", "TypeScript", "Java", 
            "C#", "PHP", "Ruby", "Go"
        }
        
        # Check if language is supported
        normalized_language = self._normalize_language(language)
        if normalized_language not in supported_languages:
            logger.debug(f"AST analysis not supported for {language}")
            return []
        
        # Get appropriate language analyzer
        analyzer = self.get_language_analyzer(normalized_language)
        if not analyzer:
            logger.warning(f"No language analyzer available for {language}")
            return []
        
        # Perform AST analysis using the language analyzer
        findings = analyzer.analyze_ast(file_id, content)
        
        # Create finding nodes in the database
        for finding in findings:
            self._create_finding_node(file_id, finding)
        
        logger.debug(f"AST analysis complete: {len(findings)} findings")
        return findings
    
    def _normalize_language(self, language: str) -> str:
        """Normalize language name for consistent lookup.
        
        Args:
            language: Language name to normalize
            
        Returns:
            Normalized language name
        """
        # Handle common language variants
        if language in ("JavaScript", "TypeScript", "JS", "TS"):
            return "JavaScript"
        elif language in ("C#", "CSharp", "C Sharp"):
            return "C#"
        elif "Python" in language:
            return "Python"
        elif "Java" in language and "Script" not in language:
            return "Java"
        elif "PHP" in language:
            return "PHP"
        
        return language
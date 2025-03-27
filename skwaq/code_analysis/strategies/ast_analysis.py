"""AST-based analysis strategy for vulnerability detection.

This module implements the AST-based analysis strategy for detecting vulnerabilities
in source code using Abstract Syntax Tree parsing and pattern recognition.
"""

from typing import Dict, List, Any, Optional, Type

from ...shared.finding import Finding
from ...utils.logging import get_logger
from ..languages.base import LanguageAnalyzer
from .base import AnalysisStrategy

# Import Blarify integration - the module handles its own availability check
from ..blarify_integration import BlarifyIntegration, BLARIFY_AVAILABLE

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
        
        # Initialize Blarify integration - the BlarifyIntegration class handles 
        # checking availability internally, so we can always create the instance
        self.blarify_integration = BlarifyIntegration()
        
        # Log the AST analysis capabilities
        if self.blarify_integration.is_available():
            logger.info("AST analysis initialized with Blarify integration")
        else:
            logger.info("AST analysis initialized with limited capabilities (no Blarify)")
            # Only log this warning in non-test environments
            if not "PYTEST_CURRENT_TEST" in __import__("os").environ:
                logger.debug("Some advanced AST analysis features will be limited")

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
        options: Optional[Dict[str, Any]] = None,
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
        
        if options is None:
            options = {}

        # AST analysis is language-specific
        supported_languages = {
            "Python",
            "JavaScript",
            "TypeScript",
            "Java",
            "C#",
            "PHP",
            "Ruby",
            "Go",
        }

        # Check if language is supported
        normalized_language = self._normalize_language(language)
        if normalized_language not in supported_languages:
            logger.debug(f"AST analysis not supported for {language}")
            return []
            
        # Initialize findings list
        findings = []
        
        # Try to use Blarify for advanced AST analysis if available
        blarify_used = False
        if options.get("use_blarify", True):
            if self.blarify_integration and self.blarify_integration.is_available():
                try:
                    # Analyze with Blarify
                    blarify_findings = self.blarify_integration.analyze_security_patterns(
                        content, normalized_language, file_id
                    )
                    findings.extend(blarify_findings)
                    
                    logger.debug(f"Performed Blarify AST analysis for file ID {file_id}")
                    blarify_used = True
                    
                    # Use code structure information if available from options
                    if "code_structure" in options:
                        code_structure = options["code_structure"]
                        findings.extend(self._analyze_code_structure(file_id, code_structure, content))
                    
                except Exception as e:
                    logger.error(f"Error in Blarify AST analysis: {e}")
                    # Continue to use language analyzer
                    logger.debug(f"Will use standard language analyzer for {normalized_language}")
            else:
                # Only log in debug mode to avoid spamming warnings - more detailed warning happened in __init__
                logger.debug("Blarify not available for AST analysis, using standard analysis")

        # Get appropriate language analyzer for regular analysis
        analyzer = self.get_language_analyzer(normalized_language)
        if analyzer:
            # Perform AST analysis using the language analyzer
            analyzer_findings = analyzer.analyze_ast(file_id, content)
            findings.extend(analyzer_findings)
        else:
            logger.warning(f"No language analyzer available for {language}")

        # Create finding nodes in the database
        for finding in findings:
            self._create_finding_node(file_id, finding)

        logger.debug(f"AST analysis complete: {len(findings)} findings")
        return findings
        
    def _analyze_code_structure(
        self, file_id: int, code_structure: Dict[str, Any], content: str
    ) -> List[Finding]:
        """Analyze code structure information for potential vulnerabilities.
        
        Args:
            file_id: ID of the file in the database
            code_structure: Code structure information from Blarify
            content: Original code content
            
        Returns:
            List of additional findings based on code structure
        """
        findings = []
        
        # Example: Check for overly complex functions
        for func in code_structure.get("functions", []):
            if func.get("complexity", 0) > 10:  # Threshold for cyclomatic complexity
                # Get line number range for the function
                line_start = func.get("line_start", 0)
                line_end = func.get("line_end", 0)
                
                if line_start and line_end:
                    findings.append(
                        Finding(
                            type="ast_analysis",
                            vulnerability_type="Code Complexity",
                            description=f"Function '{func.get('name', 'unknown')}' has high cyclomatic complexity",
                            file_id=file_id,
                            line_number=line_start,
                            matched_text=f"Lines {line_start}-{line_end}",
                            severity="Low",
                            confidence=0.8,
                            suggestion="Consider refactoring to reduce complexity and improve maintainability.",
                        )
                    )
        
        # Example: Check for large classes (potential code smells)
        for cls in code_structure.get("classes", []):
            method_count = len(cls.get("methods", []))
            if method_count > 20:  # Threshold for method count
                line_start = cls.get("line_start", 0)
                findings.append(
                    Finding(
                        type="ast_analysis",
                        vulnerability_type="Design Issue",
                        description=f"Class '{cls.get('name', 'unknown')}' has {method_count} methods",
                        file_id=file_id,
                        line_number=line_start,
                        matched_text=f"Class with {method_count} methods",
                        severity="Info",
                        confidence=0.7,
                        suggestion="Consider breaking down large classes into smaller, more focused components.",
                    )
                )
        
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

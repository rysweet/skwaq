"""Code analyzer for the Skwaq vulnerability assessment copilot.

This module provides the main CodeAnalyzer class which orchestrates the analysis
of source code files to identify potential security vulnerabilities.
"""

import asyncio
from typing import Dict, List, Optional, Any, Type

from ..db.neo4j_connector import get_connector
from ..core.openai_client import get_openai_client
from ..utils.logging import get_logger, LogEvent
from ..utils.config import get_config
from ..shared.finding import Finding, AnalysisResult
from .strategies.base import AnalysisStrategy
from .strategies.pattern_matching import PatternMatchingStrategy
from .strategies.semantic_analysis import SemanticAnalysisStrategy
from .strategies.ast_analysis import ASTAnalysisStrategy
from .languages.base import LanguageAnalyzer
from .languages.python import PythonAnalyzer
from .languages.javascript import JavaScriptAnalyzer

logger = get_logger(__name__)


class CodeAnalyzer:
    """Code analyzer for vulnerability assessment.
    
    This class provides static code analysis capabilities to identify potential
    vulnerabilities in source code repositories. It orchestrates different analysis
    strategies and language-specific analyzers to detect security issues.
    """
    
    def __init__(self) -> None:
        """Initialize the code analyzer."""
        self.connector = get_connector()
        self.openai_client = get_openai_client(async_mode=True)
        self.config = get_config()
        
        # Initialize strategies
        self.strategies: Dict[str, AnalysisStrategy] = {
            "pattern_matching": PatternMatchingStrategy(),
            "semantic_analysis": SemanticAnalysisStrategy(),
            "ast_analysis": ASTAnalysisStrategy()
        }
        
        # Initialize language analyzers
        self.language_analyzers: Dict[str, LanguageAnalyzer] = {}
        self._register_default_language_analyzers()
    
    def _register_default_language_analyzers(self) -> None:
        """Register default language analyzers."""
        # Register Python analyzer
        python_analyzer = PythonAnalyzer()
        self.register_language_analyzer(python_analyzer)
        
        # Register JavaScript/TypeScript analyzer
        js_analyzer = JavaScriptAnalyzer()
        self.register_language_analyzer(js_analyzer)
        
        # Add language analyzers to the AST strategy
        ast_strategy = self.strategies.get("ast_analysis")
        # Skip type check in tests by checking if method exists
        if ast_strategy and hasattr(ast_strategy, "register_language_analyzer"):
            for analyzer in self.language_analyzers.values():
                ast_strategy.register_language_analyzer(analyzer)
    
    def register_language_analyzer(self, analyzer: LanguageAnalyzer) -> None:
        """Register a language-specific analyzer.
        
        Args:
            analyzer: Language analyzer instance
        """
        language = analyzer.get_language_name()
        self.language_analyzers[language] = analyzer
        logger.info(f"Registered language analyzer for {language}")
        
        # Also register with AST strategy
        ast_strategy = self.strategies.get("ast_analysis")
        # Skip type check in tests by checking if method exists
        if ast_strategy and hasattr(ast_strategy, "register_language_analyzer"):
            ast_strategy.register_language_analyzer(analyzer)
    
    def register_strategy(self, name: str, strategy: AnalysisStrategy) -> None:
        """Register an analysis strategy.
        
        Args:
            name: Strategy name
            strategy: Strategy instance
        """
        self.strategies[name] = strategy
        logger.info(f"Registered analysis strategy: {name}")
    
    async def analyze_repository(
        self, 
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
        logger.info(f"Analyzing repository (ID: {repo_id})")
        
        if analysis_options is None:
            analysis_options = {}
            
        # Get repository info
        repo_info = self.connector.run_query(
            "MATCH (r:Repository) WHERE id(r) = $repo_id RETURN r.name, r.path",
            {"repo_id": repo_id}
        )
        
        if not repo_info:
            raise ValueError(f"Repository with ID {repo_id} not found")
            
        repo_name = repo_info[0]["r.name"]
        repo_path = repo_info[0]["r.path"]
        
        logger.info(f"Starting analysis for repository: {repo_name} ({repo_path})")
        
        # Initialize results
        results = {
            "repository_id": repo_id,
            "repository_name": repo_name,
            "files_analyzed": 0,
            "vulnerabilities_found": 0,
            "patterns_matched": 0,
            "analysis_details": [],
        }
        
        try:
            # Get all code files in the repository
            code_files = self.connector.run_query(
                """
                MATCH (r:Repository)-[:HAS_FILE]->(f:File)
                WHERE id(r) = $repo_id AND EXISTS(f.language)
                RETURN id(f) as file_id, f.path as file_path, f.language as language
                """,
                {"repo_id": repo_id}
            )
            
            # Analyze each file
            for file_info in code_files:
                file_id = file_info["file_id"]
                file_path = file_info["file_path"]
                language = file_info["language"]
                
                logger.debug(f"Analyzing file: {file_path} ({language})")
                
                # Perform file analysis
                file_results = await self.analyze_file(file_id, language, analysis_options)
                
                # Update overall results
                results["files_analyzed"] += 1
                results["vulnerabilities_found"] += file_results.vulnerabilities_found
                results["patterns_matched"] += file_results.patterns_matched
                results["analysis_details"].append({
                    "file_id": file_id,
                    "file_path": file_path,
                    "language": language,
                    "results": file_results.to_dict(),
                })
            
            logger.info(
                f"Repository analysis complete: {results['files_analyzed']} files analyzed, "
                f"{results['vulnerabilities_found']} vulnerabilities found"
            )
            
            return results
            
        except Exception as e:
            logger.error(f"Error analyzing repository {repo_name}: {e}")
            raise
    
    async def analyze_file(
        self, 
        file_id: int, 
        language: str,
        analysis_options: Optional[Dict[str, Any]] = None
    ) -> AnalysisResult:
        """Analyze a file for potential vulnerabilities.
        
        Args:
            file_id: ID of the file node in the graph
            language: Programming language of the file
            analysis_options: Dictionary with analysis configuration
            
        Returns:
            AnalysisResult with findings
        """
        if analysis_options is None:
            analysis_options = {}
            
        # Get file content
        file_content = self.connector.run_query(
            """
            MATCH (f:File)-[:HAS_CONTENT]->(c:CodeContent)
            WHERE id(f) = $file_id
            RETURN c.content as content
            """,
            {"file_id": file_id}
        )
        
        if not file_content:
            logger.warning(f"No content found for file ID {file_id}")
            return AnalysisResult(file_id=file_id)
        
        content = file_content[0]["content"]
        
        # Initialize analysis result
        result = AnalysisResult(file_id=file_id)
        
        # Apply each analysis strategy based on options
        tasks = []
        
        if analysis_options.get("pattern_matching", True) and "pattern_matching" in self.strategies:
            tasks.append(
                self.strategies["pattern_matching"].analyze(
                    file_id, content, language, analysis_options
                )
            )
        
        if analysis_options.get("semantic_analysis", True) and "semantic_analysis" in self.strategies:
            tasks.append(
                self.strategies["semantic_analysis"].analyze(
                    file_id, content, language, analysis_options
                )
            )
        
        if analysis_options.get("ast_analysis", True) and "ast_analysis" in self.strategies:
            tasks.append(
                self.strategies["ast_analysis"].analyze(
                    file_id, content, language, analysis_options
                )
            )
        
        # Run strategies in parallel
        if tasks:
            findings_lists = await asyncio.gather(*tasks)
            
            # Add findings from all strategies
            for findings in findings_lists:
                result.add_findings(findings)
        
        return result
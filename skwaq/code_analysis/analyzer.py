"""Code analyzer for the Skwaq vulnerability assessment copilot.

This module provides the main CodeAnalyzer class which orchestrates the analysis
of source code files to identify potential security vulnerabilities.
"""

import asyncio
import os
import tempfile
from typing import Dict, List, Optional, Any, Type

from ..db.neo4j_connector import get_connector
from ..core.openai_client import get_openai_client
from ..utils.logging import get_logger, LogEvent
from ..utils.config import get_config
from ..shared.finding import Finding, AnalysisResult, CodeSummary, ArchitectureModel
from .strategies.base import AnalysisStrategy
from .strategies.pattern_matching import PatternMatchingStrategy
from .strategies.semantic_analysis import SemanticAnalysisStrategy
from .strategies.ast_analysis import ASTAnalysisStrategy
from .languages.base import LanguageAnalyzer
from .languages.python import PythonAnalyzer
from .languages.javascript import JavaScriptAnalyzer
from .languages.csharp import CSharpAnalyzer
from .blarify_integration import BlarifyIntegration, BLARIFY_AVAILABLE
from .parallel_orchestrator import ParallelOrchestrator
from .codeql_integration import CodeQLIntegration
from .metrics_collector import MetricsCollector
from .tool_integration import ToolIntegrationFramework

logger = get_logger(__name__)


class CodeAnalyzer:
    """Code analyzer for vulnerability assessment.

    This class provides static code analysis capabilities to identify potential
    vulnerabilities in source code repositories. It orchestrates different analysis
    strategies and language-specific analyzers to detect security issues.
    """

    _instance = None
    
    def __new__(cls):
        """Create a singleton instance of CodeAnalyzer."""
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance
    
    def __init__(self) -> None:
        """Initialize the code analyzer."""
        # Skip initialization if already done (singleton pattern)
        if getattr(self, '_initialized', False):
            return
            
        self.connector = get_connector()
        self.openai_client = get_openai_client(async_mode=True)
        self.config = get_config()

        # Initialize Blarify integration if available
        self.blarify_integration = BlarifyIntegration() if BLARIFY_AVAILABLE else None

        # Initialize strategies
        self.strategies: Dict[str, AnalysisStrategy] = {
            "pattern_matching": PatternMatchingStrategy(),
            "semantic_analysis": SemanticAnalysisStrategy(),
            "ast_analysis": ASTAnalysisStrategy(),
        }

        # Initialize language analyzers
        self.language_analyzers: Dict[str, LanguageAnalyzer] = {}
        self._register_default_language_analyzers()
        
        # Initialize advanced analysis components
        self.parallel_orchestrator = ParallelOrchestrator()
        self.codeql_integration = CodeQLIntegration()
        self.metrics_collector = MetricsCollector()
        self.tool_integration = ToolIntegrationFramework()
        
        logger.info("CodeAnalyzer initialized with advanced components")
        
        # Mark as initialized
        self._initialized = True

    def _register_default_language_analyzers(self) -> None:
        """Register default language analyzers."""
        # Register Python analyzer
        python_analyzer = PythonAnalyzer()
        self.register_language_analyzer(python_analyzer)

        # Register JavaScript/TypeScript analyzer
        js_analyzer = JavaScriptAnalyzer()
        self.register_language_analyzer(js_analyzer)
        
        # Register C# analyzer
        csharp_analyzer = CSharpAnalyzer()
        self.register_language_analyzer(csharp_analyzer)

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
        self, repo_id: int, analysis_options: Optional[Dict[str, Any]] = None
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
            {"repo_id": repo_id},
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
                {"repo_id": repo_id},
            )

            # Analyze each file
            for file_info in code_files:
                file_id = file_info["file_id"]
                file_path = file_info["file_path"]
                language = file_info["language"]

                logger.debug(f"Analyzing file: {file_path} ({language})")

                # Perform file analysis
                file_results = await self.analyze_file(
                    file_id, language, analysis_options
                )

                # Update overall results
                results["files_analyzed"] += 1
                results["vulnerabilities_found"] += file_results.vulnerabilities_found
                results["patterns_matched"] += file_results.patterns_matched
                results["analysis_details"].append(
                    {
                        "file_id": file_id,
                        "file_path": file_path,
                        "language": language,
                        "results": file_results.to_dict(),
                    }
                )

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
        analysis_options: Optional[Dict[str, Any]] = None,
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
            RETURN c.content as content, f.path as path
            """,
            {"file_id": file_id},
        )

        if not file_content:
            logger.warning(f"No content found for file ID {file_id}")
            return AnalysisResult(file_id=file_id)

        content = file_content[0]["content"]
        file_path = file_content[0].get("path", "")

        # Initialize analysis result
        result = AnalysisResult(file_id=file_id)

        # Perform Blarify-based code structure mapping if available and enabled
        if (
            self.blarify_integration 
            and self.blarify_integration.is_available()
            and analysis_options.get("code_structure_mapping", True)
        ):
            try:
                # Extract code structure
                code_structure = self.blarify_integration.extract_code_structure(content, language)
                
                if code_structure:
                    # Store code structure in the database
                    self._store_code_structure(file_id, code_structure)
                    
                    # Add Blarify-based security findings
                    blarify_findings = self.blarify_integration.analyze_security_patterns(
                        content, language, file_id
                    )
                    result.add_findings(blarify_findings)
                    
                    logger.info(f"Performed Blarify code structure mapping for file ID {file_id}")
                    
                    # Add Blarify code structure to the analysis options for strategies to use
                    analysis_options["code_structure"] = code_structure
            except Exception as e:
                logger.error(f"Error performing Blarify code structure mapping: {e}")

        # Apply each analysis strategy based on options
        tasks = []

        if (
            analysis_options.get("pattern_matching", True)
            and "pattern_matching" in self.strategies
        ):
            tasks.append(
                self.strategies["pattern_matching"].analyze(
                    file_id, content, language, analysis_options
                )
            )

        if (
            analysis_options.get("semantic_analysis", True)
            and "semantic_analysis" in self.strategies
        ):
            tasks.append(
                self.strategies["semantic_analysis"].analyze(
                    file_id, content, language, analysis_options
                )
            )

        if (
            analysis_options.get("ast_analysis", True)
            and "ast_analysis" in self.strategies
        ):
            tasks.append(
                self.strategies["ast_analysis"].analyze(
                    file_id, content, language, analysis_options
                )
            )

        # Run strategies in parallel using parallel orchestrator
        if tasks:
            findings_lists = await self.parallel_orchestrator.execute_parallel_tasks(tasks)

            # Add findings from all strategies
            for findings in findings_lists:
                result.add_findings(findings)
        
        # Run advanced analysis if enabled
        if analysis_options.get("advanced_analysis", False):
            # Collect code metrics if enabled
            if analysis_options.get("metrics_collection", True):
                try:
                    # Create temporary file for metrics collection
                    with tempfile.NamedTemporaryFile(mode='w', suffix=f'.{language.lower()}', delete=False) as tmp:
                        tmp.write(content)
                        metrics_file_path = tmp.name
                    
                    # Collect metrics
                    metrics = self.metrics_collector.collect_metrics(metrics_file_path)
                    
                    # Store metrics in the database
                    self.metrics_collector.store_metrics(file_id, metrics)
                    
                    # Add metrics info to result
                    result.metrics = metrics
                    
                    # Clean up temp file
                    os.unlink(metrics_file_path)
                    
                    logger.info(f"Collected {len(metrics)} metrics for file ID {file_id}")
                except Exception as e:
                    logger.error(f"Error collecting metrics for file ID {file_id}: {e}")
            
            # Run external tools if enabled
            if analysis_options.get("external_tools", True):
                try:
                    # Create a temporary file for tool analysis
                    with tempfile.NamedTemporaryFile(mode='w', suffix=f'.{language.lower()}', delete=False) as tmp:
                        tmp.write(content)
                        tool_file_path = tmp.name
                    
                    # Run all applicable tools
                    tool_results = self.tool_integration.execute_all_tools(
                        language, [tool_file_path]
                    )
                    
                    # Convert tool results to findings
                    if tool_results:
                        file_id_map = {tool_file_path: file_id}
                        tool_findings = self.tool_integration.convert_to_findings(
                            tool_results, file_id_map
                        )
                        result.add_findings(tool_findings)
                        
                        logger.info(f"Added {len(tool_findings)} findings from external tools for file ID {file_id}")
                    
                    # Clean up temp file
                    os.unlink(tool_file_path)
                except Exception as e:
                    logger.error(f"Error running external tools for file ID {file_id}: {e}")
            
            # Run CodeQL analysis if enabled
            if analysis_options.get("codeql_analysis", True) and self.codeql_integration.is_available:
                try:
                    repo_path = analysis_options.get("repo_path")
                    if repo_path:
                        # Create CodeQL database (this is usually done once per repository)
                        database_path = analysis_options.get("codeql_database")
                        
                        if not database_path:
                            # Create temporary database
                            database_path = tempfile.mkdtemp(prefix="skwaq_codeql_")
                            self.codeql_integration.create_codeql_database(repo_path, language, database_path)
                        
                        # Run default queries
                        codeql_results = self.codeql_integration.run_default_queries(database_path, language)
                        
                        # Convert results to findings
                        if codeql_results:
                            file_id_map = {file_path: file_id}
                            codeql_findings = self.codeql_integration.convert_to_findings(
                                codeql_results, file_id_map
                            )
                            result.add_findings(codeql_findings)
                            
                            logger.info(f"Added {len(codeql_findings)} findings from CodeQL for file ID {file_id}")
                except Exception as e:
                    logger.error(f"Error running CodeQL analysis for file ID {file_id}: {e}")

        return result
        
    def _store_code_structure(self, file_id: int, code_structure: Dict[str, Any]) -> None:
        """Store code structure information in the graph database.
        
        Args:
            file_id: ID of the file in the database
            code_structure: Code structure information extracted by Blarify
        """
        try:
            # Create a CodeStructure node
            structure_props = {
                "timestamp": self._get_timestamp(),
                "structure_version": "1.0",
            }
            
            structure_id = self.connector.create_node(
                labels=["CodeStructure"],
                properties=structure_props
            )
            
            # Link CodeStructure to the File node
            self.connector.create_relationship(
                start_id=file_id,
                end_id=structure_id,
                rel_type="HAS_STRUCTURE",
                properties={}
            )
            
            # Add Function nodes
            for func in code_structure.get("functions", []):
                func_id = self.connector.create_node(
                    labels=["Function"],
                    properties={
                        "name": func.get("name", ""),
                        "line_start": func.get("line_start", 0),
                        "line_end": func.get("line_end", 0),
                        "complexity": func.get("complexity", 0),
                    }
                )
                
                # Link Function to CodeStructure
                self.connector.create_relationship(
                    start_id=structure_id,
                    end_id=func_id,
                    rel_type="HAS_FUNCTION",
                    properties={}
                )
            
            # Add Class nodes
            for cls in code_structure.get("classes", []):
                cls_id = self.connector.create_node(
                    labels=["Class"],
                    properties={
                        "name": cls.get("name", ""),
                        "line_start": cls.get("line_start", 0),
                        "line_end": cls.get("line_end", 0),
                    }
                )
                
                # Link Class to CodeStructure
                self.connector.create_relationship(
                    start_id=structure_id,
                    end_id=cls_id,
                    rel_type="HAS_CLASS",
                    properties={}
                )
                
            logger.info(f"Stored code structure for file ID {file_id}")
            
        except Exception as e:
            logger.error(f"Error storing code structure in database: {e}")
    
    def _get_timestamp(self) -> str:
        """Get the current timestamp in ISO format.
        
        Returns:
            Current timestamp as string
        """
        from datetime import datetime, UTC
        return datetime.now(UTC).isoformat()
        
    async def summarize_code(self, code: str, level: str = "function") -> CodeSummary:
        """Summarize code at the specified level.
        
        Args:
            code: Code to summarize
            level: Level of summarization (function, class, module, system)
            
        Returns:
            CodeSummary object
        """
        # This is a placeholder method for the C4 milestone
        # It will be implemented in the next development phase
        return CodeSummary(
            name="placeholder",
            summary="Code summary placeholder",
            complexity=0,
            component_type=level,
            responsible_for=[],
            input_types=[],
            output_types=[],
            security_considerations=[]
        )
    
    async def infer_intent(self, code: str, level: str = "function") -> Dict[str, Any]:
        """Infer developer intent from code.
        
        Args:
            code: Code to analyze
            level: Level of intent inference (function, class, module)
            
        Returns:
            Dictionary with intent information
        """
        # This is a placeholder method for the C4 milestone
        # It will be implemented in the next development phase
        return {
            "intent": "Placeholder intent",
            "purpose": "Placeholder purpose",
            "confidence": 0.5
        }
    
    async def reconstruct_architecture(self, repo_path: str) -> ArchitectureModel:
        """Reconstruct the architecture of a repository.
        
        Args:
            repo_path: Path to the repository
            
        Returns:
            ArchitectureModel representing the system architecture
        """
        # This is a placeholder method for the C4 milestone
        # It will be implemented in the next development phase
        return ArchitectureModel(
            name="Placeholder Architecture",
            components=[
                {"name": "component1", "type": "module"}
            ],
            relationships=[
                {"source": "component1", "target": "component2", "type": "uses"}
            ]
        )
    
    async def find_cross_references(self, symbol: Dict[str, Any]) -> Dict[str, Any]:
        """Find cross-references for a symbol.
        
        Args:
            symbol: Dictionary with symbol information
            
        Returns:
            Dictionary with cross-reference information
        """
        # This is a placeholder method for the C4 milestone
        # It will be implemented in the next development phase
        return {
            "symbol": symbol.get("name", ""),
            "references": []
        }

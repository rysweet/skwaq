"""Code analyzer for the Skwaq vulnerability assessment copilot.

This module provides the main CodeAnalyzer class which orchestrates the analysis
of source code files to identify potential security vulnerabilities.
"""

import asyncio
import os
import tempfile
from pathlib import Path
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

        # Initialize Blarify integration - the class handles availability internally
        self.blarify_integration = BlarifyIntegration()

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
        
        # Initialize C4 code understanding components
        from .summarization.code_summarizer import CodeSummarizer
        from .summarization.intent_inference import IntentInferenceEngine
        from .summarization.architecture_reconstruction import ArchitectureReconstructor
        from .summarization.cross_referencer import CrossReferencer
        
        self._summarizer = CodeSummarizer()
        self._intent_engine = IntentInferenceEngine()
        self._architecture_reconstructor = ArchitectureReconstructor()
        self._cross_referencer = CrossReferencer()
        
        logger.info("CodeAnalyzer initialized with advanced components and code understanding capabilities")
        
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

        # Perform code structure mapping if enabled
        if analysis_options.get("code_structure_mapping", True):
            # Check if Blarify is available
            if self.blarify_integration.is_available():
                try:
                    # Extract code structure using Blarify
                    code_structure = self.blarify_integration.extract_code_structure(content, language)
                    
                    if code_structure:
                        # Store code structure in the database
                        self._store_code_structure(file_id, code_structure)
                        
                        # Add Blarify-based security findings
                        blarify_findings = self.blarify_integration.analyze_security_patterns(
                            content, language, file_id
                        )
                        result.add_findings(blarify_findings)
                        
                        logger.debug(f"Performed Blarify code structure mapping for file ID {file_id}")
                        
                        # Add Blarify code structure to the analysis options for strategies to use
                        analysis_options["code_structure"] = code_structure
                except Exception as e:
                    logger.error(f"Error performing Blarify code structure mapping: {e}")
                    # Fallback to simpler structure mapping if necessary
                    logger.debug("Falling back to basic code structure mapping")
                    # Note: we could implement a simple fallback structure mapping here
            else:
                # Blarify not available, log at debug level to avoid spamming warnings
                logger.debug("Blarify not available for code structure mapping. Using simplified analysis.")

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
        
    def _store_code_structure(self, file_id: int, code_structure: Dict[str, Any]) -> int:
        """Store code structure information in the graph database.
        
        Args:
            file_id: ID of the file in the database
            code_structure: Code structure information extracted by Blarify
            
        Returns:
            ID of the created structure node
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
            return structure_id
            
        except Exception as e:
            logger.error(f"Error storing code structure in database: {e}")
            # Always return an integer (0 indicates failure)
            return 0
    
    def _get_timestamp(self) -> str:
        """Get the current timestamp in ISO format.
        
        Returns:
            Current timestamp as string
        """
        from datetime import datetime, UTC
        return datetime.now(UTC).isoformat()
        
    def _detect_language(self, code: str) -> str:
        """Detect the programming language of a code snippet.
        
        Args:
            code: Code snippet to analyze
            
        Returns:
            Detected language name (python, javascript, etc.)
        """
        # Simple heuristic detection based on common language patterns
        code = code.lower()
        
        # Check for Python
        if "def " in code and ":" in code or "import " in code and "as " in code:
            return "python"
            
        # Check for JavaScript/TypeScript
        if "function" in code or "const " in code or "let " in code or "class" in code and "{" in code:
            if "interface " in code or "type " in code and ":" in code:
                return "typescript"
            return "javascript"
            
        # Check for Java
        if "public class" in code or "private " in code and ";" in code:
            return "java"
            
        # Check for C#
        if "namespace " in code or "using " in code and ";" in code:
            return "csharp"
            
        # Check for C/C++
        if "#include" in code or "int main" in code:
            if "class " in code and "::" in code:
                return "cpp"
            return "c"
            
        # Default to Python if unable to detect
        return "python"
        
    def _add_demo_findings(self, result: AnalysisResult, content: str, language: str, file_path: str) -> None:
        """Add demo findings for CLI mode when no database is available.
        
        Args:
            result: AnalysisResult to add findings to
            content: File content to analyze
            language: Programming language of the file
            file_path: Path to the file
        """
        import re
        from ..shared.finding import Finding
        
        # Add some generic findings based on language
        if language.lower() in ["python", "python3"]:
            # Look for potential issues in Python code
            
            # Check for use of eval (security risk)
            if "eval(" in content:
                line_number = 1
                for i, line in enumerate(content.splitlines(), 1):
                    if "eval(" in line:
                        line_number = i
                        break
                
                result.add_findings([
                    Finding(
                        type="pattern_match",
                        vulnerability_type="Code Injection",
                        description="Use of eval() detected, which can lead to code injection vulnerabilities",
                        file_id=result.file_id,
                        line_number=line_number,
                        matched_text="eval(...)",
                        severity="High",
                        confidence=0.85,
                        remediation="Avoid using eval(). Instead, use safer alternatives like ast.literal_eval() for parsing data or redesign to avoid dynamic code execution."
                    )
                ])
            
            # Check for potential SQL injection in ORM queries
            if "execute(" in content and ("SELECT" in content or "INSERT" in content or "UPDATE" in content):
                line_number = 1
                for i, line in enumerate(content.splitlines(), 1):
                    if "execute(" in line and any(kw in line for kw in ["SELECT", "INSERT", "UPDATE"]):
                        line_number = i
                        break
                
                result.add_findings([
                    Finding(
                        type="semantic_analysis",
                        vulnerability_type="SQL Injection",
                        description="Potential SQL injection vulnerability in database query",
                        file_id=result.file_id,
                        line_number=line_number,
                        matched_text="execute(query_with_params)",
                        severity="High",
                        confidence=0.7,
                        remediation="Use parameterized queries with placeholders instead of string concatenation for SQL queries."
                    )
                ])
            
            # Check for sensitive information in variables
            sensitive_patterns = ["password", "secret", "token", "key", "api_key", "apikey"]
            for pattern in sensitive_patterns:
                regex = r"\b" + pattern + r"\s*=\s*['\"]([^'\"]+)['\"]"
                matches = re.finditer(regex, content, re.IGNORECASE)
                
                for match in matches:
                    line_number = content[:match.start()].count('\n') + 1
                    
                    result.add_findings([
                        Finding(
                            type="pattern_match",
                            vulnerability_type="Sensitive Information",
                            description=f"Hardcoded {pattern} detected",
                            file_id=result.file_id,
                            line_number=line_number,
                            matched_text=match.group(0),
                            severity="Medium",
                            confidence=0.75,
                            remediation="Store sensitive information in environment variables or secure secret management systems."
                        )
                    ])
            
            # Check for usage of pickle (serialization vulnerability)
            if "import pickle" in content or "from pickle" in content:
                line_number = 1
                for i, line in enumerate(content.splitlines(), 1):
                    if "import pickle" in line or "from pickle" in line:
                        line_number = i
                        break
                
                result.add_findings([
                    Finding(
                        type="pattern_match",
                        vulnerability_type="Insecure Deserialization",
                        description="Use of pickle module detected, which can lead to remote code execution if used with untrusted data",
                        file_id=result.file_id,
                        line_number=line_number,
                        matched_text="import pickle",
                        severity="Medium",
                        confidence=0.8,
                        remediation="Use safer serialization formats like JSON for untrusted data. If pickle is required, ensure the data comes from a trusted source."
                    )
                ])
                
            # Check for usage of assert (can be bypassed with -O flag)
            if "assert " in content:
                line_number = 1
                for i, line in enumerate(content.splitlines(), 1):
                    if "assert " in line:
                        line_number = i
                        break
                
                result.add_findings([
                    Finding(
                        type="ast_analysis",
                        vulnerability_type="Logic Error",
                        description="Use of assert for validation detected. Assertions can be disabled with -O flag",
                        file_id=result.file_id,
                        line_number=line_number,
                        matched_text="assert condition",
                        severity="Low",
                        confidence=0.7,
                        remediation="Don't use assert for security validation. Use explicit if conditions and raise exceptions instead."
                    )
                ])
                
        elif language.lower() in ["javascript", "typescript", "js", "ts"]:
            # JavaScript/TypeScript specific checks
            
            # Check for potential XSS vulnerabilities
            if "innerHTML" in content or "document.write" in content:
                line_number = 1
                for i, line in enumerate(content.splitlines(), 1):
                    if "innerHTML" in line or "document.write" in line:
                        line_number = i
                        break
                
                result.add_findings([
                    Finding(
                        type="pattern_match",
                        vulnerability_type="Cross-Site Scripting (XSS)",
                        description="Potentially unsafe DOM manipulation detected. This could lead to XSS vulnerabilities.",
                        file_id=result.file_id,
                        line_number=line_number,
                        matched_text="innerHTML = ...",
                        severity="High",
                        confidence=0.75,
                        remediation="Use safer alternatives like textContent for text or create elements properly with document.createElement and set properties individually."
                    )
                ])
                
            # Check for eval usage
            if "eval(" in content:
                line_number = 1
                for i, line in enumerate(content.splitlines(), 1):
                    if "eval(" in line:
                        line_number = i
                        break
                
                result.add_findings([
                    Finding(
                        type="pattern_match",
                        vulnerability_type="Code Injection",
                        description="Use of eval() detected, which can lead to code injection vulnerabilities",
                        file_id=result.file_id,
                        line_number=line_number,
                        matched_text="eval(...)",
                        severity="High",
                        confidence=0.9,
                        remediation="Avoid using eval(). Refactor to use safer alternatives or redesign the functionality."
                    )
                ])
                
        # If no findings were added yet, add at least one general finding
        if not result.findings:
            result.add_findings([
                Finding(
                    type="pattern_match",
                    vulnerability_type="General Security",
                    description="This is a sample finding to demonstrate the CLI output. In a real analysis, this would be a genuine security finding.",
                    file_id=result.file_id,
                    line_number=1,
                    matched_text="// Sample code",
                    severity="Info",
                    confidence=0.5,
                    remediation="This is a sample remediation suggestion. In a real analysis, this would contain specific remediation advice."
                )
            ])
        
    async def summarize_code(self, code: str, level: str = "function") -> CodeSummary:
        """Summarize code at the specified level.
        
        Args:
            code: Code to summarize
            level: Level of summarization (function, class, module, system)
            
        Returns:
            CodeSummary object
        """
        logger.info(f"Summarizing code at {level} level")
        
        if not self._summarizer:
            logger.warning("CodeSummarizer not initialized, using placeholder summary")
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
            
        context = {
            "language": self._detect_language(code),
            "model": self.config.get("summarization.model", "gpt-4"),
            "level": level
        }
            
        try:
            if level == "function":
                return self._summarizer.summarize_function(code, context)
            elif level == "class":
                return self._summarizer.summarize_class(code, context)
            elif level == "module":
                return self._summarizer.summarize_module(code, context)
            elif level == "system":
                # For system summarization, code should be a dictionary of file paths to code content
                if isinstance(code, str):
                    logger.warning("System summarization requires a dictionary of files, using placeholders")
                    system_code = {"placeholder.py": code}
                else:
                    system_code = code
                return self._summarizer.summarize_system(system_code, context)
            else:
                logger.warning(f"Unknown summarization level: {level}, using function level")
                return self._summarizer.summarize_function(code, context)
        except Exception as e:
            logger.error(f"Error during code summarization: {e}")
            return CodeSummary(
                name="error",
                summary=f"Error during summarization: {str(e)}",
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
        logger.info(f"Inferring intent for code at {level} level")
        
        if not self._intent_engine:
            logger.warning("IntentInferenceEngine not initialized, using placeholder intent")
            return {
                "intent": "Placeholder intent",
                "purpose": "Placeholder purpose",
                "confidence": 0.5
            }
            
        context = {
            "language": self._detect_language(code),
            "model": self.config.get("intent_inference.model", "gpt-4"),
            "level": level
        }
            
        try:
            if level == "function":
                return self._intent_engine.infer_function_intent(code, context)
            elif level == "class":
                return self._intent_engine.infer_class_intent(code, context)
            elif level == "module":
                return self._intent_engine.infer_module_intent(code, context)
            else:
                logger.warning(f"Unknown intent inference level: {level}, using function level")
                return self._intent_engine.infer_function_intent(code, context)
        except Exception as e:
            logger.error(f"Error during intent inference: {e}")
            return {
                "intent": f"Error: {str(e)}",
                "purpose": "Could not determine due to error",
                "confidence": 0.0
            }
    
    async def analyze_file_from_path(
        self, 
        file_path: str,
        repository_id: Optional[int] = None,
        strategy_names: Optional[List[str]] = None
    ) -> AnalysisResult:
        """Analyze a file directly from the file system path.
        
        This is a convenience wrapper for CLI and external tools that need to analyze
        files without ingesting them into the database first.
        
        Args:
            file_path: Path to the file to analyze
            repository_id: Optional repository ID for context
            strategy_names: Optional list of strategy names to use
            
        Returns:
            AnalysisResult with findings
        """
        logger.info(f"Analyzing file from path: {file_path}")
        
        # Check if file exists
        file_path_obj = Path(file_path)
        if not file_path_obj.exists() or not file_path_obj.is_file():
            raise FileNotFoundError(f"File not found: {file_path}")
            
        # Read file content
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read()
        except Exception as e:
            logger.error(f"Error reading file {file_path}: {e}")
            raise
            
        # Determine language from file extension
        extension = file_path_obj.suffix.lower()
        language_map = {
            ".py": "Python",
            ".js": "JavaScript",
            ".ts": "TypeScript", 
            ".jsx": "JavaScript",
            ".tsx": "TypeScript",
            ".java": "Java",
            ".cs": "C#",
            ".php": "PHP",
            ".rb": "Ruby",
            ".go": "Go",
        }
        language = language_map.get(extension, "Unknown")
        
        if language == "Unknown":
            # Try to detect language from content
            language = self._detect_language(content)
            
        # Create analysis options
        analysis_options = {}
        
        # Configure requested strategies
        if strategy_names:
            for strategy in ["pattern_matching", "semantic_analysis", "ast_analysis"]:
                analysis_options[strategy] = strategy in strategy_names
                
        # Create a temporary file ID since we're not using the database
        file_id = -1
        
        # Create an AnalysisResult with file path for reference
        result = AnalysisResult(file_id=file_id)
        result.file_path = file_path
        
        # Add language and file information to the analysis options
        analysis_options["language"] = language
        analysis_options["file_path"] = file_path
        analysis_options["cli_mode"] = True  # Indicate this is being run from CLI
        
        # Create mock findings for CLI demo when Neo4j isn't available
        # This ensures the CLI can show output even without a database connection
        is_connected = False
        try:
            if self.connector.is_connected():
                is_connected = True
        except Exception:
            logger.debug("Neo4j connection not available, using CLI standalone mode")
            
        if not is_connected:
            # Add demo findings if we're in CLI standalone mode
            logger.info("Using standalone analysis mode (no database connection)")
            
            # Add some example findings based on the file type
            self._add_demo_findings(result, content, language, file_path)
            return result
        
        # If connected to database, proceed with normal analysis
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
                
        return result
        
    async def reconstruct_architecture(self, repo_path: str) -> ArchitectureModel:
        """Reconstruct the architecture of a repository.
        
        Args:
            repo_path: Path to the repository
            
        Returns:
            ArchitectureModel representing the system architecture
        """
        logger.info(f"Reconstructing architecture for repository: {repo_path}")
        
        if not self._architecture_reconstructor:
            logger.warning("ArchitectureReconstructor not initialized, using placeholder architecture")
            return ArchitectureModel(
                name="Placeholder Architecture",
                components=[
                    {"name": "component1", "type": "module"}
                ],
                relationships=[
                    {"source": "component1", "target": "component2", "type": "uses"}
                ]
            )
        
        try:
            # Use the architecture reconstructor to analyze the repository
            architecture_model = self._architecture_reconstructor.reconstruct_architecture(repo_path)
            
            # Optionally, we could generate a visual representation of the architecture
            # diagram = self._architecture_reconstructor.generate_diagram(architecture_model)
            
            logger.info(f"Architecture reconstruction complete with {len(architecture_model.components)} components" + 
                       f" and {len(architecture_model.relationships)} relationships")
            
            return architecture_model
        except Exception as e:
            logger.error(f"Error during architecture reconstruction: {e}")
            return ArchitectureModel(
                name=f"Error: {str(e)}",
                components=[
                    {"name": "error", "type": "error", "details": str(e)}
                ],
                relationships=[]
            )
    
    async def find_cross_references(self, symbol: Dict[str, Any]) -> Dict[str, Any]:
        """Find cross-references for a symbol.
        
        Args:
            symbol: Dictionary with symbol information
            
        Returns:
            Dictionary with cross-reference information
        """
        logger.info(f"Finding cross-references for symbol: {symbol.get('name', 'unknown')}")
        
        if not self._cross_referencer:
            logger.warning("CrossReferencer not initialized, using placeholder references")
            return {
                "symbol": symbol.get("name", ""),
                "references": []
            }
        
        try:
            # Use the cross referencer to find references to the symbol
            reference_info = self._cross_referencer.find_references(symbol)
            
            # Optionally generate a reference graph
            # reference_graph = self._cross_referencer.generate_reference_graph(repo_path)
            
            reference_count = len(reference_info.get("references", []))
            logger.info(f"Found {reference_count} references to symbol {symbol.get('name', 'unknown')}")
            
            return reference_info
        except Exception as e:
            logger.error(f"Error during cross-reference search: {e}")
            return {
                "symbol": symbol.get("name", ""),
                "error": str(e),
                "references": []
            }

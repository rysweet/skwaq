"""Code metrics collection for advanced analysis.

This module provides functionality for collecting code quality and
complexity metrics to aid in vulnerability assessment.
"""

import os
import ast
import re
import math
import tempfile
import subprocess
from pathlib import Path
from typing import Dict, List, Any, Optional, Union, Set, Tuple, cast

from ..utils.logging import get_logger, LogEvent
from ..utils.config import get_config

logger = get_logger(__name__)


class MetricsCollector:
    """Collects code quality and complexity metrics.
    
    This class provides functionality for analyzing code to collect
    various metrics that can be used to assess code quality and
    identify potential areas of concern.
    """
    
    def __init__(self, radon_available: bool = True, lizard_available: bool = True):
        """Initialize the metrics collector.
        
        Args:
            radon_available: Whether radon package is available
            lizard_available: Whether lizard package is available
        """
        self.config = get_config()
        
        # Check for optional dependencies
        self.radon_available = radon_available
        self.lizard_available = lizard_available
        
        # Try to import optional dependencies
        if self.radon_available:
            try:
                import radon.complexity
                import radon.metrics
                self.radon = True
                logger.info("Radon metrics available")
            except ImportError:
                self.radon = False
                logger.info("Radon package not available for metrics collection")
        else:
            self.radon = False
        
        if self.lizard_available:
            try:
                import lizard
                self.lizard = True
                logger.info("Lizard metrics available")
            except ImportError:
                self.lizard = False
                logger.info("Lizard package not available for metrics collection")
        else:
            self.lizard = False
    
    @LogEvent("collect_metrics")
    def collect_metrics(self, file_path: str) -> Dict[str, Any]:
        """Collect metrics for a file.
        
        Args:
            file_path: Path to the file to analyze
            
        Returns:
            Dictionary of metrics
        """
        logger.info(f"Collecting metrics for {file_path}")
        
        metrics: Dict[str, Any] = {}
        
        # Basic file metrics
        metrics.update(self._collect_basic_metrics(file_path))
        
        # Determine language from file extension
        _, extension = os.path.splitext(file_path)
        language = self._get_language_from_extension(extension)
        metrics["language"] = language
        
        # Language-specific metrics collection
        if language == "python":
            python_metrics = self._collect_python_metrics(file_path)
            metrics.update(python_metrics)
        elif language in ["javascript", "typescript"]:
            js_metrics = self._collect_javascript_metrics(file_path)
            metrics.update(js_metrics)
        elif language in ["java", "csharp", "cpp"]:
            compiled_metrics = self._collect_compiled_metrics(file_path, language)
            metrics.update(compiled_metrics)
        
        # Radon metrics if available
        if self.radon and language == "python":
            radon_metrics = self._collect_radon_metrics(file_path)
            metrics.update(radon_metrics)
        
        # Lizard metrics if available
        if self.lizard:
            lizard_metrics = self._collect_lizard_metrics(file_path)
            metrics.update(lizard_metrics)
        
        logger.info(f"Collected {len(metrics)} metrics for {file_path}")
        return metrics
    
    def _collect_basic_metrics(self, file_path: str) -> Dict[str, Any]:
        """Collect basic file metrics.
        
        Args:
            file_path: Path to the file to analyze
            
        Returns:
            Dictionary of basic metrics
        """
        metrics = {}
        
        try:
            # Get file size
            file_size = os.path.getsize(file_path)
            metrics["file_size_bytes"] = file_size
            
            # Read file content
            with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
                content = f.read()
                
            # Count lines
            lines = content.splitlines()
            metrics["total_lines"] = len(lines)
            
            # Count non-empty lines
            non_empty_lines = [line for line in lines if line.strip()]
            metrics["non_empty_lines"] = len(non_empty_lines)
            
            # Estimate comment lines
            comment_pattern = re.compile(r'^\s*(?://|#|\/\*|\*\/|\*\s|<!--)')
            comment_lines = [line for line in lines if comment_pattern.search(line)]
            metrics["comment_lines"] = len(comment_lines)
            
            if metrics["non_empty_lines"] > 0:
                metrics["comment_ratio"] = metrics["comment_lines"] / metrics["non_empty_lines"]
            else:
                metrics["comment_ratio"] = 0
                
            # Count maximum line length
            if lines:
                max_line_length = max(len(line) for line in lines)
                metrics["max_line_length"] = max_line_length
                
                # Calculate average line length
                total_length = sum(len(line) for line in lines)
                metrics["avg_line_length"] = total_length / len(lines)
        except Exception as e:
            logger.error(f"Error collecting basic metrics for {file_path}: {e}")
            
        return metrics
    
    def _get_language_from_extension(self, extension: str) -> str:
        """Determine language from file extension.
        
        Args:
            extension: File extension including dot (e.g., ".py")
            
        Returns:
            Language name
        """
        extension_map = {
            ".py": "python",
            ".js": "javascript",
            ".jsx": "javascript",
            ".ts": "typescript",
            ".tsx": "typescript",
            ".java": "java",
            ".cs": "csharp",
            ".cpp": "cpp",
            ".cc": "cpp",
            ".c": "c",
            ".h": "cpp",
            ".hpp": "cpp",
            ".go": "go",
            ".rb": "ruby",
            ".php": "php",
            ".swift": "swift",
            ".kt": "kotlin",
            ".rs": "rust",
        }
        
        extension = extension.lower()
        return extension_map.get(extension, "unknown")
    
    def _collect_python_metrics(self, file_path: str) -> Dict[str, Any]:
        """Collect metrics specific to Python files.
        
        Args:
            file_path: Path to the Python file
            
        Returns:
            Dictionary of Python-specific metrics
        """
        metrics = {}
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
                content = f.read()
                
            # Parse AST to analyze code structure
            try:
                tree = ast.parse(content)
                
                # Count functions and classes
                function_count = 0
                class_count = 0
                import_count = 0
                
                for node in ast.walk(tree):
                    if isinstance(node, ast.FunctionDef):
                        function_count += 1
                    elif isinstance(node, ast.ClassDef):
                        class_count += 1
                    elif isinstance(node, (ast.Import, ast.ImportFrom)):
                        import_count += 1
                
                metrics["function_count"] = function_count
                metrics["class_count"] = class_count
                metrics["import_count"] = import_count
                
                # Calculate approximate complexity
                complexity = self._calculate_python_complexity(tree)
                metrics["estimated_complexity"] = complexity
            except SyntaxError:
                logger.warning(f"Could not parse {file_path} as valid Python for AST analysis")
        except Exception as e:
            logger.error(f"Error collecting Python metrics for {file_path}: {e}")
            
        return metrics
    
    def _calculate_python_complexity(self, tree: ast.AST) -> int:
        """Calculate approximate cyclomatic complexity for Python AST.
        
        Args:
            tree: Python AST to analyze
            
        Returns:
            Estimated cyclomatic complexity
        """
        complexity = 1  # Base complexity
        
        for node in ast.walk(tree):
            # Increase complexity for control flow statements
            if isinstance(node, (ast.If, ast.For, ast.While, ast.Try, ast.ExceptHandler)):
                complexity += 1
            
            # Boolean operations add complexity
            elif isinstance(node, ast.BoolOp):
                # Add complexity for each additional condition
                complexity += len(node.values) - 1
                
        return complexity
    
    def _collect_javascript_metrics(self, file_path: str) -> Dict[str, Any]:
        """Collect metrics specific to JavaScript/TypeScript files.
        
        Args:
            file_path: Path to the JavaScript/TypeScript file
            
        Returns:
            Dictionary of JavaScript-specific metrics
        """
        metrics = {}
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
                content = f.read()
                
            # Count functions using regex (simplified)
            function_pattern = re.compile(r'\bfunction\s+\w+\s*\(|\bconst\s+\w+\s*=\s*function|\bconst\s+\w+\s*=\s*\(.*\)\s*=>')
            function_matches = function_pattern.findall(content)
            metrics["function_count"] = len(function_matches)
            
            # Count classes
            class_pattern = re.compile(r'\bclass\s+\w+')
            class_matches = class_pattern.findall(content)
            metrics["class_count"] = len(class_matches)
            
            # Count imports
            import_pattern = re.compile(r'\bimport\s+.*\bfrom\s+|require\(')
            import_matches = import_pattern.findall(content)
            metrics["import_count"] = len(import_matches)
            
            # Estimate complexity (simplified)
            complexity = self._estimate_js_complexity(content)
            metrics["estimated_complexity"] = complexity
        except Exception as e:
            logger.error(f"Error collecting JavaScript metrics for {file_path}: {e}")
            
        return metrics
    
    def _estimate_js_complexity(self, content: str) -> int:
        """Estimate complexity for JavaScript/TypeScript code.
        
        Args:
            content: Source code content
            
        Returns:
            Estimated complexity
        """
        complexity = 1  # Base complexity
        
        # Count control flow statements
        if_count = len(re.findall(r'\bif\s*\(', content))
        for_count = len(re.findall(r'\bfor\s*\(', content))
        while_count = len(re.findall(r'\bwhile\s*\(', content))
        case_count = len(re.findall(r'\bcase\s+', content))
        catch_count = len(re.findall(r'\bcatch\s*\(', content))
        
        complexity += if_count + for_count + while_count + case_count + catch_count
        
        # Count logical operators as additional complexity
        and_count = len(re.findall(r'&&', content))
        or_count = len(re.findall(r'\|\|', content))
        
        complexity += and_count + or_count
        
        return complexity
    
    def _collect_compiled_metrics(self, file_path: str, language: str) -> Dict[str, Any]:
        """Collect metrics for compiled languages (Java, C#, C++).
        
        Args:
            file_path: Path to the file
            language: Language name
            
        Returns:
            Dictionary of language-specific metrics
        """
        metrics = {}
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
                content = f.read()
                
            # Collect metrics based on language
            if language == "java":
                return self._analyze_java_metrics(content)
            elif language == "csharp":
                return self._analyze_csharp_metrics(content)
            elif language == "cpp":
                return self._analyze_cpp_metrics(content)
        except Exception as e:
            logger.error(f"Error collecting {language} metrics for {file_path}: {e}")
            
        return metrics
    
    def _analyze_java_metrics(self, content: str) -> Dict[str, Any]:
        """Analyze Java code for metrics.
        
        Args:
            content: Java source code
            
        Returns:
            Dictionary of Java-specific metrics
        """
        metrics = {}
        
        # Count classes
        class_pattern = re.compile(r'\bclass\s+\w+|interface\s+\w+|enum\s+\w+')
        class_matches = class_pattern.findall(content)
        metrics["class_count"] = len(class_matches)
        
        # Count methods
        method_pattern = re.compile(r'(?:public|private|protected|static|final|native|synchronized|abstract|transient)+\s+[\w\<\>\[\]]+\s+(\w+) *\([^\)]*\) *(\{?|[^;])')
        method_matches = method_pattern.findall(content)
        metrics["method_count"] = len(method_matches)
        
        # Count imports
        import_pattern = re.compile(r'import\s+[\w\.]+;')
        import_matches = import_pattern.findall(content)
        metrics["import_count"] = len(import_matches)
        
        # Estimate complexity
        complexity = self._estimate_compiled_complexity(content)
        metrics["estimated_complexity"] = complexity
        
        return metrics
    
    def _analyze_csharp_metrics(self, content: str) -> Dict[str, Any]:
        """Analyze C# code for metrics.
        
        Args:
            content: C# source code
            
        Returns:
            Dictionary of C#-specific metrics
        """
        metrics = {}
        
        # Count classes
        class_pattern = re.compile(r'\bclass\s+\w+|\binterface\s+\w+|\benum\s+\w+|\bstruct\s+\w+')
        class_matches = class_pattern.findall(content)
        metrics["class_count"] = len(class_matches)
        
        # Count methods
        method_pattern = re.compile(r'(?:public|private|protected|internal|static|virtual|override|abstract|async)+\s+[\w\<\>\[\]]+\s+(\w+) *\([^\)]*\)')
        method_matches = method_pattern.findall(content)
        metrics["method_count"] = len(method_matches)
        
        # Count imports
        import_pattern = re.compile(r'using\s+[\w\.]+;')
        import_matches = import_pattern.findall(content)
        metrics["import_count"] = len(import_matches)
        
        # Estimate complexity
        complexity = self._estimate_compiled_complexity(content)
        metrics["estimated_complexity"] = complexity
        
        return metrics
    
    def _analyze_cpp_metrics(self, content: str) -> Dict[str, Any]:
        """Analyze C++ code for metrics.
        
        Args:
            content: C++ source code
            
        Returns:
            Dictionary of C++-specific metrics
        """
        metrics = {}
        
        # Count classes
        class_pattern = re.compile(r'\bclass\s+\w+|\bstruct\s+\w+|\benum\s+\w+')
        class_matches = class_pattern.findall(content)
        metrics["class_count"] = len(class_matches)
        
        # Count functions (simplified)
        function_pattern = re.compile(r'[\w\*\&]+\s+(\w+)\s*\([^\{;]*\)\s*(?=\{)')
        function_matches = function_pattern.findall(content)
        metrics["function_count"] = len(function_matches)
        
        # Count includes
        include_pattern = re.compile(r'#include\s+[<"][\w\.]+[>"]')
        include_matches = include_pattern.findall(content)
        metrics["include_count"] = len(include_matches)
        
        # Estimate complexity
        complexity = self._estimate_compiled_complexity(content)
        metrics["estimated_complexity"] = complexity
        
        return metrics
    
    def _estimate_compiled_complexity(self, content: str) -> int:
        """Estimate complexity for compiled languages.
        
        Args:
            content: Source code content
            
        Returns:
            Estimated complexity
        """
        complexity = 1  # Base complexity
        
        # Count control flow statements
        if_count = len(re.findall(r'\bif\s*\(', content))
        for_count = len(re.findall(r'\bfor\s*\(', content))
        while_count = len(re.findall(r'\bwhile\s*\(', content))
        switch_count = len(re.findall(r'\bswitch\s*\(', content))
        case_count = len(re.findall(r'\bcase\s+', content))
        catch_count = len(re.findall(r'\bcatch\s*\(', content))
        
        complexity += if_count + for_count + while_count + switch_count + case_count + catch_count
        
        # Count logical operators as additional complexity
        and_count = len(re.findall(r'&&', content))
        or_count = len(re.findall(r'\|\|', content))
        
        complexity += and_count + or_count
        
        return complexity
    
    def _collect_radon_metrics(self, file_path: str) -> Dict[str, Any]:
        """Collect metrics using Radon package for Python files.
        
        Args:
            file_path: Path to the Python file
            
        Returns:
            Dictionary of Radon metrics
        """
        metrics = {}
        
        try:
            import radon.complexity
            import radon.metrics
            import radon.raw
            
            with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
                content = f.read()
                
            # Calculate raw metrics
            raw_metrics = radon.raw.analyze(content)
            metrics["radon_raw_loc"] = raw_metrics.loc
            metrics["radon_sloc"] = raw_metrics.sloc
            metrics["radon_comments"] = raw_metrics.comments
            metrics["radon_blank"] = raw_metrics.blank
            metrics["radon_single_comments"] = raw_metrics.single_comments
            metrics["radon_multi_comments"] = raw_metrics.multi
            
            # Calculate maintainability index
            mi = radon.metrics.mi_visit(content, True)
            metrics["maintainability_index"] = mi
            
            # Calculate cyclomatic complexity
            complexity = radon.complexity.cc_visit(content)
            
            if complexity:
                total_cc = sum(cc.complexity for cc in complexity)
                avg_cc = total_cc / len(complexity) if complexity else 0
                max_cc = max(cc.complexity for cc in complexity) if complexity else 0
                
                metrics["total_cyclomatic_complexity"] = total_cc
                metrics["avg_cyclomatic_complexity"] = avg_cc
                metrics["max_cyclomatic_complexity"] = max_cc
                
                # Count complexity categories
                simple = sum(1 for cc in complexity if cc.complexity <= 5)
                medium = sum(1 for cc in complexity if 5 < cc.complexity <= 10)
                high = sum(1 for cc in complexity if 10 < cc.complexity <= 20)
                extreme = sum(1 for cc in complexity if cc.complexity > 20)
                
                metrics["simple_functions"] = simple
                metrics["medium_complexity_functions"] = medium
                metrics["high_complexity_functions"] = high
                metrics["extreme_complexity_functions"] = extreme
        except Exception as e:
            logger.error(f"Error collecting Radon metrics for {file_path}: {e}")
            
        return metrics
    
    def _collect_lizard_metrics(self, file_path: str) -> Dict[str, Any]:
        """Collect metrics using lizard package.
        
        Args:
            file_path: Path to the file
            
        Returns:
            Dictionary of lizard metrics
        """
        metrics = {}
        
        try:
            import lizard
            
            # Analyze the file
            analysis = lizard.analyze_file(file_path)
            
            # Get file-level metrics
            metrics["lizard_nloc"] = analysis.nloc
            metrics["lizard_function_count"] = len(analysis.function_list)
            
            if analysis.function_list:
                # Calculate function-level metrics
                total_cc = sum(func.cyclomatic_complexity for func in analysis.function_list)
                avg_cc = total_cc / len(analysis.function_list)
                max_cc = max(func.cyclomatic_complexity for func in analysis.function_list)
                
                total_tokens = sum(func.token_count for func in analysis.function_list)
                avg_tokens = total_tokens / len(analysis.function_list)
                max_tokens = max(func.token_count for func in analysis.function_list)
                
                metrics["lizard_total_cc"] = total_cc
                metrics["lizard_avg_cc"] = avg_cc
                metrics["lizard_max_cc"] = max_cc
                
                metrics["lizard_total_tokens"] = total_tokens
                metrics["lizard_avg_tokens"] = avg_tokens
                metrics["lizard_max_tokens"] = max_tokens
                
                # Count functions by complexity
                simple = sum(1 for func in analysis.function_list if func.cyclomatic_complexity <= 5)
                medium = sum(1 for func in analysis.function_list if 5 < func.cyclomatic_complexity <= 10)
                high = sum(1 for func in analysis.function_list if 10 < func.cyclomatic_complexity <= 20)
                extreme = sum(1 for func in analysis.function_list if func.cyclomatic_complexity > 20)
                
                metrics["lizard_simple_functions"] = simple
                metrics["lizard_medium_functions"] = medium
                metrics["lizard_high_functions"] = high
                metrics["lizard_extreme_functions"] = extreme
                
                # Function length statistics
                func_lengths = [func.nloc for func in analysis.function_list]
                metrics["lizard_avg_function_length"] = sum(func_lengths) / len(func_lengths)
                metrics["lizard_max_function_length"] = max(func_lengths)
                
                # Calculate lizard warnings
                warning_count = sum(1 for func in analysis.function_list 
                                   if func.cyclomatic_complexity > 15 or 
                                      func.nloc > 1000 or 
                                      func.token_count > 1000)
                metrics["lizard_warnings"] = warning_count
        except Exception as e:
            logger.error(f"Error collecting lizard metrics for {file_path}: {e}")
            
        return metrics
            
    @LogEvent("store_metrics")
    def store_metrics(self, file_id: int, metrics: Dict[str, Any]) -> bool:
        """Store metrics in the database.
        
        Args:
            file_id: Database ID of the file
            metrics: Metrics to store
            
        Returns:
            True if successful, False otherwise
        """
        from ..db.neo4j_connector import get_connector
        
        try:
            connector = get_connector()
            
            # Create a CodeMetrics node
            metrics_props = {
                "timestamp": metrics.get("timestamp", self._get_timestamp()),
                **{k: v for k, v in metrics.items() if self._is_valid_property(v)}
            }
            
            metrics_id = connector.create_node(
                labels=["CodeMetrics"],
                properties=metrics_props
            )
            
            # Create relationship to the file
            connector.create_relationship(
                start_id=file_id,
                end_id=metrics_id,
                rel_type="HAS_METRICS"
            )
            
            logger.info(f"Stored metrics for file ID {file_id}")
            return True
        except Exception as e:
            logger.error(f"Error storing metrics in database: {e}")
            return False
    
    def _get_timestamp(self) -> str:
        """Get current timestamp.
        
        Returns:
            ISO format timestamp
        """
        from datetime import datetime, timezone
        return datetime.now(timezone.utc).isoformat()
    
    def _is_valid_property(self, value: Any) -> bool:
        """Check if a value can be stored as a Neo4j property.
        
        Args:
            value: Value to check
            
        Returns:
            True if the value can be stored, False otherwise
        """
        if value is None:
            return False
            
        if isinstance(value, (str, int, float, bool)):
            return True
            
        if isinstance(value, list) and all(isinstance(item, (str, int, float, bool)) for item in value):
            return True
            
        return False
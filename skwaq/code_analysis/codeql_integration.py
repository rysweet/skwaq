"""CodeQL integration for advanced code analysis.

This module provides integration with the CodeQL static analysis tool
for detecting security vulnerabilities in code.
"""

import os
import json
import tempfile
import subprocess
from pathlib import Path
from typing import Dict, List, Any, Optional, Union, Tuple

from ..utils.logging import get_logger, LogEvent
from ..utils.config import get_config
from ..shared.finding import Finding

logger = get_logger(__name__)


class CodeQLIntegration:
    """Integration with the CodeQL static analysis tool.
    
    This class provides functionality for executing CodeQL queries against
    code repositories to identify security vulnerabilities.
    """
    
    def __init__(self, codeql_path: Optional[str] = None):
        """Initialize the CodeQL integration.
        
        Args:
            codeql_path: Path to the CodeQL executable. If None, attempts
                to find CodeQL in PATH or from config.
        """
        self.config = get_config()
        
        # Find CodeQL executable path
        self.codeql_path = codeql_path
        
        if not self.codeql_path:
            # Try to get from config
            self.codeql_path = self.config.get("codeql.path")
            
        if not self.codeql_path:
            # Try to find in PATH
            self.codeql_path = self._find_codeql_in_path()
        
        self.is_available = self._check_codeql_available()
        
        if self.is_available:
            logger.info(f"CodeQL integration initialized with path: {self.codeql_path}")
        else:
            logger.warning(
                "CodeQL is not available. CodeQL analysis will be skipped. "
                "Install CodeQL CLI or set the correct path in config."
            )
            
        # Directory for built-in queries
        self.queries_dir = self.config.get(
            "codeql.queries_dir", 
            Path.home() / ".skwaq" / "codeql-queries"
        )
        
        # Ensure the queries directory exists
        os.makedirs(self.queries_dir, exist_ok=True)
        
        # Initialize built-in queries for different languages
        self.default_queries = {
            "python": ["security/cwe-079", "security/cwe-089", "security/cwe-022"], 
            "javascript": ["security/cwe-079", "security/cwe-094", "security/cwe-352"],
            "csharp": ["security/cwe-079", "security/cwe-089", "security/cwe-614"],
            "java": ["security/cwe-078", "security/cwe-089", "security/cwe-295"],
            "cpp": ["security/cwe-119", "security/cwe-120", "security/cwe-476"],
            "go": ["security/cwe-079", "security/cwe-089", "security/cwe-022"],
        }
    
    def _find_codeql_in_path(self) -> Optional[str]:
        """Try to find CodeQL executable in PATH.
        
        Returns:
            Path to CodeQL executable or None if not found
        """
        paths = os.environ["PATH"].split(os.pathsep)
        for path in paths:
            codeql_path = os.path.join(path, "codeql")
            if os.path.exists(codeql_path) and os.access(codeql_path, os.X_OK):
                return codeql_path
            
            # Check for Windows executable
            codeql_exe = os.path.join(path, "codeql.exe")
            if os.path.exists(codeql_exe) and os.access(codeql_exe, os.X_OK):
                return codeql_exe
                
        return None
    
    def _check_codeql_available(self) -> bool:
        """Check if CodeQL is available and working.
        
        Returns:
            True if CodeQL is available, False otherwise
        """
        if not self.codeql_path:
            return False
            
        try:
            # Run codeql version command
            result = subprocess.run(
                [self.codeql_path, "version"],
                capture_output=True,
                text=True,
                check=False
            )
            
            if result.returncode == 0 and "CodeQL" in result.stdout:
                # Parse version from output
                version_info = result.stdout.strip()
                logger.info(f"CodeQL version: {version_info}")
                return True
                
            return False
        except (subprocess.SubprocessError, OSError, FileNotFoundError):
            logger.warning(f"Failed to execute CodeQL at {self.codeql_path}")
            return False
    
    @LogEvent("create_codeql_database")
    def create_codeql_database(
        self, 
        repo_path: str, 
        language: str, 
        database_path: Optional[str] = None
    ) -> Optional[str]:
        """Create a CodeQL database from a repository.
        
        Args:
            repo_path: Path to the repository
            language: Programming language of the repository
            database_path: Path to store the database. If None, creates
                a temporary directory.
                
        Returns:
            Path to the created database or None if creation failed
        """
        if not self.is_available:
            logger.warning("Cannot create CodeQL database: CodeQL is not available")
            return None
            
        # Map skwaq language names to CodeQL language names
        language_map = {
            "python": "python",
            "javascript": "javascript",
            "typescript": "javascript",
            "csharp": "csharp",
            "c#": "csharp",
            "java": "java",
            "cpp": "cpp",
            "c++": "cpp",
            "c": "cpp",
            "go": "go",
            "ruby": "ruby",
        }
        
        # Normalize language name
        normalized_language = language.lower()
        codeql_language = language_map.get(normalized_language)
        
        if not codeql_language:
            logger.warning(f"Unsupported language for CodeQL: {language}")
            return None
            
        # Create temporary database path if not provided
        if not database_path:
            database_dir = tempfile.mkdtemp(prefix="skwaq_codeql_")
            database_path = os.path.join(database_dir, "db")
            
        logger.info(f"Creating CodeQL database for {language} at {database_path}")
        
        try:
            # Run CodeQL database create command
            cmd = [
                self.codeql_path,
                "database",
                "create",
                database_path,
                "--language=" + codeql_language,
                "--source-root=" + repo_path,
                "--overwrite"
            ]
            
            logger.debug(f"Running CodeQL command: {' '.join(cmd)}")
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=False
            )
            
            if result.returncode != 0:
                logger.error(f"CodeQL database creation failed: {result.stderr}")
                return None
                
            logger.info(f"CodeQL database created successfully at {database_path}")
            return database_path
        except subprocess.SubprocessError as e:
            logger.error(f"Error creating CodeQL database: {e}")
            return None
    
    @LogEvent("execute_query")
    def execute_query(
        self, 
        query_path: str, 
        database_path: str, 
        output_format: str = "json"
    ) -> List[Dict[str, Any]]:
        """Execute a CodeQL query against a database.
        
        Args:
            query_path: Path to the query file (.ql)
            database_path: Path to the CodeQL database
            output_format: Output format (json, csv, etc.)
            
        Returns:
            List of query results as dictionaries
        """
        if not self.is_available:
            logger.warning("Cannot execute CodeQL query: CodeQL is not available")
            return []
            
        logger.info(f"Executing CodeQL query: {query_path}")
        
        try:
            # Create temporary file for results
            with tempfile.NamedTemporaryFile(suffix=f".{output_format}", delete=False) as temp_file:
                results_path = temp_file.name
                
            # Run CodeQL query command
            cmd = [
                self.codeql_path,
                "query",
                "run",
                query_path,
                "--database=" + database_path,
                "--output=" + results_path,
                "--format=" + output_format
            ]
            
            logger.debug(f"Running CodeQL command: {' '.join(cmd)}")
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=False
            )
            
            if result.returncode != 0:
                logger.error(f"CodeQL query execution failed: {result.stderr}")
                return []
                
            # Parse results from file
            try:
                with open(results_path, 'r') as f:
                    if output_format == "json":
                        data = json.load(f)
                        results = data.get("results", [])
                    else:
                        # For other formats, return raw content
                        results = [{"result": f.read()}]
            except Exception as e:
                logger.error(f"Error parsing CodeQL results: {e}")
                results = []
                
            # Clean up temporary file
            try:
                os.unlink(results_path)
            except OSError:
                pass
                
            logger.info(f"CodeQL query returned {len(results)} results")
            return results
        except subprocess.SubprocessError as e:
            logger.error(f"Error executing CodeQL query: {e}")
            return []
    
    @LogEvent("run_default_queries")
    def run_default_queries(
        self, 
        database_path: str, 
        language: str
    ) -> List[Dict[str, Any]]:
        """Run default security queries for a language.
        
        Args:
            database_path: Path to the CodeQL database
            language: Programming language of the database
            
        Returns:
            List of query results as dictionaries
        """
        if not self.is_available:
            logger.warning("Cannot run default queries: CodeQL is not available")
            return []
            
        # Normalize language name
        normalized_language = language.lower()
        
        # Check if we have default queries for this language
        if normalized_language not in self.default_queries:
            logger.warning(f"No default CodeQL queries available for {language}")
            return []
            
        logger.info(f"Running default CodeQL queries for {language}")
        
        all_results: List[Dict[str, Any]] = []
        query_packs = self.default_queries[normalized_language]
        
        for query_pack in query_packs:
            try:
                # Run CodeQL pack command
                cmd = [
                    self.codeql_path,
                    "database",
                    "analyze",
                    database_path,
                    query_pack,
                    "--format=json"
                ]
                
                logger.debug(f"Running CodeQL command: {' '.join(cmd)}")
                
                with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as temp_file:
                    results_path = temp_file.name
                    
                    cmd.append("--output=" + results_path)
                    
                    result = subprocess.run(
                        cmd,
                        capture_output=True,
                        text=True,
                        check=False
                    )
                    
                    if result.returncode != 0:
                        logger.error(f"CodeQL pack execution failed: {result.stderr}")
                        continue
                        
                    # Parse results from file
                    try:
                        with open(results_path, 'r') as f:
                            data = json.load(f)
                            pack_results = data.get("results", [])
                            all_results.extend(pack_results)
                    except Exception as e:
                        logger.error(f"Error parsing CodeQL results: {e}")
                        
                    # Clean up temporary file
                    try:
                        os.unlink(results_path)
                    except OSError:
                        pass
            except subprocess.SubprocessError as e:
                logger.error(f"Error executing CodeQL pack: {e}")
                
        logger.info(f"Default CodeQL queries returned {len(all_results)} results")
        return all_results
    
    @LogEvent("convert_to_findings")
    def convert_to_findings(
        self, 
        codeql_results: List[Dict[str, Any]], 
        file_id_map: Dict[str, int]
    ) -> List[Finding]:
        """Convert CodeQL results to Skwaq findings.
        
        Args:
            codeql_results: CodeQL query results
            file_id_map: Mapping from file paths to database file IDs
            
        Returns:
            List of Finding objects
        """
        findings: List[Finding] = []
        
        for result in codeql_results:
            try:
                # Extract common information
                rule_id = result.get("rule_id", "unknown")
                message = result.get("message", "CodeQL finding")
                severity = result.get("severity", "Medium")
                
                # Map CodeQL severity to Skwaq severity
                severity_map = {
                    "error": "High",
                    "warning": "Medium",
                    "note": "Low",
                    "recommendation": "Info"
                }
                
                severity = severity_map.get(severity.lower(), severity)
                
                # Extract location information
                locations = result.get("locations", [])
                
                for location in locations:
                    file_path = location.get("file", "")
                    
                    # Try to find file ID
                    file_id = file_id_map.get(file_path)
                    if not file_id:
                        logger.warning(f"No file ID found for {file_path}")
                        continue
                        
                    # Extract line information
                    start_line = location.get("start_line", 0)
                    
                    # Create a finding
                    finding = Finding(
                        type="codeql",
                        vulnerability_type=rule_id,
                        description=message,
                        file_id=file_id,
                        line_number=start_line,
                        severity=severity,
                        confidence=0.9,  # CodeQL has high confidence
                        suggestion="Review the code based on CodeQL finding",
                        metadata={
                            "codeql_rule": rule_id,
                            "raw_result": result
                        }
                    )
                    
                    findings.append(finding)
            except Exception as e:
                logger.error(f"Error converting CodeQL result to finding: {e}")
                
        logger.info(f"Converted {len(findings)} CodeQL results to findings")
        return findings
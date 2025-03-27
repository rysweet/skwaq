"""Blarify integration for advanced code analysis.

This module provides integration with the Blarify library for advanced 
code analysis, AST processing, and code structure mapping.
"""

import os
import tempfile
from pathlib import Path
from typing import Dict, List, Any, Optional, Set, Tuple, Union
import logging

from ..shared.finding import Finding
from ..utils.logging import get_logger
from ..utils.config import get_config

logger = get_logger(__name__)

# Check if we're in CLI mode (to determine log level)
import os
import sys
in_cli_mode = 'skwaq' in sys.argv[0] if len(sys.argv) > 0 else False
log_level = logger.error if in_cli_mode else logger.warning

# Try to import Blarify, which will fail gracefully if not installed or properly configured
try:
    import blarify
    from blarify.code_hierarchy.tree_sitter_helper import TreeSitterHelper
    from blarify.project_graph_creator import ProjectGraphCreator
    from blarify.graph.graph_environment import GraphEnvironment
    from blarify.code_references import LspQueryHelper
    
    # Verify we can actually create a TreeSitterHelper instance
    try:
        test_helper = TreeSitterHelper()
        BLARIFY_AVAILABLE = True
        logger.debug("Blarify library successfully initialized.")
    except Exception as e:
        log_level(f"Blarify library found but couldn't be initialized: {e}. Using fallback analysis.")
        BLARIFY_AVAILABLE = False
except ImportError as e:
    # Only log at warning level in non-CLI mode
    msg = f"Blarify library or dependencies not found: {e}. Advanced AST analysis will be limited."
    if not in_cli_mode:
        logger.warning(msg)
    else:
        logger.debug(msg)
    BLARIFY_AVAILABLE = False


class BlarifyIntegration:
    """Integration with Blarify for advanced code analysis.
    
    This class provides integration with the Blarify library, which uses
    tree-sitter for advanced AST processing and code structure mapping.
    """
    
    def __init__(self) -> None:
        """Initialize the Blarify integration module."""
        self.config = get_config()
        self.tree_sitter_helper = None
        self.blarify_available = BLARIFY_AVAILABLE
        
        # Try to initialize tree-sitter helper if Blarify is available
        if self.blarify_available:
            try:
                self.tree_sitter_helper = TreeSitterHelper()
                logger.info("Blarify TreeSitterHelper initialized successfully")
            except Exception as e:
                logger.error(f"Failed to initialize Blarify TreeSitterHelper: {e}")
                self.blarify_available = False
                # Provide more helpful message about fallback behavior
                logger.info("Falling back to standard AST analysis methods without Blarify")
        else:
            # Only log this if we're not in a test environment to reduce noise
            if not os.environ.get("PYTEST_CURRENT_TEST"):
                logger.info("Blarify not available. Using standard AST analysis methods instead.")
    
    def is_available(self) -> bool:
        """Check if Blarify is available.
        
        Returns:
            True if Blarify is available, False otherwise
        """
        return self.blarify_available
    
    def get_ast(self, content: str, language: str) -> Optional[Dict[str, Any]]:
        """Parse code content into an AST using Blarify.
        
        Args:
            content: Code content to parse
            language: Programming language of the code
            
        Returns:
            Dictionary containing the AST or None if parsing failed
        """
        if not self.blarify_available or not self.tree_sitter_helper:
            logger.warning("Blarify is not available for AST parsing")
            return None
        
        try:
            # Map language names to Blarify supported languages
            language_map = {
                "Python": "python",
                "JavaScript": "javascript",
                "TypeScript": "typescript",
                "C#": "c_sharp",
                "Ruby": "ruby",
                "Go": "go"
            }
            
            # Normalize language name
            normalized_language = language_map.get(language, language.lower())
            
            # Write content to a temporary file for Tree-sitter parsing
            with tempfile.NamedTemporaryFile(delete=False, mode='w', suffix=f'.{normalized_language}') as tmp:
                tmp.write(content)
                tmp_path = tmp.name
            
            try:
                # Parse the file using tree-sitter
                ast = self.tree_sitter_helper.parse_file(tmp_path)
                
                # Process the AST to extract meaningful information
                processed_ast = self._process_ast(ast, normalized_language)
                
                return processed_ast
            finally:
                # Clean up temporary file
                if os.path.exists(tmp_path):
                    os.unlink(tmp_path)
        
        except Exception as e:
            logger.error(f"Error parsing AST with Blarify: {e}")
            return None
    
    def extract_code_structure(self, content: str, language: str) -> Optional[Dict[str, Any]]:
        """Extract code structure information using Blarify.
        
        Args:
            content: Code content to analyze
            language: Programming language of the code
            
        Returns:
            Dictionary containing code structure information or None if extraction failed
        """
        if not self.blarify_available:
            logger.warning("Blarify is not available for code structure extraction")
            return None
            
        try:
            # Extract structure information from the AST
            ast = self.get_ast(content, language)
            if not ast:
                return None
            
            # Extract structure information
            structure = {
                "functions": self._extract_functions(ast),
                "classes": self._extract_classes(ast),
                "imports": self._extract_imports(ast),
                "variables": self._extract_variables(ast)
            }
            
            return structure
        
        except Exception as e:
            logger.error(f"Error extracting code structure with Blarify: {e}")
            return None
    
    def analyze_security_patterns(
        self, content: str, language: str, file_id: int
    ) -> List[Finding]:
        """Analyze code for security patterns using Blarify and tree-sitter.
        
        Args:
            content: Code content to analyze
            language: Programming language of the code
            file_id: ID of the file in the database
            
        Returns:
            List of security findings
        """
        findings = []
        
        if not self.blarify_available:
            logger.warning("Blarify is not available for security pattern analysis")
            return findings
            
        try:
            ast = self.get_ast(content, language)
            if not ast:
                return findings
            
            # Analyze the AST for security patterns based on language
            if language == "Python":
                findings.extend(self._analyze_python_security_patterns(ast, content, file_id))
            elif language == "C#":
                findings.extend(self._analyze_csharp_security_patterns(ast, content, file_id))
            elif language in ("JavaScript", "TypeScript"):
                findings.extend(self._analyze_javascript_security_patterns(ast, content, file_id))
            
            return findings
        
        except Exception as e:
            logger.error(f"Error analyzing security patterns with Blarify: {e}")
            return findings
    
    def _process_ast(self, ast: Any, language: str) -> Dict[str, Any]:
        """Process a raw AST from tree-sitter into a more useful structure.
        
        Args:
            ast: Raw AST from tree-sitter
            language: Programming language of the code
            
        Returns:
            Processed AST as a dictionary
        """
        # Default implementation returns a simple representation
        return {
            "type": "root",
            "language": language,
            "children": self._extract_nodes(ast)
        }
    
    def _extract_nodes(self, node: Any) -> List[Dict[str, Any]]:
        """Extract node information from a tree-sitter node recursively.
        
        Args:
            node: Tree-sitter node
            
        Returns:
            List of node dictionaries
        """
        # Basic implementation - in practice, we would parse the AST recursively
        # This is a placeholder that would need to be implemented based on tree-sitter's API
        return []
    
    def _extract_functions(self, ast: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract function information from an AST.
        
        Args:
            ast: Processed AST
            
        Returns:
            List of function dictionaries
        """
        # Placeholder implementation
        return []
    
    def _extract_classes(self, ast: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract class information from an AST.
        
        Args:
            ast: Processed AST
            
        Returns:
            List of class dictionaries
        """
        # Placeholder implementation
        return []
    
    def _extract_imports(self, ast: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract import information from an AST.
        
        Args:
            ast: Processed AST
            
        Returns:
            List of import dictionaries
        """
        # Placeholder implementation
        return []
    
    def _extract_variables(self, ast: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract variable information from an AST.
        
        Args:
            ast: Processed AST
            
        Returns:
            List of variable dictionaries
        """
        # Placeholder implementation
        return []
    
    def _analyze_python_security_patterns(
        self, ast: Dict[str, Any], content: str, file_id: int
    ) -> List[Finding]:
        """Analyze Python code for security patterns using tree-sitter.
        
        Args:
            ast: Processed AST
            content: Original code content
            file_id: ID of the file in the database
            
        Returns:
            List of security findings
        """
        # Placeholder implementation
        return []
    
    def _analyze_csharp_security_patterns(
        self, ast: Dict[str, Any], content: str, file_id: int
    ) -> List[Finding]:
        """Analyze C# code for security patterns using tree-sitter.
        
        Args:
            ast: Processed AST
            content: Original code content
            file_id: ID of the file in the database
            
        Returns:
            List of security findings
        """
        # Placeholder implementation
        return []
    
    def _analyze_javascript_security_patterns(
        self, ast: Dict[str, Any], content: str, file_id: int
    ) -> List[Finding]:
        """Analyze JavaScript/TypeScript code for security patterns using tree-sitter.
        
        Args:
            ast: Processed AST
            content: Original code content
            file_id: ID of the file in the database
            
        Returns:
            List of security findings
        """
        # Placeholder implementation
        return []
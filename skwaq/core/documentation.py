"""Documentation management functionality for Skwaq.

This module provides functionality for managing documentation, including
building documentation, checking coverage, and identifying documentation gaps.
"""

import os
import sys
import subprocess
import re
import importlib
import inspect
from pathlib import Path
from typing import Dict, Any, List, Optional, Set, Tuple, Union

from skwaq.utils.config import get_config
from skwaq.utils.logging import get_logger

logger = get_logger(__name__)


class DocumentationManager:
    """Manages documentation for the Skwaq project."""
    
    def __init__(self) -> None:
        """Initialize the DocumentationManager."""
        self.config = get_config()
        self.project_root = Path(__file__).parent.parent.parent
        self.docs_dir = self.project_root / "docs"
        self.source_dir = self.project_root / "skwaq"
        
    def build_documentation(self, output_format: str = "html") -> str:
        """Build documentation in the specified format.
        
        Args:
            output_format: The output format ('html', 'pdf', 'epub').
                
        Returns:
            The path to the built documentation.
        """
        if not self.docs_dir.exists():
            raise FileNotFoundError(f"Documentation directory not found: {self.docs_dir}")
        
        # Ensure docs directory exists
        os.makedirs(self.docs_dir, exist_ok=True)
        
        try:
            # Build documentation using Sphinx
            build_dir = self.docs_dir / "_build" / output_format
            os.makedirs(build_dir, exist_ok=True)
            
            cmd = [
                "sphinx-build",
                "-b", output_format,
                str(self.docs_dir),
                str(build_dir),
            ]
            
            subprocess.run(cmd, check=True, capture_output=True)
            
            return str(build_dir)
        except subprocess.CalledProcessError as e:
            logger.error(f"Error building documentation: {e}")
            logger.debug(f"STDOUT: {e.stdout.decode()}")
            logger.debug(f"STDERR: {e.stderr.decode()}")
            raise RuntimeError(f"Failed to build documentation: {e}") from e
        
    def get_documentation_coverage(self) -> float:
        """Calculate documentation coverage percentage.
        
        Returns:
            The documentation coverage percentage (0-100).
        """
        try:
            # Use docstr-coverage tool if available
            cmd = [
                sys.executable,
                "-m",
                "docstr_coverage",
                str(self.source_dir),
                "--skipmagic",
                "--skipfile=__init__.py",
                "--format=json",
            ]
            
            try:
                result = subprocess.run(cmd, check=True, capture_output=True, text=True)
                
                # Parse the JSON output
                import json
                coverage_data = json.loads(result.stdout)
                return float(coverage_data.get("total", {}).get("coverage", 0)) * 100
            except (subprocess.SubprocessError, ImportError, json.JSONDecodeError) as e:
                logger.error(f"Error running docstr-coverage: {e}")
                # Fall through to manual calculation
            
        except Exception as e:
            logger.error(f"Error calculating documentation coverage: {e}")
            
        # Fallback to manual calculation if docstr-coverage fails
        return self._calculate_coverage_manually()
    
    def _calculate_coverage_manually(self) -> float:
        """Calculate documentation coverage manually by inspecting modules.
        
        Returns:
            The documentation coverage percentage (0-100).
        """
        total_objects = 0
        documented_objects = 0
        
        # Get all Python files
        python_files = list(self.source_dir.glob("**/*.py"))
        
        for file_path in python_files:
            if file_path.name == "__init__.py":
                continue
                
            # Convert file path to module path
            rel_path = file_path.relative_to(self.project_root)
            module_path = str(rel_path).replace("/", ".").replace("\\", ".")[:-3]  # Remove .py
            
            try:
                # Import the module
                module = importlib.import_module(module_path)
                
                # Count classes and functions
                for name, obj in inspect.getmembers(module):
                    if name.startswith("_"):
                        continue
                        
                    # Only count classes and functions
                    if inspect.isclass(obj) or inspect.isfunction(obj):
                        total_objects += 1
                        if obj.__doc__:
                            documented_objects += 1
                            
            except (ImportError, AttributeError) as e:
                logger.warning(f"Error importing module {module_path}: {e}")
                
        if total_objects == 0:
            return 0.0
            
        return (documented_objects / total_objects) * 100
        
    def get_missing_documentation(self) -> List[str]:
        """Get a list of objects missing documentation.
        
        Returns:
            A list of object paths missing documentation.
        """
        missing_docs = []
        
        # Get all Python files
        python_files = list(self.source_dir.glob("**/*.py"))
        
        for file_path in python_files:
            if file_path.name == "__init__.py":
                continue
                
            # Convert file path to module path
            rel_path = file_path.relative_to(self.project_root)
            module_path = str(rel_path).replace("/", ".").replace("\\", ".")[:-3]  # Remove .py
            
            try:
                # Import the module
                module = importlib.import_module(module_path)
                
                # Check classes and functions
                for name, obj in inspect.getmembers(module):
                    if name.startswith("_") and name != "__init__":
                        continue
                        
                    # Only check classes and functions
                    if inspect.isclass(obj):
                        if not obj.__doc__:
                            missing_docs.append(f"{module_path}.{name} (class)")
                            
                        # Check methods in class
                        for method_name, method in inspect.getmembers(obj, inspect.isfunction):
                            if not method_name.startswith("_") or method_name == "__init__":
                                if not method.__doc__:
                                    missing_docs.append(f"{module_path}.{name}.{method_name} (method)")
                                    
                    elif inspect.isfunction(obj):
                        if not obj.__doc__:
                            missing_docs.append(f"{module_path}.{name} (function)")
                            
            except (ImportError, AttributeError) as e:
                logger.warning(f"Error importing module {module_path}: {e}")
                
        return missing_docs
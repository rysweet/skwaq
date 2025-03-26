"""Architecture reconstruction for code analysis.

This module provides functionality for reconstructing the architecture
of a software system from its source code.
"""

import os
import re
import ast
import json
import glob
from pathlib import Path
from typing import Dict, Any, List, Optional, Set, Tuple

from ...utils.logging import get_logger, LogEvent
from ...utils.config import get_config
from ...shared.finding import ArchitectureModel
from ...core.openai_client import get_openai_client
from ..patterns.matcher import PatternMatcher

logger = get_logger(__name__)


class ArchitectureReconstructor:
    """Reconstructs software architecture from code.
    
    This class provides functionality for analyzing source code to reconstruct
    the architecture of the software system, identifying components and their relationships.
    """
    
    def __init__(self) -> None:
        """Initialize the architecture reconstructor."""
        self.config = get_config()
        self.openai_client = get_openai_client(async_mode=True)
        self.pattern_matcher = PatternMatcher()
        
        # Common dependency patterns by language
        self.dependency_patterns = {
            "python": {
                "import": r"^\s*import\s+(\S+)(?:\s+as\s+\S+)?",
                "from_import": r"^\s*from\s+(\S+)\s+import",
                "package_usage": r"([a-zA-Z_][a-zA-Z0-9_]*)\.[a-zA-Z_][a-zA-Z0-9_]*\(",
            },
            "javascript": {
                "import": r"^\s*import\s+.*\s+from\s+['\"]([^'\"]+)['\"]",
                "require": r"^\s*(?:const|let|var)\s+.*\s*=\s*require\(['\"]([^'\"]+)['\"]",
                "dynamic_import": r"import\(['\"]([^'\"]+)['\"]",
            },
            "typescript": {
                "import": r"^\s*import\s+.*\s+from\s+['\"]([^'\"]+)['\"]",
                "require": r"^\s*(?:const|let|var)\s+.*\s*=\s*require\(['\"]([^'\"]+)['\"]",
                "dynamic_import": r"import\(['\"]([^'\"]+)['\"]",
                "type_import": r"^\s*import\s+type\s+.*\s+from\s+['\"]([^'\"]+)['\"]",
            },
            "java": {
                "import": r"^\s*import\s+([^;]+);",
                "static_import": r"^\s*import\s+static\s+([^;]+);",
                "class_usage": r"new\s+([a-zA-Z_][a-zA-Z0-9_]*)",
            },
            "csharp": {
                "using": r"^\s*using\s+([^;]+);",
                "namespace": r"^\s*namespace\s+([^{;]+)",
                "class_usage": r"new\s+([a-zA-Z_][a-zA-Z0-9_]*)",
            },
        }
        
        # Folder patterns that typically indicate components
        self.component_folder_patterns = [
            r"src/([^/]+)",
            r"app/([^/]+)",
            r"lib/([^/]+)",
            r"modules/([^/]+)",
            r"components/([^/]+)",
            r"services/([^/]+)",
            r"controllers/([^/]+)",
            r"views/([^/]+)",
            r"models/([^/]+)",
        ]
        
        # File extensions for different languages
        self.language_extensions = {
            ".py": "python",
            ".js": "javascript",
            ".jsx": "javascript",
            ".ts": "typescript",
            ".tsx": "typescript",
            ".java": "java",
            ".cs": "csharp",
            ".cpp": "cpp",
            ".c": "c",
            ".h": "cpp",
            ".hpp": "cpp",
            ".rb": "ruby",
            ".go": "go",
            ".php": "php",
        }
        
        logger.info("ArchitectureReconstructor initialized")
    
    def _get_file_language(self, file_path: str) -> str:
        """Determine the programming language of a file based on its extension.
        
        Args:
            file_path: Path to the file
            
        Returns:
            Language name or "unknown"
        """
        _, ext = os.path.splitext(file_path)
        return self.language_extensions.get(ext.lower(), "unknown")
    
    def _get_files(self, repo_path: str, include_patterns: Optional[List[str]] = None) -> List[str]:
        """Get all code files in a repository.
        
        Args:
            repo_path: Path to the repository
            include_patterns: Optional list of glob patterns to include
            
        Returns:
            List of file paths
        """
        if not include_patterns:
            # Default patterns for common code files
            include_patterns = [
                "**/*.py", "**/*.js", "**/*.jsx", "**/*.ts", "**/*.tsx", 
                "**/*.java", "**/*.cs", "**/*.cpp", "**/*.c", "**/*.h",
                "**/*.hpp", "**/*.rb", "**/*.go", "**/*.php"
            ]
            
        all_files = []
        repo_path = os.path.abspath(repo_path)
        
        for pattern in include_patterns:
            matched_files = glob.glob(os.path.join(repo_path, pattern), recursive=True)
            all_files.extend(matched_files)
            
        # Remove duplicate files
        return list(set(all_files))
    
    def _extract_component_from_path(self, file_path: str, repo_path: str) -> str:
        """Extract component name from file path based on common patterns.
        
        Args:
            file_path: Path to the file
            repo_path: Base repository path
            
        Returns:
            Component name or None
        """
        # Get the relative path
        if file_path.startswith(repo_path):
            rel_path = os.path.relpath(file_path, repo_path)
        else:
            rel_path = file_path
            
        # Try to match component folder patterns
        for pattern in self.component_folder_patterns:
            match = re.search(pattern, rel_path)
            if match:
                return match.group(1)
                
        # If no match, use the top-level directory
        parts = rel_path.split(os.path.sep)
        if len(parts) > 1:
            return parts[0]
            
        return "root"
    
    def _extract_dependencies(self, file_path: str, language: str, content: Optional[str] = None) -> List[str]:
        """Extract dependencies from a file based on its language.
        
        Args:
            file_path: Path to the file
            language: Programming language
            content: Optional file content (will be read if not provided)
            
        Returns:
            List of dependencies
        """
        if not content:
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
            except (IOError, UnicodeDecodeError):
                logger.warning(f"Could not read file {file_path}")
                return []
                
        dependencies = []
        
        # Get language-specific patterns
        patterns = self.dependency_patterns.get(language, {})
        
        for pattern_name, pattern in patterns.items():
            matches = re.findall(pattern, content, re.MULTILINE)
            dependencies.extend(matches)
            
        # Clean and normalize dependencies
        normalized_deps = []
        for dep in dependencies:
            # Split by dots to get the top-level package
            parts = dep.split('.')
            if parts and parts[0]:
                # Remove quotes and other unwanted characters
                clean_dep = re.sub(r'[\'"\s]', '', parts[0])
                if clean_dep:
                    normalized_deps.append(clean_dep)
                    
        return list(set(normalized_deps))  # Remove duplicates
    
    def _extract_package_info(self, file_path: str, repo_path: str) -> Dict[str, Any]:
        """Extract package information from Python files.
        
        Args:
            file_path: Path to the file
            repo_path: Base repository path
            
        Returns:
            Dictionary with package information
        """
        info = {"name": None, "path": file_path}
        
        try:
            # Get the package name from the file path
            rel_path = os.path.relpath(file_path, repo_path)
            
            # Convert path to potential package name
            path_parts = os.path.dirname(rel_path).split(os.path.sep)
            if path_parts and path_parts[0] == "src":
                path_parts = path_parts[1:]
                
            if path_parts:
                package_name = ".".join(path_parts)
                info["name"] = package_name
        except Exception as e:
            logger.error(f"Error extracting package info from {file_path}: {e}")
            
        return info
    
    @LogEvent("identify_components")
    def identify_components(self, repo_path: str) -> List[Dict[str, Any]]:
        """Identify components in a repository.
        
        Args:
            repo_path: Path to the repository
            
        Returns:
            List of component information dictionaries
        """
        components = {}
        
        # Get all code files
        files = self._get_files(repo_path)
        
        # First pass: identify potential components by directory structure
        for file_path in files:
            language = self._get_file_language(file_path)
            if language == "unknown":
                continue
                
            component_name = self._extract_component_from_path(file_path, repo_path)
            
            if component_name not in components:
                components[component_name] = {
                    "name": component_name,
                    "type": "module",
                    "purpose": None,
                    "files": [],
                    "languages": set(),
                    "paths": set(),
                }
                
            component = components[component_name]
            component["files"].append(file_path)
            component["languages"].add(language)
            
            # Add directory to component paths
            dir_path = os.path.dirname(file_path)
            component["paths"].add(dir_path)
        
        # Second pass: determine component types based on content and structure
        for component_name, component in components.items():
            # Determine if it's a library, application, or service
            if any("test" in os.path.basename(f).lower() for f in component["files"]):
                component["has_tests"] = True
            else:
                component["has_tests"] = False
                
            # Check for common component indicators
            if any("api" in os.path.basename(f).lower() for f in component["files"]):
                component["type"] = "api"
            elif any("controller" in os.path.basename(f).lower() for f in component["files"]):
                component["type"] = "controller"
            elif any("model" in os.path.basename(f).lower() for f in component["files"]):
                component["type"] = "model"
            elif any("view" in os.path.basename(f).lower() for f in component["files"]):
                component["type"] = "view"
            elif any("service" in os.path.basename(f).lower() for f in component["files"]):
                component["type"] = "service"
            elif any("util" in os.path.basename(f).lower() for f in component["files"]):
                component["type"] = "utility"
                
            # Convert language set to list for JSON serialization
            component["languages"] = list(component["languages"])
            
            # Keep only component paths that are common to all files
            common_prefix = os.path.commonprefix(list(component["paths"]))
            component["path"] = common_prefix
            del component["paths"]
            
            # Do not include all files in the component info to keep the model size reasonable
            file_count = len(component["files"])
            component["file_count"] = file_count
            component["files"] = component["files"][:5]  # Keep only a few examples
        
        # Convert dictionary to list
        return list(components.values())
    
    @LogEvent("analyze_dependencies")
    def analyze_dependencies(self, repo_path: str, components: Optional[List[Dict[str, Any]]] = None) -> List[Dict[str, Any]]:
        """Analyze dependencies between components.
        
        Args:
            repo_path: Path to the repository
            components: Optional list of components (will be identified if not provided)
            
        Returns:
            List of dependency information dictionaries
        """
        if not components:
            components = self.identify_components(repo_path)
            
        # Create a map of files to components
        file_to_component = {}
        component_names = set()
        
        for component in components:
            component_names.add(component["name"])
            for file_path in component.get("files", []):
                file_to_component[file_path] = component["name"]
                
        # Get all code files
        files = self._get_files(repo_path)
        
        # Analyze dependencies
        dependencies = {}
        
        for file_path in files:
            language = self._get_file_language(file_path)
            if language == "unknown":
                continue
                
            # Get source component
            source_component = file_to_component.get(file_path)
            if not source_component:
                source_component = self._extract_component_from_path(file_path, repo_path)
                
            # Get file dependencies
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    
                file_deps = self._extract_dependencies(file_path, language, content)
                
                # Map dependencies to components when possible
                for dep in file_deps:
                    # Skip standard library dependencies
                    if dep in ["os", "sys", "re", "json", "math", "datetime", "time", "logging",
                              "collections", "string", "random", "itertools", "functools"]:
                        continue
                        
                    # Check if dependency is a component
                    if dep in component_names:
                        target_component = dep
                    else:
                        # Try to find a component that contains this dependency
                        target_component = None
                        for component in components:
                            if dep.lower() in component["name"].lower():
                                target_component = component["name"]
                                break
                                
                        if not target_component:
                            target_component = "external"
                            
                    # Create dependency key
                    dep_key = f"{source_component}:{target_component}"
                    
                    # Add or update dependency
                    if dep_key not in dependencies:
                        dependencies[dep_key] = {
                            "source": source_component,
                            "target": target_component,
                            "type": "uses",
                            "count": 0,
                            "files": set(),
                        }
                        
                    dependency = dependencies[dep_key]
                    dependency["count"] += 1
                    dependency["files"].add(file_path)
            except Exception as e:
                logger.error(f"Error analyzing dependencies in {file_path}: {e}")
        
        # Convert to list and prepare for serialization
        dependency_list = []
        
        for dep in dependencies.values():
            # Don't include self-references
            if dep["source"] == dep["target"]:
                continue
                
            # Convert file set to count
            dep["file_count"] = len(dep["files"])
            del dep["files"]
            
            dependency_list.append(dep)
            
        return dependency_list
    
    @LogEvent("generate_diagram")
    def generate_diagram(self, model: ArchitectureModel) -> str:
        """Generate a diagram from an architecture model in DOT format.
        
        Args:
            model: Architecture model to visualize
            
        Returns:
            String representation of the diagram in DOT format
        """
        # Create a DOT format string for the architecture diagram
        dot = ["digraph G {"]
        dot.append("  rankdir=LR;")
        dot.append("  node [shape=box, style=filled, fillcolor=lightblue];")
        
        # Add nodes for components
        for component in model.components:
            name = component.get("name", "unknown")
            comp_type = component.get("type", "module")
            label = f"{name}\\n({comp_type})"
            dot.append(f'  "{name}" [label="{label}"];')
            
        # Add edges for relationships
        for rel in model.relationships:
            source = rel.get("source", "")
            target = rel.get("target", "")
            rel_type = rel.get("type", "uses")
            
            if source and target:
                dot.append(f'  "{source}" -> "{target}" [label="{rel_type}"];')
                
        dot.append("}")
        
        return "\n".join(dot)
    
    @LogEvent("reconstruct_architecture")
    def reconstruct_architecture(self, repo_path: str) -> ArchitectureModel:
        """Reconstruct the architecture of a repository.
        
        Args:
            repo_path: Path to the repository
            
        Returns:
            ArchitectureModel representing the system
        """
        try:
            logger.info(f"Reconstructing architecture for repository: {repo_path}")
            
            # Get repository name from path
            repo_name = os.path.basename(os.path.normpath(repo_path))
            
            # Identify components
            components = self.identify_components(repo_path)
            logger.info(f"Identified {len(components)} components")
            
            # Analyze dependencies
            relationships = self.analyze_dependencies(repo_path, components)
            logger.info(f"Identified {len(relationships)} relationships")
            
            # Create architecture model
            architecture = ArchitectureModel(
                name=f"{repo_name} Architecture",
                components=components,
                relationships=relationships
            )
            
            return architecture
        except Exception as e:
            logger.error(f"Error reconstructing architecture: {e}")
            # Return minimal model in case of error
            return ArchitectureModel(
                name=f"Error: {str(e)}",
                components=[
                    {"name": "error", "type": "error", "purpose": str(e)}
                ],
                relationships=[]
            )
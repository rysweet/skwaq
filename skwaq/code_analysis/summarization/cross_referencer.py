"""Cross-reference linking for code analysis.

This module provides functionality for finding and linking references
between related components in code.
"""

import os
import re
import ast
import glob
from typing import Dict, Any, List, Optional, Set, Tuple

from ...utils.logging import get_logger, LogEvent
from ...utils.config import get_config
from ...core.openai_client import get_openai_client

logger = get_logger(__name__)


class CrossReferencer:
    """Finds and links references between code components.
    
    This class provides functionality for identifying references between
    code components, creating a graph of relationships.
    """
    
    # Class variable for singleton pattern
    _instance = None
    
    def __new__(cls):
        """Create a new instance or return the existing one."""
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance
    
    def __init__(self) -> None:
        """Initialize the cross referencer."""
        # Skip initialization if already done (singleton pattern)
        if getattr(self, '_initialized', False):
            return
            
        self.config = get_config()
        self.openai_client = get_openai_client(async_mode=True)
        
        # Cache for already analyzed files
        self._file_cache: Dict[str, Dict[str, Any]] = {}
        
        # Maximum lines of context to extract around a reference
        self.context_lines = self.config.get("cross_referencer.context_lines", 3)
        
        logger.info("CrossReferencer initialized")
        
        # Mark as initialized
        self._initialized = True
    
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
    
    def _get_file_language(self, file_path: str) -> str:
        """Get the programming language of a file based on extension.
        
        Args:
            file_path: Path to file
            
        Returns:
            Language name
        """
        ext = os.path.splitext(file_path)[1].lower()
        ext_map = {
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
        return ext_map.get(ext, "unknown")
    
    def _extract_symbols_from_file(self, file_path: str) -> Dict[str, Any]:
        """Extract all defined symbols from a file.
        
        Args:
            file_path: Path to the file
            
        Returns:
            Dictionary with symbol information
        """
        if file_path in self._file_cache:
            return self._file_cache[file_path]
            
        # Get file language
        language = self._get_file_language(file_path)
        
        # Initialize result
        result = {
            "path": file_path,
            "language": language,
            "symbols": [],
            "imports": [],
            "references": [],
        }
        
        try:
            # Read file content
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                
            # Parse based on language
            if language == "python":
                self._extract_python_symbols(content, result)
            elif language in ["javascript", "typescript"]:
                self._extract_js_symbols(content, result)
            elif language == "java":
                self._extract_java_symbols(content, result)
            elif language == "csharp":
                self._extract_csharp_symbols(content, result)
                
            # Cache result
            self._file_cache[file_path] = result
            
            return result
        except Exception as e:
            logger.error(f"Error extracting symbols from {file_path}: {e}")
            return result
    
    def _extract_python_symbols(self, content: str, result: Dict[str, Any]) -> None:
        """Extract symbols from Python code.
        
        Args:
            content: Python code
            result: Result dictionary to update
        """
        try:
            # Parse AST
            tree = ast.parse(content)
            
            # Extract defined symbols
            for node in ast.walk(tree):
                if isinstance(node, ast.FunctionDef):
                    result["symbols"].append({
                        "name": node.name,
                        "type": "function",
                        "line": node.lineno,
                        "end_line": node.end_lineno,
                    })
                elif isinstance(node, ast.ClassDef):
                    result["symbols"].append({
                        "name": node.name,
                        "type": "class",
                        "line": node.lineno,
                        "end_line": node.end_lineno,
                    })
                    
            # Extract imports
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for name in node.names:
                        result["imports"].append({
                            "name": name.name,
                            "alias": name.asname,
                            "line": node.lineno,
                        })
                elif isinstance(node, ast.ImportFrom):
                    module = node.module or ""
                    for name in node.names:
                        result["imports"].append({
                            "name": f"{module}.{name.name}",
                            "alias": name.asname,
                            "line": node.lineno,
                        })
                        
            # Extract function calls and other references
            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    func_name = ""
                    if isinstance(node.func, ast.Name):
                        func_name = node.func.id
                    elif isinstance(node.func, ast.Attribute):
                        if isinstance(node.func.value, ast.Name):
                            func_name = f"{node.func.value.id}.{node.func.attr}"
                        else:
                            func_name = node.func.attr
                            
                    if func_name:
                        result["references"].append({
                            "name": func_name,
                            "type": "call",
                            "line": node.lineno,
                        })
        except Exception as e:
            logger.error(f"Error parsing Python code: {e}")
    
    def _extract_js_symbols(self, content: str, result: Dict[str, Any]) -> None:
        """Extract symbols from JavaScript/TypeScript code using regex.
        
        Args:
            content: JavaScript/TypeScript code
            result: Result dictionary to update
        """
        # Use regex patterns for JS/TS - this is a simplified approach
        # Extract function declarations
        func_pattern = re.compile(r"(?:function\s+(\w+)|(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s*)?\(?.*\)?\s*=>|(?:const|let|var)\s+(\w+)\s*=\s*function)")
        for match in func_pattern.finditer(content):
            name = match.group(1) or match.group(2) or match.group(3)
            if name:
                line = content[:match.start()].count('\n') + 1
                result["symbols"].append({
                    "name": name,
                    "type": "function",
                    "line": line,
                    "end_line": None,  # Can't determine without proper parsing
                })
                
        # Extract class declarations
        class_pattern = re.compile(r"class\s+(\w+)")
        for match in class_pattern.finditer(content):
            name = match.group(1)
            line = content[:match.start()].count('\n') + 1
            result["symbols"].append({
                "name": name,
                "type": "class",
                "line": line,
                "end_line": None,  # Can't determine without proper parsing
            })
            
        # Extract imports
        import_pattern = re.compile(r"import\s+(?:{\s*(.+?)\s*}|(\w+))\s+from\s+['\"](.+?)['\"]")
        for match in import_pattern.finditer(content):
            imported_symbols = match.group(1) or match.group(2)
            module = match.group(3)
            line = content[:match.start()].count('\n') + 1
            
            if imported_symbols:
                for symbol in re.split(r'\s*,\s*', imported_symbols):
                    parts = re.split(r'\s+as\s+', symbol)
                    name = parts[0].strip()
                    alias = parts[1].strip() if len(parts) > 1 else None
                    
                    result["imports"].append({
                        "name": f"{module}.{name}",
                        "alias": alias,
                        "line": line,
                    })
                    
        # Extract require statements
        require_pattern = re.compile(r"(?:const|let|var)\s+(\w+)\s*=\s*require\(['\"](.+?)['\"]\)")
        for match in require_pattern.finditer(content):
            name = match.group(1)
            module = match.group(2)
            line = content[:match.start()].count('\n') + 1
            
            result["imports"].append({
                "name": module,
                "alias": name,
                "line": line,
            })
            
        # Extract function calls
        call_pattern = re.compile(r"(\w+)(?:\.\w+)*\(")
        for match in call_pattern.finditer(content):
            name = match.group(1)
            line = content[:match.start()].count('\n') + 1
            
            result["references"].append({
                "name": name,
                "type": "call",
                "line": line,
            })
    
    def _extract_java_symbols(self, content: str, result: Dict[str, Any]) -> None:
        """Extract symbols from Java code using regex.
        
        Args:
            content: Java code
            result: Result dictionary to update
        """
        # Extract class declarations
        class_pattern = re.compile(r"(?:public|protected|private|abstract|final|static|\s)*\s*(?:class|interface|enum)\s+(\w+)")
        for match in class_pattern.finditer(content):
            name = match.group(1)
            line = content[:match.start()].count('\n') + 1
            result["symbols"].append({
                "name": name,
                "type": "class",
                "line": line,
                "end_line": None,  # Can't determine without proper parsing
            })
            
        # Extract method declarations
        method_pattern = re.compile(r"(?:public|protected|private|abstract|final|static|\s)*\s*(?:<[\w\s<>,?]*>\s*)?(?:[\w<>,\[\]]+\s+)+(\w+)\s*\([^)]*\)")
        for match in method_pattern.finditer(content):
            name = match.group(1)
            line = content[:match.start()].count('\n') + 1
            result["symbols"].append({
                "name": name,
                "type": "method",
                "line": line,
                "end_line": None,  # Can't determine without proper parsing
            })
            
        # Extract imports
        import_pattern = re.compile(r"import\s+([^;]+);")
        for match in import_pattern.finditer(content):
            name = match.group(1).strip()
            line = content[:match.start()].count('\n') + 1
            
            result["imports"].append({
                "name": name,
                "alias": None,
                "line": line,
            })
            
        # Extract method calls
        call_pattern = re.compile(r"(\w+)(?:\.\w+)*\(")
        for match in call_pattern.finditer(content):
            name = match.group(1)
            line = content[:match.start()].count('\n') + 1
            
            result["references"].append({
                "name": name,
                "type": "call",
                "line": line,
            })
    
    def _extract_csharp_symbols(self, content: str, result: Dict[str, Any]) -> None:
        """Extract symbols from C# code using regex.
        
        Args:
            content: C# code
            result: Result dictionary to update
        """
        # Extract class declarations
        class_pattern = re.compile(r"(?:public|protected|private|internal|abstract|sealed|static|\s)*\s*(?:class|interface|enum|struct)\s+(\w+)")
        for match in class_pattern.finditer(content):
            name = match.group(1)
            line = content[:match.start()].count('\n') + 1
            result["symbols"].append({
                "name": name,
                "type": "class",
                "line": line,
                "end_line": None,  # Can't determine without proper parsing
            })
            
        # Extract method declarations
        method_pattern = re.compile(r"(?:public|protected|private|internal|abstract|override|virtual|static|\s)*\s*(?:[\w<>,\[\]]+\s+)+(\w+)\s*\([^)]*\)")
        for match in method_pattern.finditer(content):
            name = match.group(1)
            line = content[:match.start()].count('\n') + 1
            result["symbols"].append({
                "name": name,
                "type": "method",
                "line": line,
                "end_line": None,  # Can't determine without proper parsing
            })
            
        # Extract using directives
        using_pattern = re.compile(r"using\s+([^;]+);")
        for match in using_pattern.finditer(content):
            name = match.group(1).strip()
            line = content[:match.start()].count('\n') + 1
            
            result["imports"].append({
                "name": name,
                "alias": None,
                "line": line,
            })
            
        # Extract method calls
        call_pattern = re.compile(r"(\w+)(?:\.\w+)*\(")
        for match in call_pattern.finditer(content):
            name = match.group(1)
            line = content[:match.start()].count('\n') + 1
            
            result["references"].append({
                "name": name,
                "type": "call",
                "line": line,
            })
    
    def _find_references_in_file(self, symbol_name: str, file_path: str) -> List[Dict[str, Any]]:
        """Find references to a symbol in a specific file.
        
        Args:
            symbol_name: Name of the symbol to find
            file_path: Path to the file
            
        Returns:
            List of reference dictionaries
        """
        references = []
        
        try:
            # Extract symbols and references from file
            file_info = self._extract_symbols_from_file(file_path)
            
            # Get file content and lines
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                lines = content.splitlines()
                
            # Find exact matches for symbols in text
            pattern = re.compile(rf'\b({re.escape(symbol_name)})\b')
            for match in pattern.finditer(content):
                line_number = content[:match.start()].count('\n') + 1
                
                # Get context around the line
                start_line = max(0, line_number - self.context_lines - 1)
                end_line = min(len(lines), line_number + self.context_lines)
                context_lines = lines[start_line:end_line]
                context = "\n".join(context_lines)
                
                # Determine reference type
                ref_type = "use"
                
                # Check if it's a function call
                if match.end() < len(content) and content[match.end()].strip() == '(':
                    ref_type = "call"
                
                references.append({
                    "file": file_path,
                    "line": line_number,
                    "type": ref_type,
                    "context": context
                })
                
            # Also check references list
            for ref in file_info.get("references", []):
                if ref["name"] == symbol_name or ref["name"].endswith(f".{symbol_name}"):
                    line_number = ref["line"]
                    
                    # Get context around the line
                    start_line = max(0, line_number - self.context_lines - 1)
                    end_line = min(len(lines), line_number + self.context_lines)
                    context_lines = lines[start_line:end_line]
                    context = "\n".join(context_lines)
                    
                    references.append({
                        "file": file_path,
                        "line": line_number,
                        "type": ref["type"],
                        "context": context
                    })
        except Exception as e:
            logger.error(f"Error finding references in {file_path}: {e}")
            
        return references
    
    @LogEvent("find_references")
    def find_references(self, symbol: Dict[str, Any]) -> Dict[str, Any]:
        """Find references to a symbol in the codebase.
        
        Args:
            symbol: Dictionary with symbol information
            
        Returns:
            Dictionary with reference information
        """
        # Initialize result
        result = {
            "source_file": symbol.get("file", ""),
            "source_line": symbol.get("line", 0),
            "symbol": symbol.get("name", ""),
            "references": []
        }
        
        # Get symbol name
        symbol_name = symbol.get("name", "")
        if not symbol_name:
            logger.warning("No symbol name provided")
            return result
            
        # Add source file to search path if provided
        repo_path = os.path.dirname(symbol.get("file", ""))
        
        # If repo_path is empty, use current directory
        if not repo_path:
            repo_path = "."
            
        # Find all code files in repository
        files = self._get_files(repo_path)
        
        # Search for references in all files
        all_references = []
        
        for file_path in files:
            file_references = self._find_references_in_file(symbol_name, file_path)
            all_references.extend(file_references)
            
        result["references"] = all_references
        return result
    
    @LogEvent("link_components")
    def link_components(self, components: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Link related components based on references.
        
        Args:
            components: List of component information dictionaries
            
        Returns:
            List of relationship dictionaries
        """
        relationships = []
        
        # Create a map of component names to components
        component_map = {comp["name"]: comp for comp in components}
        
        # Create a map of file paths to components
        file_to_component = {}
        for comp in components:
            for file_path in comp.get("files", []):
                file_to_component[file_path] = comp["name"]
                
        # Find relationships between components based on imports and references
        for comp in components:
            comp_name = comp["name"]
            
            for file_path in comp.get("files", []):
                # Extract symbols and imports from file
                file_info = self._extract_symbols_from_file(file_path)
                
                # Check imports for references to other components
                for imp in file_info.get("imports", []):
                    import_name = imp["name"]
                    
                    # Check if import matches a component
                    for target_name, target_comp in component_map.items():
                        # Skip self-references
                        if target_name == comp_name:
                            continue
                            
                        # Check if import matches target component
                        if target_name in import_name or any(target_name in path for path in target_comp.get("files", [])):
                            # Create a relationship
                            rel = {
                                "source": comp_name,
                                "target": target_name,
                                "type": "imports",
                                "file": file_path,
                                "line": imp.get("line", 0)
                            }
                            
                            # Check if relationship already exists
                            if not any(r["source"] == rel["source"] and r["target"] == rel["target"] and r["type"] == rel["type"] for r in relationships):
                                relationships.append(rel)
        
        return relationships
    
    @LogEvent("generate_reference_graph")
    def generate_reference_graph(self, repo_path: str) -> Dict[str, Any]:
        """Generate a graph of references between components.
        
        Args:
            repo_path: Path to the repository
            
        Returns:
            Dictionary with graph structure
        """
        # Get all files in the repository
        files = self._get_files(repo_path)
        
        # Extract symbols from all files
        all_symbols = []
        file_symbols = {}
        
        for file_path in files:
            file_info = self._extract_symbols_from_file(file_path)
            file_symbols[file_path] = file_info
            
            for symbol in file_info.get("symbols", []):
                all_symbols.append({
                    "name": symbol["name"],
                    "type": symbol["type"],
                    "file": file_path,
                    "line": symbol["line"]
                })
                
        # Find references for each symbol
        references = []
        
        for symbol in all_symbols:
            symbol_refs = self.find_references(symbol)
            
            if symbol_refs["references"]:
                symbol_id = f"{symbol['name']}:{symbol['file']}:{symbol['line']}"
                
                for ref in symbol_refs["references"]:
                    ref_id = f"{symbol['name']}:{ref['file']}:{ref['line']}"
                    
                    references.append({
                        "source": symbol_id,
                        "target": ref_id,
                        "type": ref["type"]
                    })
                    
        # Create a graph of nodes and edges
        nodes = []
        edges = []
        
        # Add file nodes
        for file_path in files:
            nodes.append({
                "id": file_path,
                "type": "file",
                "name": os.path.basename(file_path)
            })
            
        # Add symbol nodes
        for symbol in all_symbols:
            symbol_id = f"{symbol['name']}:{symbol['file']}:{symbol['line']}"
            
            nodes.append({
                "id": symbol_id,
                "type": symbol["type"],
                "name": symbol["name"],
                "file": symbol["file"]
            })
            
            # Add edge from file to symbol
            edges.append({
                "source": symbol["file"],
                "target": symbol_id,
                "type": "defines"
            })
            
        # Add reference edges
        for ref in references:
            edges.append(ref)
            
        return {
            "nodes": nodes,
            "edges": edges
        }
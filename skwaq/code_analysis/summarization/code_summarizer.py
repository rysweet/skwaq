"""Code summarization for advanced code analysis.

This module provides functionality for generating summaries of code at
different levels of abstraction (function, class, module, system).
"""

import re
import ast
import os
from typing import Dict, Any, List, Optional, Tuple, Set

from ...utils.logging import get_logger, LogEvent
from ...utils.config import get_config
from ...shared.finding import CodeSummary
from ...core.openai_client import get_openai_client

logger = get_logger(__name__)


class CodeSummarizer:
    """Generates code summaries at different levels of abstraction.
    
    This class provides functionality for summarizing code at function,
    class, module, and system levels to aid in understanding and analysis.
    """
    
    def __init__(self) -> None:
        """Initialize the code summarizer."""
        self.config = get_config()
        self.openai_client = get_openai_client(async_mode=True)
        
        # Load code summarization prompts from config
        self.summarization_prompts = {
            "function": self.config.get(
                "summarization.prompts.function",
                "Analyze the following function and provide: 1) A concise summary of what it does, "
                "2) Estimated cyclomatic complexity (1-10), "
                "3) What it's responsible for, 4) Input types, 5) Output types, "
                "6) Any security considerations.\n\nCode:\n{code}"
            ),
            "class": self.config.get(
                "summarization.prompts.class",
                "Analyze the following class and provide: 1) A concise summary of its purpose, "
                "2) Estimated complexity (1-10), "
                "3) Its key responsibilities, 4) Important methods, "
                "5) Any security considerations.\n\nCode:\n{code}"
            ),
            "module": self.config.get(
                "summarization.prompts.module",
                "Analyze the following module and provide: 1) A concise summary of its purpose, "
                "2) Estimated complexity (1-10), "
                "3) Key components and their responsibilities, "
                "4) Any security considerations.\n\nCode:\n{code}"
            ),
            "system": self.config.get(
                "summarization.prompts.system",
                "Analyze the following system components and provide: 1) A concise system summary, "
                "2) Overall system complexity (1-10), "
                "3) Key components and their responsibilities, "
                "4) Any security considerations.\n\nComponents:\n{components}"
            )
        }
        
        # Set default model
        self.default_model = self.config.get("summarization.default_model", "o1")
        
        logger.info("CodeSummarizer initialized with LLM capabilities")
    
    async def _get_llm_summary(self, code: str, level: str, context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Get summary from LLM for the provided code.
        
        Args:
            code: Code to summarize
            level: Level of summarization (function, class, module, system)
            context: Optional additional context
            
        Returns:
            Dictionary with summary information
        """
        if not context:
            context = {}
            
        model = context.get("model", self.default_model)
        language = context.get("language", "python")
        
        # Get the appropriate prompt template
        prompt_template = self.summarization_prompts.get(level, self.summarization_prompts["function"])
        
        # Format the prompt
        if level == "system":
            # For system level, code is a dictionary of components
            components_str = "\n\n".join([f"File: {file_path}\n```{language}\n{code_content}\n```" 
                                        for file_path, code_content in code.items()])
            prompt = prompt_template.format(components=components_str)
        else:
            prompt = prompt_template.format(code=code)
            
        # Add language information to the prompt
        prompt = f"Programming language: {language}\n\n{prompt}"
        
        try:
            # Get completion from OpenAI
            response = await self.openai_client.create_completion(
                prompt=prompt,
                model=model,
                temperature=0.2,
                max_tokens=1000
            )
            
            # Extract the response text
            response_text = response.get("choices", [{}])[0].get("text", "").strip()
            
            # Parse the response into structured data
            summary_data = self._parse_llm_response(response_text, level)
            
            return summary_data
        except Exception as e:
            logger.error(f"Error getting LLM summary: {e}")
            return {
                "name": "error",
                "summary": f"Error: {str(e)}",
                "complexity": 1,
                "responsible_for": [],
                "security_considerations": []
            }
    
    def _parse_llm_response(self, response: str, level: str) -> Dict[str, Any]:
        """Parse the LLM response into structured summary data.
        
        Args:
            response: Raw LLM response text
            level: Level of summarization
            
        Returns:
            Dictionary with structured summary data
        """
        # Default values
        summary_data = {
            "name": f"unknown_{level}",
            "summary": "No summary provided",
            "complexity": 1,
            "responsible_for": [],
            "input_types": [],
            "output_types": [],
            "security_considerations": []
        }
        
        # Try to extract a name
        name_match = re.search(r"name:?\s*(\w+)", response, re.IGNORECASE)
        if name_match:
            summary_data["name"] = name_match.group(1)
            
        # Extract summary (assume first paragraph or sentence is the summary)
        summary_match = re.search(r"(?:summary|purpose):?\s*(.*?)(?:\n\n|\.\s)", response, re.IGNORECASE | re.DOTALL)
        if summary_match:
            summary_data["summary"] = summary_match.group(1).strip()
        else:
            # Just use the first paragraph if we can't find an explicit summary
            first_para = response.split("\n\n")[0]
            if first_para:
                summary_data["summary"] = first_para.strip()
                
        # Extract complexity
        complexity_match = re.search(r"complexity:?\s*(\d+)", response, re.IGNORECASE)
        if complexity_match:
            try:
                summary_data["complexity"] = int(complexity_match.group(1))
            except ValueError:
                pass
                
        # Extract responsibilities
        resp_match = re.search(r"responsib(?:le|ilit(?:y|ies)):?\s*(.*?)(?:\n\n|\n\d\.|\n#)", response, re.IGNORECASE | re.DOTALL)
        if resp_match:
            responsibilities = resp_match.group(1).strip()
            # Split by bullets, commas, etc.
            items = re.split(r'\n-|\n\*|,\s*|\.\s+(?=[A-Z])', responsibilities)
            summary_data["responsible_for"] = [item.strip() for item in items if item.strip()]
            
        # Extract input types for functions
        if level == "function":
            input_match = re.search(r"input(?:\s+types?)?:?\s*(.*?)(?:\n\n|\n\d\.|\n#)", response, re.IGNORECASE | re.DOTALL)
            if input_match:
                inputs = input_match.group(1).strip()
                items = re.split(r'\n-|\n\*|,\s*', inputs)
                summary_data["input_types"] = [item.strip() for item in items if item.strip()]
                
            # Extract output types for functions
            output_match = re.search(r"output(?:\s+types?)?:?\s*(.*?)(?:\n\n|\n\d\.|\n#)", response, re.IGNORECASE | re.DOTALL)
            if output_match:
                outputs = output_match.group(1).strip()
                items = re.split(r'\n-|\n\*|,\s*', outputs)
                summary_data["output_types"] = [item.strip() for item in items if item.strip()]
                
        # Extract security considerations
        security_match = re.search(r"security(?:\s+considerations?)?:?\s*(.*?)(?:\n\n|\n\d\.|\n#|$)", response, re.IGNORECASE | re.DOTALL)
        if security_match:
            security = security_match.group(1).strip()
            items = re.split(r'\n-|\n\*|,\s*|\.\s+(?=[A-Z])', security)
            summary_data["security_considerations"] = [item.strip() for item in items if item.strip()]
            
        return summary_data
            
    def _extract_function_info(self, function_code: str) -> Dict[str, Any]:
        """Extract information from function code using static analysis.
        
        Args:
            function_code: Function code to analyze
            
        Returns:
            Dictionary with function information
        """
        info = {
            "name": "unknown_function",
            "params": [],
            "return_type": None,
            "docstring": None
        }
        
        try:
            # Parse the code with ast
            tree = ast.parse(function_code)
            
            for node in ast.walk(tree):
                if isinstance(node, ast.FunctionDef):
                    # Extract function name
                    info["name"] = node.name
                    
                    # Extract parameters
                    for arg in node.args.args:
                        param = {"name": arg.arg}
                        if arg.annotation:
                            param["type"] = ast.unparse(arg.annotation)
                        info["params"].append(param)
                    
                    # Extract return type
                    if node.returns:
                        info["return_type"] = ast.unparse(node.returns)
                    
                    # Extract docstring
                    if (ast.get_docstring(node)):
                        info["docstring"] = ast.get_docstring(node)
                    
                    break  # Only look at the first function
        except Exception as e:
            logger.error(f"Error extracting function info: {e}")
            
        return info
    
    @LogEvent("summarize_function")
    async def summarize_function(self, function_code: str, context: Optional[Dict[str, Any]] = None) -> CodeSummary:
        """Summarize a function.
        
        Args:
            function_code: Function code to summarize
            context: Optional additional context
            
        Returns:
            CodeSummary for the function
        """
        if not context:
            context = {}
            
        # First, try to extract basic information using static analysis
        func_info = self._extract_function_info(function_code)
        
        # Get summary from LLM
        summary_data = await self._get_llm_summary(function_code, "function", context)
        
        # Use extracted name if LLM didn't provide one
        if summary_data.get("name") == "unknown_function" and func_info["name"] != "unknown_function":
            summary_data["name"] = func_info["name"]
            
        # Construct the result
        return CodeSummary(
            name=summary_data.get("name", func_info["name"]),
            summary=summary_data.get("summary", "No summary available"),
            complexity=summary_data.get("complexity", 1),
            component_type="function",
            responsible_for=summary_data.get("responsible_for", []),
            input_types=summary_data.get("input_types", [p.get("type", p.get("name", "unknown")) for p in func_info["params"]]),
            output_types=summary_data.get("output_types", [func_info["return_type"]] if func_info["return_type"] else []),
            security_considerations=summary_data.get("security_considerations", [])
        )
    
    def _extract_class_info(self, class_code: str) -> Dict[str, Any]:
        """Extract information from class code using static analysis.
        
        Args:
            class_code: Class code to analyze
            
        Returns:
            Dictionary with class information
        """
        info = {
            "name": "unknown_class",
            "methods": [],
            "attributes": [],
            "docstring": None
        }
        
        try:
            # Parse the code with ast
            tree = ast.parse(class_code)
            
            for node in ast.walk(tree):
                if isinstance(node, ast.ClassDef):
                    # Extract class name
                    info["name"] = node.name
                    
                    # Extract docstring
                    if (ast.get_docstring(node)):
                        info["docstring"] = ast.get_docstring(node)
                    
                    # Extract methods and attributes
                    for item in node.body:
                        if isinstance(item, ast.FunctionDef):
                            method = {"name": item.name}
                            if ast.get_docstring(item):
                                method["docstring"] = ast.get_docstring(item)
                            info["methods"].append(method)
                        elif isinstance(item, ast.Assign):
                            for target in item.targets:
                                if isinstance(target, ast.Name):
                                    info["attributes"].append({"name": target.id})
                    
                    break  # Only look at the first class
        except Exception as e:
            logger.error(f"Error extracting class info: {e}")
            
        return info
    
    @LogEvent("summarize_class")
    async def summarize_class(self, class_code: str, context: Optional[Dict[str, Any]] = None) -> CodeSummary:
        """Summarize a class.
        
        Args:
            class_code: Class code to summarize
            context: Optional additional context
            
        Returns:
            CodeSummary for the class
        """
        if not context:
            context = {}
            
        # First, try to extract basic information using static analysis
        class_info = self._extract_class_info(class_code)
        
        # Get summary from LLM
        summary_data = await self._get_llm_summary(class_code, "class", context)
        
        # Use extracted name if LLM didn't provide one
        if summary_data.get("name") == "unknown_class" and class_info["name"] != "unknown_class":
            summary_data["name"] = class_info["name"]
            
        # Construct the result
        return CodeSummary(
            name=summary_data.get("name", class_info["name"]),
            summary=summary_data.get("summary", "No summary available"),
            complexity=summary_data.get("complexity", 1),
            component_type="class",
            responsible_for=summary_data.get("responsible_for", []),
            input_types=[],  # Classes don't have direct input types
            output_types=[],  # Classes don't have direct output types
            security_considerations=summary_data.get("security_considerations", [])
        )
    
    def _extract_module_info(self, module_code: str) -> Dict[str, Any]:
        """Extract information from module code using static analysis.
        
        Args:
            module_code: Module code to analyze
            
        Returns:
            Dictionary with module information
        """
        info = {
            "name": "unknown_module",
            "classes": [],
            "functions": [],
            "imports": [],
            "docstring": None
        }
        
        try:
            # Parse the code with ast
            tree = ast.parse(module_code)
            
            # Extract module docstring
            if (ast.get_docstring(tree)):
                info["docstring"] = ast.get_docstring(tree)
            
            # Extract module elements
            for node in tree.body:
                if isinstance(node, ast.ClassDef):
                    info["classes"].append({"name": node.name})
                elif isinstance(node, ast.FunctionDef):
                    info["functions"].append({"name": node.name})
                elif isinstance(node, (ast.Import, ast.ImportFrom)):
                    if isinstance(node, ast.Import):
                        for name in node.names:
                            info["imports"].append({"module": name.name})
                    else:  # ImportFrom
                        for name in node.names:
                            info["imports"].append({"module": f"{node.module}.{name.name}"})
                            
            # Try to infer module name from imports or file structure patterns
            if info["imports"]:
                # Look for patterns that might indicate the module name
                for imp in info["imports"]:
                    if "." in imp["module"]:
                        parts = imp["module"].split(".")
                        if len(parts) > 1:
                            # Guess based on common import patterns
                            potential_name = parts[-2]  # Often the parent module name
                            if potential_name and potential_name != "unknown_module":
                                info["name"] = potential_name
                                break
        except Exception as e:
            logger.error(f"Error extracting module info: {e}")
            
        return info
    
    @LogEvent("summarize_module")
    async def summarize_module(self, module_code: str, context: Optional[Dict[str, Any]] = None) -> CodeSummary:
        """Summarize a module.
        
        Args:
            module_code: Module code to summarize
            context: Optional additional context
            
        Returns:
            CodeSummary for the module
        """
        if not context:
            context = {}
            
        # First, try to extract basic information using static analysis
        module_info = self._extract_module_info(module_code)
        
        # Get summary from LLM
        summary_data = await self._get_llm_summary(module_code, "module", context)
        
        # Use extracted name if LLM didn't provide one
        if summary_data.get("name") == "unknown_module" and module_info["name"] != "unknown_module":
            summary_data["name"] = module_info["name"]
            
        # Infer responsibilities from module components if not provided by LLM
        if not summary_data.get("responsible_for"):
            responsible_for = []
            if module_info["classes"]:
                responsible_for.append(f"Defining {len(module_info['classes'])} classes")
            if module_info["functions"]:
                responsible_for.append(f"Providing {len(module_info['functions'])} functions")
            summary_data["responsible_for"] = responsible_for
            
        # Construct the result
        return CodeSummary(
            name=summary_data.get("name", module_info["name"]),
            summary=summary_data.get("summary", module_info.get("docstring", "No summary available")),
            complexity=summary_data.get("complexity", 1),
            component_type="module",
            responsible_for=summary_data.get("responsible_for", []),
            input_types=[],  # Modules don't have direct input types
            output_types=[],  # Modules don't have direct output types
            security_considerations=summary_data.get("security_considerations", [])
        )
    
    def _extract_system_info(self, system_code: Dict[str, str]) -> Dict[str, Any]:
        """Extract information from a collection of modules using static analysis.
        
        Args:
            system_code: Dictionary mapping file paths to code
            
        Returns:
            Dictionary with system information
        """
        info = {
            "name": "unknown_system",
            "modules": [],
            "file_count": len(system_code),
            "class_count": 0,
            "function_count": 0,
            "language_counts": {}
        }
        
        try:
            # Extract name from directory structure
            if system_code:
                # Try to extract project name from paths
                paths = list(system_code.keys())
                common_prefix = os.path.commonprefix(paths)
                if common_prefix:
                    parts = common_prefix.strip('/').split('/')
                    if parts:
                        # Use the last part of the common prefix as the system name
                        # or the second-to-last if the last is a generic name like "src"
                        if parts[-1] in ["src", "lib", "app", "source"]:
                            info["name"] = parts[-2] if len(parts) > 1 else parts[-1]
                        else:
                            info["name"] = parts[-1]
            
            # Process each file
            for file_path, code in system_code.items():
                file_info = {"path": file_path}
                
                # Determine language from file extension
                ext = os.path.splitext(file_path)[1].lower()
                language = "unknown"
                if ext in [".py"]:
                    language = "python"
                elif ext in [".js", ".jsx"]:
                    language = "javascript"
                elif ext in [".ts", ".tsx"]:
                    language = "typescript"
                elif ext in [".java"]:
                    language = "java"
                elif ext in [".cs"]:
                    language = "csharp"
                elif ext in [".c", ".cpp", ".cc", ".h", ".hpp"]:
                    language = "cpp"
                    
                file_info["language"] = language
                
                # Count languages
                info["language_counts"][language] = info["language_counts"].get(language, 0) + 1
                
                # Try to parse and count classes and functions
                try:
                    if language == "python":
                        tree = ast.parse(code)
                        class_count = sum(1 for node in ast.walk(tree) if isinstance(node, ast.ClassDef))
                        function_count = sum(1 for node in ast.walk(tree) if isinstance(node, ast.FunctionDef))
                        
                        info["class_count"] += class_count
                        info["function_count"] += function_count
                        
                        file_info["class_count"] = class_count
                        file_info["function_count"] = function_count
                except Exception:
                    # Ignore parsing errors for complex analysis
                    pass
                    
                info["modules"].append(file_info)
        except Exception as e:
            logger.error(f"Error extracting system info: {e}")
            
        return info
    
    @LogEvent("summarize_system")
    async def summarize_system(self, system_code: Dict[str, str], context: Optional[Dict[str, Any]] = None) -> CodeSummary:
        """Summarize a system (collection of modules).
        
        Args:
            system_code: Dictionary mapping file paths to code
            context: Optional additional context
            
        Returns:
            CodeSummary for the system
        """
        if not context:
            context = {}
            
        # First, try to extract basic information using static analysis
        system_info = self._extract_system_info(system_code)
        
        # Get summary from LLM
        summary_data = await self._get_llm_summary(system_code, "system", context)
        
        # Use extracted name if LLM didn't provide one
        if summary_data.get("name") == "unknown_system" and system_info["name"] != "unknown_system":
            summary_data["name"] = system_info["name"]
            
        # Infer responsibilities from system components if not provided by LLM
        if not summary_data.get("responsible_for"):
            responsible_for = []
            if system_info["file_count"] > 0:
                responsible_for.append(f"Managing {system_info['file_count']} files")
            if system_info["class_count"] > 0:
                responsible_for.append(f"Implementing {system_info['class_count']} classes")
            if system_info["function_count"] > 0:
                responsible_for.append(f"Providing {system_info['function_count']} functions")
                
            # Add language information
            language_info = []
            for lang, count in system_info["language_counts"].items():
                if lang != "unknown" and count > 0:
                    language_info.append(f"{lang} ({count} files)")
            if language_info:
                responsible_for.append(f"Written in {', '.join(language_info)}")
                
            summary_data["responsible_for"] = responsible_for
            
        # Estimate complexity based on file count and structure
        if not summary_data.get("complexity"):
            # Simple heuristic based on file count and class/function counts
            size_factor = min(10, system_info["file_count"] / 10)
            complexity_factor = min(10, (system_info["class_count"] + system_info["function_count"]) / 50)
            estimated_complexity = round((size_factor + complexity_factor) / 2)
            summary_data["complexity"] = max(1, min(10, estimated_complexity))
            
        # Construct the result
        return CodeSummary(
            name=summary_data.get("name", system_info["name"]),
            summary=summary_data.get("summary", f"System with {system_info['file_count']} files"),
            complexity=summary_data.get("complexity", 1),
            component_type="system",
            responsible_for=summary_data.get("responsible_for", []),
            input_types=[],  # Systems don't have direct input types
            output_types=[],  # Systems don't have direct output types
            security_considerations=summary_data.get("security_considerations", [])
        )
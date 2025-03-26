"""Tool integration framework for code analysis.

This module provides a framework for integrating external security tools
with the Skwaq vulnerability assessment system.
"""

import os
import re
import json
import tempfile
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Any, Optional, Union, Set, Callable, Tuple

from ..utils.logging import get_logger, LogEvent
from ..utils.config import get_config
from ..shared.finding import Finding

logger = get_logger(__name__)


@dataclass
class ExternalTool:
    """Configuration for an external security tool.
    
    Attributes:
        name: Name of the tool
        command: Command to run the tool
        result_parser: Function to parse tool output into findings
        language: Language the tool supports (None for all languages)
        version_command: Command to check tool version
        installation_url: URL with installation instructions
        description: Description of the tool
        args: Additional arguments to pass to the tool
    """
    
    name: str
    command: str
    result_parser: Callable[[str], List[Dict[str, Any]]]
    language: Optional[str] = None
    version_command: Optional[str] = None
    installation_url: Optional[str] = None
    description: Optional[str] = None
    args: Dict[str, str] = field(default_factory=dict)


class ToolIntegrationFramework:
    """Framework for integrating external security tools.
    
    This class provides functionality for registering, managing, and executing
    external security tools to enhance vulnerability detection.
    """
    
    def __init__(self):
        """Initialize the tool integration framework."""
        self.config = get_config()
        self.registered_tools: Dict[str, ExternalTool] = {}
        
        # Initialize built-in tool parsers
        self.tool_parsers = {
            "bandit": self._parse_bandit_output,
            "eslint": self._parse_eslint_output,
            "semgrep": self._parse_semgrep_output,
            "flawfinder": self._parse_flawfinder_output,
            "pmd": self._parse_pmd_output,
            "spotbugs": self._parse_spotbugs_output,
            "gosec": self._parse_gosec_output,
        }
        
        # Register built-in tools
        self._register_built_in_tools()
        
        # Register tools from config
        self._register_config_tools()
        
        logger.info(f"Tool integration framework initialized with {len(self.registered_tools)} tools")
    
    def _register_built_in_tools(self) -> None:
        """Register built-in security tools."""
        # Bandit for Python security scanning
        self.register_tool(ExternalTool(
            name="bandit",
            command="bandit",
            result_parser=self.tool_parsers["bandit"],
            language="python",
            version_command="bandit --version",
            installation_url="https://github.com/PyCQA/bandit#installation",
            description="Bandit is a tool designed to find common security issues in Python code",
            args={
                "format": "--format json",
                "recursive": "-r",
                "default": "-ll"
            }
        ))
        
        # ESLint for JavaScript security scanning
        self.register_tool(ExternalTool(
            name="eslint",
            command="eslint",
            result_parser=self.tool_parsers["eslint"],
            language="javascript",
            version_command="eslint --version",
            installation_url="https://eslint.org/docs/user-guide/getting-started",
            description="ESLint security plugin for JavaScript/TypeScript",
            args={
                "format": "--format json",
                "config": "--no-eslintrc --config .eslintrc-security.json"
            }
        ))
        
        # Semgrep for multi-language scanning
        self.register_tool(ExternalTool(
            name="semgrep",
            command="semgrep",
            result_parser=self.tool_parsers["semgrep"],
            version_command="semgrep --version",
            installation_url="https://semgrep.dev/docs/getting-started/",
            description="Semgrep is a lightweight static analysis tool for many languages",
            args={
                "config": "--config p/security-audit",
                "json": "--json",
                "quiet": "--quiet"
            }
        ))
        
        # Flawfinder for C/C++ security scanning
        self.register_tool(ExternalTool(
            name="flawfinder",
            command="flawfinder",
            result_parser=self.tool_parsers["flawfinder"],
            language="cpp",
            version_command="flawfinder --version",
            installation_url="https://github.com/david-a-wheeler/flawfinder",
            description="Flawfinder is a program that examines C/C++ source code and reports potential security flaws",
            args={
                "json": "--json",
                "context": "--context",
                "minlevel": "--minlevel=3"
            }
        ))
    
    def _register_config_tools(self) -> None:
        """Register tools from configuration."""
        config_tools = self.config.get("tools", {})
        
        for tool_name, tool_config in config_tools.items():
            if not isinstance(tool_config, dict):
                logger.warning(f"Invalid tool configuration for {tool_name}")
                continue
                
            # Skip if tool is already registered
            if tool_name in self.registered_tools:
                logger.debug(f"Tool {tool_name} already registered, skipping config registration")
                continue
                
            # Check for required fields
            if "command" not in tool_config:
                logger.warning(f"Missing required 'command' field for tool {tool_name}")
                continue
                
            # Get parser function
            parser_name = tool_config.get("parser", tool_name)
            parser_func = self.tool_parsers.get(parser_name)
            
            if not parser_func:
                logger.warning(
                    f"No parser function found for tool {tool_name} (parser: {parser_name}). "
                    f"Tool will be registered but results may not be parsed correctly."
                )
                parser_func = self._parse_generic_output
                
            # Create and register tool
            tool = ExternalTool(
                name=tool_name,
                command=tool_config["command"],
                result_parser=parser_func,
                language=tool_config.get("language"),
                version_command=tool_config.get("version_command"),
                installation_url=tool_config.get("installation_url"),
                description=tool_config.get("description"),
                args=tool_config.get("args", {})
            )
            
            self.register_tool(tool)
    
    @LogEvent("register_tool")
    def register_tool(self, tool: ExternalTool) -> bool:
        """Register an external security tool.
        
        Args:
            tool: ExternalTool configuration
            
        Returns:
            True if registration successful, False otherwise
        """
        # Check if tool already registered
        if tool.name in self.registered_tools:
            logger.warning(f"Tool {tool.name} already registered")
            return False
            
        # Verify tool is available
        if not self._check_tool_available(tool):
            logger.warning(f"Tool {tool.name} is not available and will not be used")
            return False
            
        # Register the tool
        self.registered_tools[tool.name] = tool
        logger.info(f"Registered tool: {tool.name}")
        
        return True
    
    def _check_tool_available(self, tool: ExternalTool) -> bool:
        """Check if a tool is available on the system.
        
        Args:
            tool: ExternalTool to check
            
        Returns:
            True if the tool is available, False otherwise
        """
        # Get the base command (without arguments)
        command_parts = tool.command.split()
        base_command = command_parts[0]
        
        # First check if the command exists in PATH
        if self._command_exists(base_command):
            logger.debug(f"Tool {tool.name} found in PATH")
            return True
            
        # If version command specified, try that
        if tool.version_command:
            try:
                # Run version command
                result = subprocess.run(
                    tool.version_command,
                    shell=True,
                    capture_output=True,
                    text=True,
                    check=False
                )
                
                if result.returncode == 0:
                    logger.debug(f"Tool {tool.name} version command succeeded: {result.stdout.strip()}")
                    return True
            except subprocess.SubprocessError:
                pass
                
        logger.warning(
            f"Tool {tool.name} not found. "
            f"Install instructions: {tool.installation_url}" if tool.installation_url else ""
        )
        return False
    
    def _command_exists(self, command: str) -> bool:
        """Check if a command exists in PATH.
        
        Args:
            command: Command to check
            
        Returns:
            True if command exists, False otherwise
        """
        if os.name == "nt":  # Windows
            # Check if command exists with 'where'
            try:
                result = subprocess.run(
                    ["where", command],
                    capture_output=True,
                    text=True,
                    check=False
                )
                return result.returncode == 0
            except subprocess.SubprocessError:
                return False
        else:  # Unix-like
            # Check if command exists with 'which'
            try:
                result = subprocess.run(
                    ["which", command],
                    capture_output=True,
                    text=True,
                    check=False
                )
                return result.returncode == 0
            except subprocess.SubprocessError:
                return False
    
    def get_registered_tools(self) -> List[str]:
        """Get list of registered tool names.
        
        Returns:
            List of registered tool names
        """
        return list(self.registered_tools.keys())
    
    def get_tools_for_language(self, language: str) -> List[ExternalTool]:
        """Get tools that support a specific language.
        
        Args:
            language: Programming language
            
        Returns:
            List of ExternalTool objects
        """
        language = language.lower()
        
        # Map common language names to normalized ones
        language_map = {
            "py": "python",
            "js": "javascript",
            "ts": "typescript",
            "c#": "csharp",
            "c++": "cpp",
            "go": "go",
            "rb": "ruby",
        }
        
        normalized_language = language_map.get(language, language)
        
        # Return tools that support the language or are language-agnostic
        return [
            tool for tool in self.registered_tools.values()
            if tool.language is None or tool.language.lower() == normalized_language
        ]
    
    @LogEvent("execute_tool")
    def execute_tool(self, tool_name: str, targets: List[str], extra_args: Optional[Dict[str, str]] = None) -> List[Dict[str, Any]]:
        """Execute a registered tool against specified targets.
        
        Args:
            tool_name: Name of the registered tool
            targets: List of files or directories to analyze
            extra_args: Additional command line arguments
            
        Returns:
            List of results as dictionaries
        """
        if tool_name not in self.registered_tools:
            logger.warning(f"Tool {tool_name} not registered")
            return []
            
        tool = self.registered_tools[tool_name]
        
        # Build command with arguments
        cmd_parts = [tool.command]
        
        # Add standard arguments from tool definition
        for arg_name, arg_value in tool.args.items():
            cmd_parts.append(arg_value)
            
        # Add extra arguments if provided
        if extra_args:
            for arg_name, arg_value in extra_args.items():
                cmd_parts.append(arg_value)
                
        # Add target files or directories
        cmd_parts.extend(targets)
        
        command = " ".join(cmd_parts)
        logger.info(f"Executing tool {tool_name}: {command}")
        
        try:
            # Create temporary file for output
            with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as temp_file:
                output_file = temp_file.name
                
            # Execute command
            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                check=False
            )
            
            # Check for successful execution
            if result.returncode != 0 and result.returncode != 1:  # Some tools use return code 1 for findings
                logger.error(f"Tool {tool_name} execution failed: {result.stderr}")
                return []
                
            # Parse results
            if result.stdout:
                findings = tool.result_parser(result.stdout)
            else:
                findings = []
                
            logger.info(f"Tool {tool_name} found {len(findings)} issues")
            return findings
        except subprocess.SubprocessError as e:
            logger.error(f"Error executing tool {tool_name}: {e}")
            return []
        except Exception as e:
            logger.error(f"Unexpected error executing tool {tool_name}: {e}")
            return []
    
    @LogEvent("execute_all_tools")
    def execute_all_tools(self, language: str, targets: List[str]) -> List[Dict[str, Any]]:
        """Execute all applicable tools for a language.
        
        Args:
            language: Programming language
            targets: List of files or directories to analyze
            
        Returns:
            Combined list of results from all tools
        """
        # Get tools for the language
        tools = self.get_tools_for_language(language)
        
        if not tools:
            logger.info(f"No tools available for language {language}")
            return []
            
        logger.info(f"Executing {len(tools)} tools for language {language}")
        
        all_results = []
        
        # Execute each tool
        for tool in tools:
            try:
                results = self.execute_tool(tool.name, targets)
                
                # Add tool name to results
                for result in results:
                    result["tool"] = tool.name
                    
                all_results.extend(results)
            except Exception as e:
                logger.error(f"Error executing tool {tool.name}: {e}")
                
        logger.info(f"All tools found {len(all_results)} issues total")
        return all_results
    
    @LogEvent("convert_to_findings")
    def convert_to_findings(
        self, 
        tool_results: List[Dict[str, Any]], 
        file_id_map: Dict[str, int]
    ) -> List[Finding]:
        """Convert tool results to Skwaq findings.
        
        Args:
            tool_results: Tool execution results
            file_id_map: Mapping from file paths to database file IDs
            
        Returns:
            List of Finding objects
        """
        findings: List[Finding] = []
        
        for result in tool_results:
            try:
                # Extract common information
                tool = result.get("tool", "unknown_tool")
                message = result.get("message", "")
                severity = result.get("severity", "Medium")
                
                # Map tool severity to Skwaq severity
                severity_map = {
                    "critical": "Critical",
                    "high": "High",
                    "medium": "Medium",
                    "low": "Low",
                    "info": "Info",
                    # Numeric mappings (some tools use numbers)
                    "4": "Critical",
                    "3": "High",
                    "2": "Medium",
                    "1": "Low",
                    "0": "Info",
                }
                
                severity = severity_map.get(str(severity).lower(), severity)
                
                # Get confidence if available
                confidence = result.get("confidence", 0.7)
                if isinstance(confidence, str):
                    confidence_map = {
                        "high": 0.9,
                        "medium": 0.7,
                        "low": 0.5,
                        # Numeric mappings
                        "3": 0.9,
                        "2": 0.7,
                        "1": 0.5,
                        "0": 0.3,
                    }
                    confidence = confidence_map.get(confidence.lower(), 0.7)
                
                # Extract file information
                file_path = result.get("file_path", "")
                
                # Try to find file ID
                file_id = file_id_map.get(file_path)
                if not file_id:
                    # Try with absolute path
                    abs_path = os.path.abspath(file_path)
                    file_id = file_id_map.get(abs_path)
                    
                    if not file_id:
                        logger.warning(f"No file ID found for {file_path}")
                        continue
                
                # Extract line information
                line_number = result.get("line", result.get("line_number", 0))
                
                # Extract vulnerability type
                vuln_type = result.get("type", result.get("rule_id", "Unknown"))
                
                # Create a finding
                finding = Finding(
                    type="external_tool",
                    vulnerability_type=vuln_type,
                    description=message,
                    file_id=file_id,
                    line_number=line_number,
                    severity=severity,
                    confidence=confidence,
                    tool_name=tool,
                    suggestion=result.get("suggestion", "Review the issue reported by the external tool"),
                    metadata={
                        "tool": tool,
                        "raw_result": result
                    }
                )
                
                findings.append(finding)
            except Exception as e:
                logger.error(f"Error converting tool result to finding: {e}")
                
        logger.info(f"Converted {len(findings)} tool results to findings")
        return findings
    
    #
    # Tool-specific result parsers
    #
    
    def _parse_bandit_output(self, output: str) -> List[Dict[str, Any]]:
        """Parse output from Bandit tool.
        
        Args:
            output: Tool output as string
            
        Returns:
            List of parsed results
        """
        try:
            data = json.loads(output)
            results = []
            
            for result in data.get("results", []):
                parsed_result = {
                    "file_path": result.get("filename", ""),
                    "line": result.get("line_number", 0),
                    "message": result.get("issue_text", ""),
                    "severity": result.get("issue_severity", ""),
                    "confidence": result.get("issue_confidence", ""),
                    "type": result.get("test_id", ""),
                    "code": result.get("code", ""),
                }
                
                results.append(parsed_result)
                
            return results
        except Exception as e:
            logger.error(f"Error parsing Bandit output: {e}")
            return []
    
    def _parse_eslint_output(self, output: str) -> List[Dict[str, Any]]:
        """Parse output from ESLint tool.
        
        Args:
            output: Tool output as string
            
        Returns:
            List of parsed results
        """
        try:
            data = json.loads(output)
            results = []
            
            for file_result in data:
                file_path = file_result.get("filePath", "")
                
                for message in file_result.get("messages", []):
                    severity_map = {
                        2: "High",
                        1: "Medium",
                        0: "Low"
                    }
                    
                    severity = severity_map.get(message.get("severity", 1), "Medium")
                    
                    parsed_result = {
                        "file_path": file_path,
                        "line": message.get("line", 0),
                        "message": message.get("message", ""),
                        "severity": severity,
                        "rule_id": message.get("ruleId", ""),
                    }
                    
                    results.append(parsed_result)
                    
            return results
        except Exception as e:
            logger.error(f"Error parsing ESLint output: {e}")
            return []
    
    def _parse_semgrep_output(self, output: str) -> List[Dict[str, Any]]:
        """Parse output from Semgrep tool.
        
        Args:
            output: Tool output as string
            
        Returns:
            List of parsed results
        """
        try:
            data = json.loads(output)
            results = []
            
            for result in data.get("results", []):
                path = result.get("path", "")
                check_id = result.get("check_id", "")
                
                parsed_result = {
                    "file_path": path,
                    "line": result.get("start", {}).get("line", 0),
                    "message": result.get("extra", {}).get("message", ""),
                    "severity": result.get("extra", {}).get("severity", "Medium"),
                    "type": check_id,
                    "suggestion": result.get("extra", {}).get("fix", result.get("extra", {}).get("metadata", {}).get("fix", "")),
                }
                
                results.append(parsed_result)
                
            return results
        except Exception as e:
            logger.error(f"Error parsing Semgrep output: {e}")
            return []
    
    def _parse_flawfinder_output(self, output: str) -> List[Dict[str, Any]]:
        """Parse output from Flawfinder tool.
        
        Args:
            output: Tool output as string
            
        Returns:
            List of parsed results
        """
        try:
            data = json.loads(output)
            results = []
            
            for item in data.get("vulnerabilities", []):
                # Map risk level to severity
                risk = item.get("severity", 0)
                if risk >= 4:
                    severity = "High"
                elif risk >= 2:
                    severity = "Medium"
                else:
                    severity = "Low"
                    
                parsed_result = {
                    "file_path": item.get("filename", ""),
                    "line": item.get("line", 0),
                    "message": item.get("description", ""),
                    "severity": severity,
                    "type": item.get("category", ""),
                    "suggestion": item.get("recommendation", ""),
                }
                
                results.append(parsed_result)
                
            return results
        except Exception as e:
            logger.error(f"Error parsing Flawfinder output: {e}")
            return []
    
    def _parse_pmd_output(self, output: str) -> List[Dict[str, Any]]:
        """Parse output from PMD tool.
        
        Args:
            output: Tool output as string
            
        Returns:
            List of parsed results
        """
        try:
            data = json.loads(output)
            results = []
            
            for file_result in data.get("files", []):
                file_path = file_result.get("filename", "")
                
                for violation in file_result.get("violations", []):
                    # Map PMD priority to severity
                    priority = violation.get("priority", 3)
                    if priority <= 1:
                        severity = "High"
                    elif priority == 2:
                        severity = "Medium"
                    else:
                        severity = "Low"
                        
                    parsed_result = {
                        "file_path": file_path,
                        "line": violation.get("beginline", 0),
                        "message": violation.get("description", ""),
                        "severity": severity,
                        "type": violation.get("rule", ""),
                        "rule_set": violation.get("ruleset", ""),
                    }
                    
                    results.append(parsed_result)
                    
            return results
        except Exception as e:
            logger.error(f"Error parsing PMD output: {e}")
            return []
    
    def _parse_spotbugs_output(self, output: str) -> List[Dict[str, Any]]:
        """Parse output from SpotBugs tool.
        
        Args:
            output: Tool output as string
            
        Returns:
            List of parsed results
        """
        try:
            data = json.loads(output)
            results = []
            
            for bug in data.get("BugInstance", []):
                # Map SpotBugs priority to severity
                priority = bug.get("priority", 3)
                if priority == 1:
                    severity = "High"
                elif priority == 2:
                    severity = "Medium"
                else:
                    severity = "Low"
                    
                source_line = bug.get("SourceLine", {})
                
                parsed_result = {
                    "file_path": source_line.get("sourcepath", ""),
                    "line": source_line.get("start", 0),
                    "message": bug.get("ShortMessage", ""),
                    "severity": severity,
                    "type": bug.get("type", ""),
                    "category": bug.get("category", ""),
                }
                
                results.append(parsed_result)
                
            return results
        except Exception as e:
            logger.error(f"Error parsing SpotBugs output: {e}")
            return []
    
    def _parse_gosec_output(self, output: str) -> List[Dict[str, Any]]:
        """Parse output from Gosec tool.
        
        Args:
            output: Tool output as string
            
        Returns:
            List of parsed results
        """
        try:
            data = json.loads(output)
            results = []
            
            for issue in data.get("Issues", []):
                parsed_result = {
                    "file_path": issue.get("file", ""),
                    "line": issue.get("line", 0),
                    "message": issue.get("details", ""),
                    "severity": issue.get("severity", "Medium"),
                    "confidence": issue.get("confidence", "Medium"),
                    "type": issue.get("rule_id", ""),
                    "code": issue.get("code", ""),
                }
                
                results.append(parsed_result)
                
            return results
        except Exception as e:
            logger.error(f"Error parsing Gosec output: {e}")
            return []
    
    def _parse_generic_output(self, output: str) -> List[Dict[str, Any]]:
        """Generic parser for unrecognized tool output.
        
        Args:
            output: Tool output as string
            
        Returns:
            List of parsed results
        """
        results = []
        
        # Try to parse as JSON
        try:
            data = json.loads(output)
            
            # If it's a list, assume each item is a finding
            if isinstance(data, list):
                for item in data:
                    if isinstance(item, dict):
                        results.append(item)
            # If it's a dict, look for common result fields
            elif isinstance(data, dict):
                # Check for common result containers
                for key in ["results", "issues", "warnings", "violations", "findings"]:
                    if key in data and isinstance(data[key], list):
                        for item in data[key]:
                            if isinstance(item, dict):
                                results.append(item)
                                
                # If no results found and the dict isn't too large, treat it as a single finding
                if not results and len(data) < 20:
                    results.append(data)
        except json.JSONDecodeError:
            # If not JSON, try to parse as text
            # Look for common patterns like "file:line: message"
            file_line_pattern = re.compile(r'(\S+):(\d+)(?::(\d+))?: (.+)')
            
            for line in output.splitlines():
                match = file_line_pattern.match(line.strip())
                if match:
                    file_path, line_num, _, message = match.groups()
                    results.append({
                        "file_path": file_path,
                        "line": int(line_num),
                        "message": message.strip(),
                        "severity": "Medium",  # Default
                    })
        
        return results
"""Tool invocation workflow for vulnerability assessment.

This module implements functionality for invoking external security tools
and processing their results.
"""

from typing import Dict, List, Any, Optional, AsyncGenerator
import asyncio
import json
import subprocess
import tempfile
import os
from pathlib import Path

from autogen_core.agent import Agent
from autogen_core.event import BaseEvent, Event, EventHook

from .base import Workflow
from ..db.neo4j_connector import get_connector
from ..utils.logging import get_logger
from ..shared.finding import Finding, AnalysisResult

logger = get_logger(__name__)


class ToolInvocationEvent(BaseEvent):
    """Event for tool invocation."""

    def __init__(
        self,
        sender: str,
        tool_name: str,
        command: str,
        status: str,
        results: Optional[Dict[str, Any]] = None,
        error: Optional[str] = None,
        target: Optional[str] = None,
    ):
        super().__init__(
            sender=sender,
            target=target,
            tool_name=tool_name,
            command=command,
            status=status,
            results=results,
            error=error,
        )


class ToolInvocationWorkflow(Workflow):
    """Tool invocation workflow for vulnerability assessment.

    This workflow provides the ability to invoke external security tools,
    process their results, and integrate them with the vulnerability assessment
    system.
    """

    def __init__(
        self,
        repository_id: Optional[int] = None,
        repository_path: Optional[str] = None,
    ):
        """Initialize the tool invocation workflow.

        Args:
            repository_id: Optional ID of the repository to analyze
            repository_path: Optional path to the repository
        """
        super().__init__()
        self.repository_id = repository_id
        self.repository_path = repository_path
        self.investigation_id = None
        self.connector = get_connector()
        self.available_tools = self._discover_tools()
        
    async def setup(self) -> None:
        """Set up the tool invocation workflow."""
        # Create a new investigation if needed
        if self.repository_id and not self.investigation_id:
            result = self.connector.run_query(
                "MATCH (r:Repository) WHERE id(r) = $repo_id "
                "CREATE (i:Investigation {created: datetime(), status: 'In Progress', type: 'ToolInvocation'}) "
                "CREATE (r)-[:HAS_INVESTIGATION]->(i) "
                "RETURN id(i) as id",
                {"repo_id": self.repository_id},
            )
            if result:
                self.investigation_id = result[0]["id"]
                logger.info(f"Created new investigation with ID: {self.investigation_id}")
        
        # Get repository path if not provided
        if self.repository_id and not self.repository_path:
            result = self.connector.run_query(
                "MATCH (r:Repository) WHERE id(r) = $repo_id "
                "RETURN r.path as path",
                {"repo_id": self.repository_id},
            )
            if result and result[0]["path"]:
                self.repository_path = result[0]["path"]
                logger.info(f"Using repository path: {self.repository_path}")
        
        logger.info("Tool invocation workflow initialized")
    
    def _discover_tools(self) -> Dict[str, Dict[str, Any]]:
        """Discover available security tools.
        
        Returns:
            Dictionary of available tools and their metadata
        """
        # Define the tools we support
        tools = {
            "bandit": {
                "name": "Bandit",
                "description": "Security linter for Python code",
                "command": "bandit",
                "language": "python",
                "check_command": ["bandit", "--version"],
                "available": self._check_tool_exists("bandit"),
                "invoke_command": ["bandit", "-r", "{path}", "-f", "json", "-o", "{output}"],
                "result_parser": self._parse_bandit_results,
            },
            "semgrep": {
                "name": "Semgrep",
                "description": "Code analysis tool for finding bugs and code quality issues",
                "command": "semgrep",
                "language": "multiple",
                "check_command": ["semgrep", "--version"],
                "available": self._check_tool_exists("semgrep"),
                "invoke_command": ["semgrep", "--config=auto", "{path}", "--json", "-o", "{output}"],
                "result_parser": self._parse_semgrep_results,
            },
            "trufflehog": {
                "name": "TruffleHog",
                "description": "Searches for secrets in git repositories",
                "command": "trufflehog",
                "language": "multiple",
                "check_command": ["trufflehog", "--version"],
                "available": self._check_tool_exists("trufflehog"),
                "invoke_command": ["trufflehog", "filesystem", "{path}", "--json", "--output={output}"],
                "result_parser": self._parse_trufflehog_results,
            },
        }
        
        return tools
    
    def _check_tool_exists(self, command: str) -> bool:
        """Check if a tool is available on the system.
        
        Args:
            command: The command to check
            
        Returns:
            True if the tool exists, False otherwise
        """
        try:
            # Use 'which' on Unix-like systems, 'where' on Windows
            if os.name == 'nt':  # Windows
                subprocess.run(["where", command], check=True, capture_output=True)
            else:  # Unix-like
                subprocess.run(["which", command], check=True, capture_output=True)
            return True
        except (subprocess.SubprocessError, FileNotFoundError):
            return False
    
    def get_available_tools(self) -> List[Dict[str, Any]]:
        """Get a list of available tools.
        
        Returns:
            List of available tools with their metadata
        """
        return [
            {
                "id": tool_id,
                "name": tool["name"],
                "description": tool["description"],
                "language": tool["language"],
                "available": tool["available"],
            }
            for tool_id, tool in self.available_tools.items()
        ]
    
    async def invoke_tool(
        self, tool_id: str, args: Optional[Dict[str, Any]] = None
    ) -> AsyncGenerator[Dict[str, Any], None]:
        """Invoke a security tool and process its results.
        
        Args:
            tool_id: ID of the tool to invoke
            args: Optional arguments for the tool
            
        Yields:
            Progress updates and results
        """
        if tool_id not in self.available_tools:
            yield {
                "status": "error",
                "message": f"Tool {tool_id} not available",
            }
            return
        
        tool = self.available_tools[tool_id]
        
        if not tool["available"]:
            yield {
                "status": "error",
                "message": f"Tool {tool['name']} is not installed or not available",
            }
            return
        
        if not self.repository_path:
            yield {
                "status": "error",
                "message": "Repository path not specified",
            }
            return
        
        # Create temporary file for output
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as temp_file:
            output_path = temp_file.name
        
        # Prepare command
        command = [
            c.format(path=self.repository_path, output=output_path)
            for c in tool["invoke_command"]
        ]
        
        # Add any additional arguments from args
        if args:
            for arg_name, arg_value in args.items():
                if arg_name != "path" and arg_name != "output":  # Skip path and output
                    command.append(f"--{arg_name}={arg_value}")
        
        # Emit event for tool invocation start
        Event.add(
            ToolInvocationEvent(
                sender=self.__class__.__name__,
                tool_name=tool["name"],
                command=" ".join(command),
                status="started",
            )
        )
        
        # Record tool invocation in the investigation
        if self.investigation_id:
            self.connector.run_query(
                "MATCH (i:Investigation) WHERE id(i) = $id "
                "CREATE (t:ToolInvocation {tool: $tool, command: $command, timestamp: $timestamp}) "
                "CREATE (i)-[:HAS_ACTIVITY]->(t)",
                {
                    "id": self.investigation_id,
                    "tool": tool["name"],
                    "command": " ".join(command),
                    "timestamp": self._get_timestamp(),
                },
            )
        
        yield {
            "status": "running",
            "message": f"Running {tool['name']}...",
            "command": " ".join(command),
        }
        
        try:
            # Run the command
            process = await asyncio.create_subprocess_exec(
                *command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode != 0:
                # Tool execution failed
                error_message = stderr.decode() if stderr else "Unknown error"
                
                # Emit event for tool invocation failure
                Event.add(
                    ToolInvocationEvent(
                        sender=self.__class__.__name__,
                        tool_name=tool["name"],
                        command=" ".join(command),
                        status="failed",
                        error=error_message,
                    )
                )
                
                yield {
                    "status": "error",
                    "message": f"Tool execution failed: {error_message}",
                }
                return
            
            # Parse results
            try:
                with open(output_path, "r") as f:
                    raw_results = f.read()
                
                # Parse the results using the tool-specific parser
                parsed_results = tool["result_parser"](raw_results)
                
                # Convert to findings
                findings = self._convert_to_findings(parsed_results, tool_id)
                
                # Store findings in the database
                if self.investigation_id:
                    for finding in findings:
                        self._store_finding(finding)
                
                # Emit event for tool invocation success
                Event.add(
                    ToolInvocationEvent(
                        sender=self.__class__.__name__,
                        tool_name=tool["name"],
                        command=" ".join(command),
                        status="completed",
                        results={"findings_count": len(findings)},
                    )
                )
                
                yield {
                    "status": "completed",
                    "message": f"Successfully ran {tool['name']}",
                    "findings_count": len(findings),
                    "findings": [f.to_dict() for f in findings],
                }
                
            except Exception as e:
                logger.error(f"Error parsing tool results: {str(e)}")
                
                # Emit event for tool invocation failure
                Event.add(
                    ToolInvocationEvent(
                        sender=self.__class__.__name__,
                        tool_name=tool["name"],
                        command=" ".join(command),
                        status="failed",
                        error=f"Error parsing results: {str(e)}",
                    )
                )
                
                yield {
                    "status": "error",
                    "message": f"Error parsing results: {str(e)}",
                }
                
        except Exception as e:
            logger.error(f"Error executing tool: {str(e)}")
            
            # Emit event for tool invocation failure
            Event.add(
                ToolInvocationEvent(
                    sender=self.__class__.__name__,
                    tool_name=tool["name"],
                    command=" ".join(command),
                    status="failed",
                    error=str(e),
                )
            )
            
            yield {
                "status": "error",
                "message": f"Error executing tool: {str(e)}",
            }
            
        finally:
            # Clean up temporary file
            try:
                if os.path.exists(output_path):
                    os.unlink(output_path)
            except Exception as e:
                logger.error(f"Error cleaning up temporary file: {str(e)}")
    
    def _store_finding(self, finding: Finding) -> None:
        """Store a finding in the database.
        
        Args:
            finding: The finding to store
        """
        if not self.investigation_id:
            return
        
        # Store the finding
        self.connector.run_query(
            "MATCH (i:Investigation) WHERE id(i) = $id "
            "CREATE (f:Finding {"
            "  vulnerability_type: $vuln_type,"
            "  severity: $severity,"
            "  confidence: $confidence,"
            "  description: $description,"
            "  file_path: $file_path,"
            "  line_number: $line_number,"
            "  remediation: $remediation,"
            "  timestamp: $timestamp"
            "}) "
            "CREATE (i)-[:HAS_FINDING]->(f)",
            {
                "id": self.investigation_id,
                "vuln_type": finding.vulnerability_type,
                "severity": finding.severity,
                "confidence": finding.confidence,
                "description": finding.description,
                "file_path": finding.file_path,
                "line_number": finding.line_number,
                "remediation": finding.remediation,
                "timestamp": self._get_timestamp(),
            },
        )
    
    def _convert_to_findings(
        self, parsed_results: List[Dict[str, Any]], tool_id: str
    ) -> List[Finding]:
        """Convert tool-specific results to standard findings.
        
        Args:
            parsed_results: The parsed results from the tool
            tool_id: The ID of the tool
            
        Returns:
            List of standardized findings
        """
        findings = []
        
        for result in parsed_results:
            # Common fields across tools
            vulnerability_type = result.get("type", "Unknown")
            description = result.get("message", "No description provided")
            file_path = result.get("file_path", "")
            line_number = result.get("line_number", 0)
            severity = result.get("severity", "medium").lower()
            confidence = float(result.get("confidence", 0.5))
            remediation = result.get("remediation", "No remediation guidance provided")
            
            finding = Finding(
                id=f"{tool_id}-{len(findings)}",
                vulnerability_type=vulnerability_type,
                severity=severity,
                confidence=confidence,
                description=description,
                file_path=file_path,
                line_number=line_number,
                remediation=remediation,
                tool=tool_id,
            )
            
            findings.append(finding)
        
        return findings
    
    def _parse_bandit_results(self, raw_results: str) -> List[Dict[str, Any]]:
        """Parse results from Bandit.
        
        Args:
            raw_results: Raw output from Bandit in JSON format
            
        Returns:
            Parsed results
        """
        try:
            data = json.loads(raw_results)
            
            # Extract results from Bandit JSON format
            parsed_results = []
            
            for result in data.get("results", []):
                # Convert Bandit severity and confidence to our standard format
                severity_map = {
                    "HIGH": "high",
                    "MEDIUM": "medium",
                    "LOW": "low",
                }
                
                confidence_map = {
                    "HIGH": 0.9,
                    "MEDIUM": 0.7,
                    "LOW": 0.4,
                }
                
                parsed_result = {
                    "type": result.get("test_id", "Unknown"),
                    "message": result.get("issue_text", "Unknown issue"),
                    "file_path": result.get("filename", ""),
                    "line_number": result.get("line_number", 0),
                    "severity": severity_map.get(result.get("issue_severity", ""), "medium"),
                    "confidence": confidence_map.get(result.get("issue_confidence", ""), 0.5),
                    "remediation": result.get("more_info", "No remediation guidance provided"),
                }
                
                parsed_results.append(parsed_result)
            
            return parsed_results
            
        except json.JSONDecodeError:
            logger.error("Failed to parse Bandit results as JSON")
            return []
    
    def _parse_semgrep_results(self, raw_results: str) -> List[Dict[str, Any]]:
        """Parse results from Semgrep.
        
        Args:
            raw_results: Raw output from Semgrep in JSON format
            
        Returns:
            Parsed results
        """
        try:
            data = json.loads(raw_results)
            
            # Extract results from Semgrep JSON format
            parsed_results = []
            
            for result in data.get("results", []):
                # Convert Semgrep severity to our standard format
                severity_map = {
                    "ERROR": "high",
                    "WARNING": "medium",
                    "INFO": "low",
                }
                
                parsed_result = {
                    "type": result.get("check_id", "Unknown"),
                    "message": result.get("extra", {}).get("message", "Unknown issue"),
                    "file_path": result.get("path", ""),
                    "line_number": result.get("start", {}).get("line", 0),
                    "severity": severity_map.get(result.get("extra", {}).get("severity", ""), "medium"),
                    "confidence": 0.8,  # Semgrep doesn't provide confidence, use a default
                    "remediation": result.get("extra", {}).get("metadata", {}).get("fix", "No remediation guidance provided"),
                }
                
                parsed_results.append(parsed_result)
            
            return parsed_results
            
        except json.JSONDecodeError:
            logger.error("Failed to parse Semgrep results as JSON")
            return []
    
    def _parse_trufflehog_results(self, raw_results: str) -> List[Dict[str, Any]]:
        """Parse results from TruffleHog.
        
        Args:
            raw_results: Raw output from TruffleHog in JSON format
            
        Returns:
            Parsed results
        """
        try:
            # TruffleHog outputs one JSON object per line
            parsed_results = []
            
            for line in raw_results.strip().split("\n"):
                if not line:
                    continue
                
                try:
                    result = json.loads(line)
                    
                    parsed_result = {
                        "type": "Secret Detection",
                        "message": f"Found potential {result.get('DetectorType', 'secret')} in {result.get('SourceName', 'file')}",
                        "file_path": result.get("SourceName", ""),
                        "line_number": result.get("SourceMetadata", {}).get("Data", {}).get("LineNumber", 0),
                        "severity": "high",  # Secrets are always high severity
                        "confidence": 0.9,  # TruffleHog is usually accurate, use high confidence
                        "remediation": "Remove the secret and rotate credentials immediately. Store secrets in a secure vault or environment variables.",
                    }
                    
                    parsed_results.append(parsed_result)
                    
                except json.JSONDecodeError:
                    # Skip invalid JSON lines
                    continue
            
            return parsed_results
            
        except Exception as e:
            logger.error(f"Failed to parse TruffleHog results: {str(e)}")
            return []
    
    def _get_timestamp(self) -> str:
        """Get the current timestamp.
        
        Returns:
            Timestamp string in ISO format
        """
        import datetime
        return datetime.datetime.utcnow().isoformat()
    
    async def run(self) -> AsyncGenerator[Dict[str, Any], None]:
        """Run the workflow.
        
        This is implemented to satisfy the Workflow base class, but tool invocation
        is typically done through specific tool invocations.
        
        Yields:
            List of available tools
        """
        yield {
            "status": "available_tools",
            "tools": self.get_available_tools(),
        }
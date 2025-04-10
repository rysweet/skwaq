"""Sources and Sinks workflow for vulnerability analysis.

This module provides functionality to identify potential sources and sinks in code
repositories. It helps developers understand data flow and potential security vulnerabilities.
"""

import os
import json
import asyncio
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Dict, List, Any, Optional, Set, Union, cast

from ..db.neo4j_connector import get_connector
from ..db.schema import NodeLabels, RelationshipTypes
from ..utils.logging import get_logger
from ..core.openai_client import OpenAIClient
from ..shared.finding import Finding
from .base import Workflow

logger = get_logger(__name__)


class SourceSinkType(Enum):
    """Types of sources and sinks used in data flow analysis."""

    # Source types
    USER_INPUT = "user_input"
    DATABASE_READ = "database_read"
    FILE_READ = "file_read"
    NETWORK_RECEIVE = "network_receive"
    ENVIRONMENT_VARIABLE = "environment_variable"
    CONFIGURATION = "configuration"
    UNKNOWN_SOURCE = "unknown_source"

    # Sink types
    DATABASE_WRITE = "database_write"
    FILE_WRITE = "file_write"
    NETWORK_SEND = "network_send"
    COMMAND_EXECUTION = "command_execution"
    HTML_RENDERING = "html_rendering"
    LOGGING = "logging"
    RESPONSE_GENERATION = "response_generation"
    UNKNOWN_SINK = "unknown_sink"


class DataFlowImpact(Enum):
    """Impact levels for data flow vulnerabilities."""

    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


@dataclass
class SourceNode:
    """Represents a source node in the data flow graph."""

    node_id: int
    name: str
    source_type: SourceSinkType
    file_node_id: Optional[int]
    function_node_id: Optional[int] = None
    class_node_id: Optional[int] = None
    line_number: Optional[int] = None
    description: str = ""
    confidence: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert the source node to a dictionary.

        Returns:
            Dictionary representation of the source node
        """
        result = {
            "node_id": self.node_id,
            "name": self.name,
            "source_type": self.source_type.value,
            "file_node_id": self.file_node_id,
            "description": self.description,
            "confidence": self.confidence,
        }

        if self.function_node_id is not None:
            result["function_node_id"] = self.function_node_id

        if self.class_node_id is not None:
            result["class_node_id"] = self.class_node_id

        if self.line_number is not None:
            result["line_number"] = self.line_number

        if self.metadata:
            result["metadata"] = self.metadata

        return result

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "SourceNode":
        """Create a source node from a dictionary.

        Args:
            data: Dictionary with source node data

        Returns:
            SourceNode instance
        """
        # Convert string source type to enum
        source_type = SourceSinkType(data["source_type"])

        # Extract core fields
        result = cls(
            node_id=data["node_id"],
            name=data["name"],
            source_type=source_type,
            file_node_id=data["file_node_id"],
            description=data.get("description", ""),
            confidence=data.get("confidence", 0.0),
        )

        # Optional fields
        if "function_node_id" in data:
            result.function_node_id = data["function_node_id"]

        if "class_node_id" in data:
            result.class_node_id = data["class_node_id"]

        if "line_number" in data:
            result.line_number = data["line_number"]

        if "metadata" in data:
            result.metadata = data["metadata"]

        return result


@dataclass
class SinkNode:
    """Represents a sink node in the data flow graph."""

    node_id: int
    name: str
    sink_type: SourceSinkType
    file_node_id: Optional[int]
    function_node_id: Optional[int] = None
    class_node_id: Optional[int] = None
    line_number: Optional[int] = None
    description: str = ""
    confidence: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert the sink node to a dictionary.

        Returns:
            Dictionary representation of the sink node
        """
        result = {
            "node_id": self.node_id,
            "name": self.name,
            "sink_type": self.sink_type.value,
            "file_node_id": self.file_node_id,
            "description": self.description,
            "confidence": self.confidence,
        }

        if self.function_node_id is not None:
            result["function_node_id"] = self.function_node_id

        if self.class_node_id is not None:
            result["class_node_id"] = self.class_node_id

        if self.line_number is not None:
            result["line_number"] = self.line_number

        if self.metadata:
            result["metadata"] = self.metadata

        return result

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "SinkNode":
        """Create a sink node from a dictionary.

        Args:
            data: Dictionary with sink node data

        Returns:
            SinkNode instance
        """
        # Convert string sink type to enum
        sink_type = SourceSinkType(data["sink_type"])

        # Extract core fields
        result = cls(
            node_id=data["node_id"],
            name=data["name"],
            sink_type=sink_type,
            file_node_id=data["file_node_id"],
            description=data.get("description", ""),
            confidence=data.get("confidence", 0.0),
        )

        # Optional fields
        if "function_node_id" in data:
            result.function_node_id = data["function_node_id"]

        if "class_node_id" in data:
            result.class_node_id = data["class_node_id"]

        if "line_number" in data:
            result.line_number = data["line_number"]

        if "metadata" in data:
            result.metadata = data["metadata"]

        return result


@dataclass
class DataFlowPath:
    """Represents a data flow path between a source and a sink."""

    source_node: SourceNode
    sink_node: SinkNode
    intermediate_nodes: List[int] = field(default_factory=list)
    vulnerability_type: str = ""
    impact: DataFlowImpact = DataFlowImpact.MEDIUM
    description: str = ""
    recommendations: List[str] = field(default_factory=list)
    confidence: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert the data flow path to a dictionary.

        Returns:
            Dictionary representation of the data flow path
        """
        return {
            "source_node": self.source_node.to_dict(),
            "sink_node": self.sink_node.to_dict(),
            "intermediate_nodes": self.intermediate_nodes,
            "vulnerability_type": self.vulnerability_type,
            "impact": self.impact.value,
            "description": self.description,
            "recommendations": self.recommendations,
            "confidence": self.confidence,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "DataFlowPath":
        """Create a data flow path from a dictionary.

        Args:
            data: Dictionary with data flow path data

        Returns:
            DataFlowPath instance
        """
        # Convert source and sink nodes
        source_node = SourceNode.from_dict(data["source_node"])
        sink_node = SinkNode.from_dict(data["sink_node"])

        # Convert impact string to enum
        impact = DataFlowImpact(data["impact"])

        return cls(
            source_node=source_node,
            sink_node=sink_node,
            intermediate_nodes=data.get("intermediate_nodes", []),
            vulnerability_type=data.get("vulnerability_type", ""),
            impact=impact,
            description=data.get("description", ""),
            recommendations=data.get("recommendations", []),
            confidence=data.get("confidence", 0.0),
            metadata=data.get("metadata", {}),
        )


@dataclass
class SourcesAndSinksResult:
    """Results of a sources and sinks analysis workflow."""

    investigation_id: str
    sources: List[SourceNode] = field(default_factory=list)
    sinks: List[SinkNode] = field(default_factory=list)
    data_flow_paths: List[DataFlowPath] = field(default_factory=list)
    summary: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert the result to a dictionary.

        Returns:
            Dictionary representation of the result
        """
        return {
            "investigation_id": self.investigation_id,
            "sources": [source.to_dict() for source in self.sources],
            "sinks": [sink.to_dict() for sink in self.sinks],
            "data_flow_paths": [path.to_dict() for path in self.data_flow_paths],
            "summary": self.summary,
            "metadata": self.metadata,
        }

    def to_json(self) -> str:
        """Convert the result to a JSON string.

        Returns:
            JSON representation of the result
        """
        return json.dumps(self.to_dict(), indent=2)

    def to_markdown(self) -> str:
        """Convert the result to a Markdown string.

        Returns:
            Markdown representation of the result
        """
        markdown = f"# Sources and Sinks Analysis Results\n\n"
        markdown += f"## Investigation ID: {self.investigation_id}\n\n"

        if self.summary:
            markdown += f"## Summary\n\n{self.summary}\n\n"

        # Sources section
        markdown += f"## Sources ({len(self.sources)})\n\n"
        if self.sources:
            markdown += "| Name | Type | Confidence | Description |\n"
            markdown += "|------|------|------------|-------------|\n"
            for source in self.sources:
                markdown += f"| {source.name} | {source.source_type.value} | {source.confidence:.2f} | {source.description} |\n"
        else:
            markdown += "No sources identified.\n"
        markdown += "\n"

        # Sinks section
        markdown += f"## Sinks ({len(self.sinks)})\n\n"
        if self.sinks:
            markdown += "| Name | Type | Confidence | Description |\n"
            markdown += "|------|------|------------|-------------|\n"
            for sink in self.sinks:
                markdown += f"| {sink.name} | {sink.sink_type.value} | {sink.confidence:.2f} | {sink.description} |\n"
        else:
            markdown += "No sinks identified.\n"
        markdown += "\n"

        # Data flow paths section
        markdown += f"## Data Flow Paths ({len(self.data_flow_paths)})\n\n"
        if self.data_flow_paths:
            for i, path in enumerate(self.data_flow_paths):
                markdown += f"### Path {i+1}: {path.vulnerability_type}\n\n"
                markdown += f"**Impact**: {path.impact.value}\n\n"
                markdown += f"**Source**: {path.source_node.name} ({path.source_node.source_type.value})\n\n"
                markdown += f"**Sink**: {path.sink_node.name} ({path.sink_node.sink_type.value})\n\n"
                markdown += f"**Description**: {path.description}\n\n"

                if path.recommendations:
                    markdown += "**Recommendations**:\n\n"
                    for rec in path.recommendations:
                        markdown += f"- {rec}\n"
                    markdown += "\n"
        else:
            markdown += "No data flow paths identified.\n"

        return markdown


class FunnelQuery(ABC):
    """Base class for funnel queries used to identify potential sources and sinks."""

    def __init__(self, connector=None, query_params: Optional[Dict[str, Any]] = None):
        """Initialize the funnel query.

        Args:
            connector: Optional connector to use for queries (default: global connector)
            query_params: Optional parameters for the query
        """
        self._connector = connector or get_connector()
        self._query_params = query_params or {}
        self.name = self.__class__.__name__

    @abstractmethod
    async def query_sources(self, investigation_id: str) -> List[Dict[str, Any]]:
        """Query the graph for potential source nodes.

        Args:
            investigation_id: ID of the investigation to query

        Returns:
            List of dictionaries with potential source node data
        """
        pass

    @abstractmethod
    async def query_sinks(self, investigation_id: str) -> List[Dict[str, Any]]:
        """Query the graph for potential sink nodes.

        Args:
            investigation_id: ID of the investigation to query

        Returns:
            List of dictionaries with potential sink node data
        """
        pass


class CodeSummaryFunnel(FunnelQuery):
    """Funnel query that uses code summary nodes to identify potential sources and sinks."""

    async def query_sources(self, investigation_id: str) -> List[Dict[str, Any]]:
        """Query the graph for potential source nodes using code summaries.

        This looks for keywords related to sources in code summary nodes.

        Args:
            investigation_id: ID of the investigation to query

        Returns:
            List of dictionaries with potential source node data
        """
        # Keywords associated with sources in code summaries
        source_keywords = [
            "input",
            "read",
            "load",
            "fetch",
            "get",
            "receive",
            "request",
            "parse",
            "environment",
            "config",
            "parameter",
            "argument",
            "userinput",
            "database",
            "file",
            "http",
            "socket",
            "port",
        ]

        # Construct the Cypher query using code summaries - with a more robust approach
        # First, try to find properly connected functions
        query = """
        MATCH (i:Investigation {id: $investigation_id})
        MATCH (i)-[:HAS_REPOSITORY]->(repo:Repository)
        WITH i, repo
        
        // Look for functions with summaries (properly connected to files in the repo)
        OPTIONAL MATCH (f:File)-[:PART_OF]->(repo)
        OPTIONAL MATCH (func)-[:DEFINED_IN]->(f)
        OPTIONAL MATCH (func)-[:HAS_SUMMARY]->(summary1:CodeSummary)
        WHERE (func:Function OR func:Method) AND 
              ANY(keyword IN $keywords WHERE toLower(summary1.summary) CONTAINS toLower(keyword))
        
        // Also look for any functions with summaries (regardless of connection to files)
        OPTIONAL MATCH (func2:Function)-[:HAS_SUMMARY]->(summary2:CodeSummary)
        WHERE ANY(keyword IN $keywords WHERE toLower(summary2.summary) CONTAINS toLower(keyword))
        
        // Union the results, with priority to properly connected functions
        WITH 
            CASE WHEN func IS NOT NULL THEN func ELSE func2 END AS function,
            CASE WHEN func IS NOT NULL THEN summary1 ELSE summary2 END AS summary,
            CASE WHEN func IS NOT NULL THEN f ELSE NULL END AS file,
            repo
        WHERE function IS NOT NULL
        
        RETURN 
            id(function) AS node_id,
            function.name AS name,
            CASE WHEN file IS NOT NULL THEN id(file) ELSE null END AS file_node_id,
            null AS method_node_id,
            null AS class_node_id,
            function.line_number AS line_number,
            summary.summary AS description,
            CASE WHEN file IS NOT NULL THEN file.path ELSE 'unknown' END AS file_path
        """

        params = {"investigation_id": investigation_id, "keywords": source_keywords}

        try:
            results = self._connector.run_query(query, params)
            logger.info(
                f"Found {len(results)} potential source nodes using code summary funnel"
            )
            return results
        except Exception as e:
            logger.error(f"Error querying potential source nodes: {e}")
            return []

    async def query_sinks(self, investigation_id: str) -> List[Dict[str, Any]]:
        """Query the graph for potential sink nodes using code summaries.

        This looks for keywords related to sinks in code summary nodes.

        Args:
            investigation_id: ID of the investigation to query

        Returns:
            List of dictionaries with potential sink node data
        """
        # Keywords associated with sinks in code summaries
        sink_keywords = [
            "write",
            "save",
            "update",
            "execute",
            "insert",
            "delete",
            "query",
            "render",
            "response",
            "print",
            "log",
            "output",
            "store",
            "send",
            "sql",
            "command",
            "exec",
            "eval",
            "database",
            "file",
            "http",
        ]

        # Construct the Cypher query using code summaries - with a more robust approach
        # First, try to find properly connected functions
        query = """
        MATCH (i:Investigation {id: $investigation_id})
        MATCH (i)-[:HAS_REPOSITORY]->(repo:Repository)
        WITH i, repo
        
        // Look for functions with summaries (properly connected to files in the repo)
        OPTIONAL MATCH (f:File)-[:PART_OF]->(repo)
        OPTIONAL MATCH (func)-[:DEFINED_IN]->(f)
        OPTIONAL MATCH (func)-[:HAS_SUMMARY]->(summary1:CodeSummary)
        WHERE (func:Function OR func:Method) AND 
              ANY(keyword IN $keywords WHERE toLower(summary1.summary) CONTAINS toLower(keyword))
        
        // Also look for any functions with summaries (regardless of connection to files)
        OPTIONAL MATCH (func2:Function)-[:HAS_SUMMARY]->(summary2:CodeSummary)
        WHERE ANY(keyword IN $keywords WHERE toLower(summary2.summary) CONTAINS toLower(keyword))
        
        // Union the results, with priority to properly connected functions
        WITH 
            CASE WHEN func IS NOT NULL THEN func ELSE func2 END AS function,
            CASE WHEN func IS NOT NULL THEN summary1 ELSE summary2 END AS summary,
            CASE WHEN func IS NOT NULL THEN f ELSE NULL END AS file,
            repo
        WHERE function IS NOT NULL
        
        RETURN 
            id(function) AS node_id,
            function.name AS name,
            CASE WHEN file IS NOT NULL THEN id(file) ELSE null END AS file_node_id,
            null AS method_node_id,
            null AS class_node_id,
            function.line_number AS line_number,
            summary.summary AS description,
            CASE WHEN file IS NOT NULL THEN file.path ELSE 'unknown' END AS file_path
        """

        params = {"investigation_id": investigation_id, "keywords": sink_keywords}

        try:
            results = self._connector.run_query(query, params)
            logger.info(
                f"Found {len(results)} potential sink nodes using code summary funnel"
            )
            return results
        except Exception as e:
            logger.error(f"Error querying potential sink nodes: {e}")
            return []


class Analyzer(ABC):
    """Base class for analyzers used to identify sources and sinks."""

    def __init__(self, connector=None):
        """Initialize the analyzer.

        Args:
            connector: Optional connector to use for queries (default: global connector)
        """
        self._connector = connector or get_connector()
        self.name = self.__class__.__name__

    @abstractmethod
    async def analyze_source(
        self, node_data: Dict[str, Any], investigation_id: str
    ) -> Optional[SourceNode]:
        """Analyze if a node is a source.

        Args:
            node_data: Data about the node to analyze
            investigation_id: ID of the investigation

        Returns:
            SourceNode if the node is a source, None otherwise
        """
        pass

    @abstractmethod
    async def analyze_sink(
        self, node_data: Dict[str, Any], investigation_id: str
    ) -> Optional[SinkNode]:
        """Analyze if a node is a sink.

        Args:
            node_data: Data about the node to analyze
            investigation_id: ID of the investigation

        Returns:
            SinkNode if the node is a sink, None otherwise
        """
        pass

    @abstractmethod
    async def analyze_data_flow(
        self, sources: List[SourceNode], sinks: List[SinkNode], investigation_id: str
    ) -> List[DataFlowPath]:
        """Analyze potential data flow paths between sources and sinks.

        Args:
            sources: List of identified source nodes
            sinks: List of identified sink nodes
            investigation_id: ID of the investigation

        Returns:
            List of potential data flow paths
        """
        pass


class LLMAnalyzer(Analyzer):
    """Analyzer that uses LLM to identify sources and sinks."""

    def __init__(self, llm_client: OpenAIClient, connector=None):
        """Initialize the LLM analyzer.

        Args:
            llm_client: LLM client to use for analysis
            connector: Optional connector to use for queries (default: global connector)
        """
        super().__init__(connector)
        self.llm_client = llm_client
        self._prompts: Dict[str, str] = self._load_prompts()

    def _load_prompts(self) -> Dict[str, str]:
        """Load the LLM prompts for source and sink identification.

        Returns:
            Dictionary of prompt names to prompt content
        """
        prompts: Dict[str, str] = {}
        prompts_dir = Path(__file__).parent / "prompts" / "sources_and_sinks"

        # Ensure the prompts directory exists
        if not prompts_dir.exists():
            logger.warning(f"Prompts directory not found: {prompts_dir}")
            return prompts

        # Load each prompt file
        for prompt_file in prompts_dir.glob("*.prompt"):
            prompt_name = prompt_file.stem
            with open(prompt_file, "r") as f:
                content = f.read()
                # Parse the prompty.ai format (simple version)
                # Extract the system prompt section
                if "system: |" in content:
                    system_prompt = content.split("system: |")[1].strip()
                    prompts[prompt_name] = system_prompt

        return prompts

    async def _get_function_code(self, node_id: int) -> str:
        """Get the function/method code from the database.

        Args:
            node_id: ID of the function/method node

        Returns:
            Function/method code as a string
        """
        query = """
        MATCH (func) WHERE id(func) = $node_id
        RETURN func.code AS code
        """

        results = self._connector.run_query(query, {"node_id": node_id})
        if results and "code" in results[0]:
            return results[0]["code"]
        return ""

    async def analyze_source(
        self, node_data: Dict[str, Any], investigation_id: str
    ) -> Optional[SourceNode]:
        """Analyze if a node is a source using LLM.

        Args:
            node_data: Data about the node to analyze
            investigation_id: ID of the investigation

        Returns:
            SourceNode if the node is a source, None otherwise
        """
        # Get function code
        function_code = await self._get_function_code(node_data["node_id"])
        if not function_code:
            logger.warning(f"No code found for node: {node_data['node_id']}")
            return None

        # Prepare context for LLM
        context = f"""
        Function Name: {node_data.get('name', 'Unknown')}
        File Path: {node_data.get('file_path', 'Unknown')}
        
        Function Code:
        ```
        {function_code}
        ```
        
        Description/Summary: {node_data.get('description', 'No description available')}
        """

        # Get the source identification prompt
        source_prompt = self._prompts.get(
            "identify_sources", "Identify if this function is a source of data."
        )

        # Create messages for the LLM
        messages = [
            {"role": "system", "content": source_prompt},
            {"role": "user", "content": context},
        ]

        try:
            # Get LLM response
            response = await self.llm_client.chat_completion(
                messages=messages, temperature=0.2, max_tokens=1000
            )

            # Check if the LLM identified this as a source
            content = response.get("content", "")

            # Simple heuristic: if the LLM response contains "source" keywords, it's likely a source
            source_indicators = [
                "is a source",
                "acts as a source",
                "functions as a source",
                "introduces data",
                "obtains data",
                "retrieves data",
            ]

            is_source = any(
                indicator in content.lower() for indicator in source_indicators
            )

            if not is_source:
                return None

            # Determine the source type based on the response
            source_type = SourceSinkType.UNKNOWN_SOURCE
            if "user input" in content.lower() or "user-supplied" in content.lower():
                source_type = SourceSinkType.USER_INPUT
            elif "database" in content.lower():
                source_type = SourceSinkType.DATABASE_READ
            elif "file" in content.lower() and any(
                word in content.lower() for word in ["read", "load", "open"]
            ):
                source_type = SourceSinkType.FILE_READ
            elif any(
                word in content.lower() for word in ["http", "request", "api", "fetch"]
            ):
                source_type = SourceSinkType.NETWORK_RECEIVE
            elif "environment" in content.lower():
                source_type = SourceSinkType.ENVIRONMENT_VARIABLE
            elif "config" in content.lower():
                source_type = SourceSinkType.CONFIGURATION

            # Extract a meaningful description from the LLM response
            description = (
                content.split("\n\n")[0] if "\n\n" in content else content[:200]
            )

            # Calculate confidence based on LLM response (simple heuristic)
            confidence_indicators = {
                "definitely": 0.9,
                "likely": 0.7,
                "probably": 0.6,
                "possibly": 0.4,
                "might": 0.3,
            }

            confidence = 0.5  # Default confidence
            for indicator, value in confidence_indicators.items():
                if indicator in content.lower():
                    confidence = value
                    break

            # Create the source node
            return SourceNode(
                node_id=node_data["node_id"],
                name=node_data.get("name", "Unknown"),
                source_type=source_type,
                file_node_id=node_data.get("file_node_id"),
                function_node_id=node_data.get("node_id"),
                class_node_id=node_data.get("class_node_id"),
                line_number=node_data.get("line_number"),
                description=description,
                confidence=confidence,
                metadata={"llm_response": content},
            )

        except Exception as e:
            logger.error(f"Error analyzing source with LLM: {e}")
            return None

    async def analyze_sink(
        self, node_data: Dict[str, Any], investigation_id: str
    ) -> Optional[SinkNode]:
        """Analyze if a node is a sink using LLM.

        Args:
            node_data: Data about the node to analyze
            investigation_id: ID of the investigation

        Returns:
            SinkNode if the node is a sink, None otherwise
        """
        # Get function code
        function_code = await self._get_function_code(node_data["node_id"])
        if not function_code:
            logger.warning(f"No code found for node: {node_data['node_id']}")
            return None

        # Prepare context for LLM
        context = f"""
        Function Name: {node_data.get('name', 'Unknown')}
        File Path: {node_data.get('file_path', 'Unknown')}
        
        Function Code:
        ```
        {function_code}
        ```
        
        Description/Summary: {node_data.get('description', 'No description available')}
        """

        # Get the sink identification prompt
        sink_prompt = self._prompts.get(
            "identify_sinks", "Identify if this function is a sink for data."
        )

        # Create messages for the LLM
        messages = [
            {"role": "system", "content": sink_prompt},
            {"role": "user", "content": context},
        ]

        try:
            # Get LLM response
            response = await self.llm_client.chat_completion(
                messages=messages, temperature=0.2, max_tokens=1000
            )

            # Check if the LLM identified this as a sink
            content = response.get("content", "")

            # Simple heuristic: if the LLM response contains "sink" keywords, it's likely a sink
            sink_indicators = [
                "is a sink",
                "acts as a sink",
                "functions as a sink",
                "outputs data",
                "writes data",
                "sends data",
                "executes",
            ]

            is_sink = any(indicator in content.lower() for indicator in sink_indicators)

            if not is_sink:
                return None

            # Determine the sink type based on the response
            sink_type = SourceSinkType.UNKNOWN_SINK
            if "database" in content.lower() and any(
                word in content.lower()
                for word in ["write", "insert", "update", "delete", "query"]
            ):
                sink_type = SourceSinkType.DATABASE_WRITE
            elif "file" in content.lower() and any(
                word in content.lower() for word in ["write", "save", "create"]
            ):
                sink_type = SourceSinkType.FILE_WRITE
            elif any(
                word in content.lower() for word in ["http", "response", "send", "api"]
            ):
                sink_type = SourceSinkType.NETWORK_SEND
            elif any(
                word in content.lower()
                for word in ["exec", "execute", "command", "system", "shell"]
            ):
                sink_type = SourceSinkType.COMMAND_EXECUTION
            elif any(
                word in content.lower() for word in ["html", "render", "template"]
            ):
                sink_type = SourceSinkType.HTML_RENDERING
            elif "log" in content.lower():
                sink_type = SourceSinkType.LOGGING
            elif "response" in content.lower():
                sink_type = SourceSinkType.RESPONSE_GENERATION

            # Extract a meaningful description from the LLM response
            description = (
                content.split("\n\n")[0] if "\n\n" in content else content[:200]
            )

            # Calculate confidence based on LLM response (simple heuristic)
            confidence_indicators = {
                "definitely": 0.9,
                "likely": 0.7,
                "probably": 0.6,
                "possibly": 0.4,
                "might": 0.3,
            }

            confidence = 0.5  # Default confidence
            for indicator, value in confidence_indicators.items():
                if indicator in content.lower():
                    confidence = value
                    break

            # Create the sink node
            return SinkNode(
                node_id=node_data["node_id"],
                name=node_data.get("name", "Unknown"),
                sink_type=sink_type,
                file_node_id=node_data.get("file_node_id"),
                function_node_id=node_data.get("node_id"),
                class_node_id=node_data.get("class_node_id"),
                line_number=node_data.get("line_number"),
                description=description,
                confidence=confidence,
                metadata={"llm_response": content},
            )

        except Exception as e:
            logger.error(f"Error analyzing sink with LLM: {e}")
            return None

    async def analyze_data_flow(
        self, sources: List[SourceNode], sinks: List[SinkNode], investigation_id: str
    ) -> List[DataFlowPath]:
        """Analyze potential data flow paths between sources and sinks using LLM.

        Args:
            sources: List of identified source nodes
            sinks: List of identified sink nodes
            investigation_id: ID of the investigation

        Returns:
            List of potential data flow paths
        """
        data_flow_paths: List[DataFlowPath] = []

        # If either sources or sinks is empty, return empty list
        if not sources or not sinks:
            logger.info("No sources and/or sinks to analyze data flow")
            return data_flow_paths

        # Get the data flow analysis prompt
        data_flow_prompt = self._prompts.get(
            "analyze_data_flow",
            "Analyze potential data flow between sources and sinks.",
        )

        # Group sources and sinks by file for more accurate analysis
        file_to_sources: Dict[int, List[SourceNode]] = {}
        file_to_sinks: Dict[int, List[SinkNode]] = {}

        for source in sources:
            if source.file_node_id not in file_to_sources:
                file_to_sources[source.file_node_id] = []
            file_to_sources[source.file_node_id].append(source)

        for sink in sinks:
            if sink.file_node_id not in file_to_sinks:
                file_to_sinks[sink.file_node_id] = []
            file_to_sinks[sink.file_node_id].append(sink)

        # First, analyze data flow within the same file
        for file_id, file_sources in file_to_sources.items():
            if file_id in file_to_sinks:
                file_sinks = file_to_sinks[file_id]

                # Get file content
                query = """
                MATCH (f:File) WHERE id(f) = $file_id
                RETURN f.path AS file_path
                """

                result = self._connector.run_query(query, {"file_id": file_id})
                if not result:
                    continue

                file_path = result[0].get("file_path", "Unknown")

                # Prepare context for LLM
                context = f"""
                File Path: {file_path}
                
                Sources:
                """

                for i, source in enumerate(file_sources, 1):
                    source_code = await self._get_function_code(source.node_id)
                    context += f"""
                    Source {i}: {source.name} (Type: {source.source_type.value})
                    Description: {source.description}
                    
                    Code:
                    ```
                    {source_code[:500]}  # Limit code size to avoid token limit
                    ```
                    
                    """

                context += "\nSinks:\n"

                for i, sink in enumerate(file_sinks, 1):
                    sink_code = await self._get_function_code(sink.node_id)
                    context += f"""
                    Sink {i}: {sink.name} (Type: {sink.sink_type.value})
                    Description: {sink.description}
                    
                    Code:
                    ```
                    {sink_code[:500]}  # Limit code size to avoid token limit
                    ```
                    
                    """

                # Create messages for the LLM
                messages = [
                    {"role": "system", "content": data_flow_prompt},
                    {"role": "user", "content": context},
                ]

                try:
                    # Get LLM response
                    response = await self.llm_client.chat_completion(
                        messages=messages, temperature=0.3, max_tokens=1500
                    )

                    content = response.get("content", "")

                    # Parse the LLM response to find data flow paths
                    # This is a simplified parser that looks for specific patterns
                    lines = content.split("\n")
                    current_source = None
                    current_sink = None
                    current_description: List[str] = []
                    current_vulnerability = ""
                    current_recommendations: List[str] = []

                    for line in lines:
                        line = line.strip().lower()

                        if not line:
                            continue

                        # Look for source references
                        if line.startswith("source") and ":" in line:
                            source_info = line.split(":", 1)[1].strip()
                            for i, source in enumerate(file_sources, 1):
                                if (
                                    f"source {i}" in line.lower()
                                    or source.name.lower() in source_info
                                ):
                                    current_source = source
                                    break

                        # Look for sink references
                        elif line.startswith("sink") and ":" in line:
                            sink_info = line.split(":", 1)[1].strip()
                            for i, sink in enumerate(file_sinks, 1):
                                if (
                                    f"sink {i}" in line.lower()
                                    or sink.name.lower() in sink_info
                                ):
                                    current_sink = sink
                                    break

                        # Look for vulnerability type
                        elif (
                            any(
                                vuln in line
                                for vuln in [
                                    "vulnerability",
                                    "vulnerability type",
                                    "issue",
                                ]
                            )
                            and ":" in line
                        ):
                            current_vulnerability = line.split(":", 1)[1].strip()

                        # Look for description
                        elif line.startswith("description") and ":" in line:
                            current_description = [line.split(":", 1)[1].strip()]
                        elif current_description and not line.startswith(
                            ("source", "sink", "recommendation", "vulnerability")
                        ):
                            current_description.append(line)

                        # Look for recommendations
                        elif line.startswith("recommendation") and ":" in line:
                            current_recommendations = [line.split(":", 1)[1].strip()]
                        elif current_recommendations and line.startswith("-"):
                            current_recommendations.append(line)

                        # If we have both source and sink, create a path
                        if (
                            current_source
                            and current_sink
                            and (current_description or current_vulnerability)
                        ):
                            # Determine impact based on the content
                            impact = DataFlowImpact.MEDIUM  # Default
                            if (
                                "high" in content.lower()
                                and "impact" in content.lower()
                            ):
                                impact = DataFlowImpact.HIGH
                            elif (
                                "low" in content.lower() and "impact" in content.lower()
                            ):
                                impact = DataFlowImpact.LOW

                            path = DataFlowPath(
                                source_node=current_source,
                                sink_node=current_sink,
                                vulnerability_type=current_vulnerability
                                or "Potential data flow vulnerability",
                                impact=impact,
                                description="\n".join(current_description),
                                recommendations=current_recommendations,
                                confidence=0.6,  # Conservative confidence for LLM-detected data flows
                                metadata={"llm_response": content},
                            )

                            data_flow_paths.append(path)

                            # Reset for next path
                            current_source = None
                            current_sink = None
                            current_description = []
                            current_vulnerability = ""
                            current_recommendations = []

                except Exception as e:
                    logger.error(f"Error analyzing data flow with LLM: {e}")

        return data_flow_paths

    async def generate_summary(
        self,
        sources: List[SourceNode],
        sinks: List[SinkNode],
        data_flow_paths: List[DataFlowPath],
        investigation_id: str,
    ) -> str:
        """Generate a summary of the sources and sinks analysis.

        Args:
            sources: List of identified source nodes
            sinks: List of identified sink nodes
            data_flow_paths: List of identified data flow paths
            investigation_id: ID of the investigation

        Returns:
            Summary text
        """
        # Get the summary prompt
        summary_prompt = self._prompts.get(
            "summarize_results",
            "Summarize the results of the sources and sinks analysis.",
        )

        # Prepare context for LLM
        context = f"""
        Investigation ID: {investigation_id}
        
        Sources Identified: {len(sources)}
        Sinks Identified: {len(sinks)}
        Data Flow Paths Identified: {len(data_flow_paths)}
        
        Source Types:
        """

        # Count source types
        source_type_counts: Dict[str, int] = {}
        for source in sources:
            source_type = source.source_type.value
            source_type_counts[source_type] = source_type_counts.get(source_type, 0) + 1

        for source_type, count in source_type_counts.items():
            context += f"- {source_type}: {count}\n"

        context += "\nSink Types:\n"

        # Count sink types
        sink_type_counts: Dict[str, int] = {}
        for sink in sinks:
            sink_type = sink.sink_type.value
            sink_type_counts[sink_type] = sink_type_counts.get(sink_type, 0) + 1

        for sink_type, count in sink_type_counts.items():
            context += f"- {sink_type}: {count}\n"

        context += "\nVulnerability Types in Data Flow Paths:\n"

        # Count vulnerability types
        vuln_type_counts: Dict[str, int] = {}
        for path in data_flow_paths:
            vuln_type = path.vulnerability_type or "Unknown"
            vuln_type_counts[vuln_type] = vuln_type_counts.get(vuln_type, 0) + 1

        for vuln_type, count in vuln_type_counts.items():
            context += f"- {vuln_type}: {count}\n"

        context += "\nImpact Levels:\n"

        # Count impact levels
        impact_counts: Dict[str, int] = {}
        for path in data_flow_paths:
            impact = path.impact.value
            impact_counts[impact] = impact_counts.get(impact, 0) + 1

        for impact, count in impact_counts.items():
            context += f"- {impact}: {count}\n"

        # Create messages for the LLM
        messages = [
            {"role": "system", "content": summary_prompt},
            {"role": "user", "content": context},
        ]

        try:
            # Get LLM response
            response = await self.llm_client.chat_completion(
                messages=messages, temperature=0.3, max_tokens=1500
            )

            result = response.get("content", "")
            return result

        except Exception as e:
            logger.error(f"Error generating summary with LLM: {e}")
            return "Could not generate summary due to an error."


class DocumentationAnalyzer(Analyzer):
    """Analyzer that uses documentation to identify sources and sinks."""

    async def analyze_source(
        self, node_data: Dict[str, Any], investigation_id: str
    ) -> Optional[SourceNode]:
        """Analyze if a node is a source using documentation.

        Args:
            node_data: Data about the node to analyze
            investigation_id: ID of the investigation

        Returns:
            SourceNode if the node is a source, None otherwise
        """
        # Query for documentation nodes related to this function/method
        query = """
        MATCH (func) WHERE id(func) = $node_id
        MATCH (func)-[:DOCUMENTS]-(doc)
        RETURN doc.content AS doc_content
        """

        results = self._connector.run_query(query, {"node_id": node_data["node_id"]})

        if not results:
            return None

        # Keywords that indicate a source in documentation
        source_keywords = [
            "read",
            "input",
            "get",
            "fetch",
            "load",
            "receive",
            "obtain",
            "parse",
            "extract",
            "import",
        ]

        # Check if documentation contains source keywords
        for result in results:
            doc_content = result.get("doc_content", "").lower()

            if any(keyword in doc_content for keyword in source_keywords):
                # Determine source type based on documentation
                source_type = SourceSinkType.UNKNOWN_SOURCE

                if "user" in doc_content and "input" in doc_content:
                    source_type = SourceSinkType.USER_INPUT
                elif "database" in doc_content:
                    source_type = SourceSinkType.DATABASE_READ
                elif "file" in doc_content:
                    source_type = SourceSinkType.FILE_READ
                elif any(
                    word in doc_content for word in ["http", "request", "network"]
                ):
                    source_type = SourceSinkType.NETWORK_RECEIVE
                elif "environment" in doc_content:
                    source_type = SourceSinkType.ENVIRONMENT_VARIABLE
                elif "config" in doc_content:
                    source_type = SourceSinkType.CONFIGURATION

                # Calculate confidence (simple heuristic based on keyword frequency)
                keyword_count = sum(
                    doc_content.count(keyword) for keyword in source_keywords
                )
                confidence = min(
                    0.3 + (keyword_count * 0.1), 0.8
                )  # Max 0.8 confidence from documentation

                # Create source node
                return SourceNode(
                    node_id=node_data["node_id"],
                    name=node_data.get("name", "Unknown"),
                    source_type=source_type,
                    file_node_id=node_data.get("file_node_id"),
                    function_node_id=node_data.get("node_id"),
                    class_node_id=node_data.get("class_node_id"),
                    line_number=node_data.get("line_number"),
                    description=f"Documentation indicates this is a {source_type.value}",
                    confidence=confidence,
                    metadata={"documentation": doc_content[:500]},  # Limit size
                )

        return None

    async def analyze_sink(
        self, node_data: Dict[str, Any], investigation_id: str
    ) -> Optional[SinkNode]:
        """Analyze if a node is a sink using documentation.

        Args:
            node_data: Data about the node to analyze
            investigation_id: ID of the investigation

        Returns:
            SinkNode if the node is a sink, None otherwise
        """
        # Query for documentation nodes related to this function/method
        query = """
        MATCH (func) WHERE id(func) = $node_id
        MATCH (func)-[:DOCUMENTS]-(doc)
        RETURN doc.content AS doc_content
        """

        results = self._connector.run_query(query, {"node_id": node_data["node_id"]})

        if not results:
            return None

        # Keywords that indicate a sink in documentation
        sink_keywords = [
            "write",
            "output",
            "save",
            "store",
            "execute",
            "update",
            "delete",
            "insert",
            "query",
            "render",
            "response",
            "print",
            "log",
        ]

        # Check if documentation contains sink keywords
        for result in results:
            doc_content = result.get("doc_content", "").lower()

            if any(keyword in doc_content for keyword in sink_keywords):
                # Determine sink type based on documentation
                sink_type = SourceSinkType.UNKNOWN_SINK

                if "database" in doc_content and any(
                    word in doc_content
                    for word in ["write", "update", "delete", "insert", "query"]
                ):
                    sink_type = SourceSinkType.DATABASE_WRITE
                elif "file" in doc_content and any(
                    word in doc_content for word in ["write", "save"]
                ):
                    sink_type = SourceSinkType.FILE_WRITE
                elif any(
                    word in doc_content for word in ["http", "response", "network"]
                ):
                    sink_type = SourceSinkType.NETWORK_SEND
                elif any(
                    word in doc_content
                    for word in ["exec", "command", "system", "shell"]
                ):
                    sink_type = SourceSinkType.COMMAND_EXECUTION
                elif any(
                    word in doc_content for word in ["html", "render", "template"]
                ):
                    sink_type = SourceSinkType.HTML_RENDERING
                elif "log" in doc_content:
                    sink_type = SourceSinkType.LOGGING
                elif "response" in doc_content:
                    sink_type = SourceSinkType.RESPONSE_GENERATION

                # Calculate confidence (simple heuristic based on keyword frequency)
                keyword_count = sum(
                    doc_content.count(keyword) for keyword in sink_keywords
                )
                confidence = min(
                    0.3 + (keyword_count * 0.1), 0.8
                )  # Max 0.8 confidence from documentation

                # Create sink node
                return SinkNode(
                    node_id=node_data["node_id"],
                    name=node_data.get("name", "Unknown"),
                    sink_type=sink_type,
                    file_node_id=node_data.get("file_node_id"),
                    function_node_id=node_data.get("node_id"),
                    class_node_id=node_data.get("class_node_id"),
                    line_number=node_data.get("line_number"),
                    description=f"Documentation indicates this is a {sink_type.value}",
                    confidence=confidence,
                    metadata={"documentation": doc_content[:500]},  # Limit size
                )

        return None

    async def analyze_data_flow(
        self, sources: List[SourceNode], sinks: List[SinkNode], investigation_id: str
    ) -> List[DataFlowPath]:
        """Analyze potential data flow paths between sources and sinks using documentation.

        Args:
            sources: List of identified source nodes
            sinks: List of identified sink nodes
            investigation_id: ID of the investigation

        Returns:
            List of potential data flow paths
        """
        # Documentation analyzer is limited in detecting data flows
        # It mainly looks for connections mentioned in documentation
        data_flow_paths: List[DataFlowPath] = []

        # Query for explicit connections in the graph
        for source in sources:
            for sink in sinks:
                # Check if there's a CALLS relationship between source and sink
                query = """
                MATCH (source) WHERE id(source) = $source_id
                MATCH (sink) WHERE id(sink) = $sink_id
                MATCH path = (source)-[:CALLS*1..3]->(sink)
                RETURN path
                """

                results = self._connector.run_query(
                    query, {"source_id": source.node_id, "sink_id": sink.node_id}
                )

                if results:
                    # There's a direct calling relationship, create a data flow path
                    path = DataFlowPath(
                        source_node=source,
                        sink_node=sink,
                        vulnerability_type=f"Potential data flow from {source.source_type.value} to {sink.sink_type.value}",
                        impact=DataFlowImpact.MEDIUM,  # Default impact
                        description=f"The function {source.name} calls {sink.name}, creating a potential flow of untrusted data.",
                        recommendations=[
                            "Verify proper data validation between source and sink"
                        ],
                        confidence=0.6,  # Medium confidence for graph-based connections
                    )

                    data_flow_paths.append(path)

        return data_flow_paths


class SourcesAndSinksWorkflow(Workflow):
    """Workflow for identifying sources and sinks in code repositories."""

    def __init__(
        self,
        llm_client: Optional[OpenAIClient] = None,
        investigation_id: Optional[str] = None,
        name: str = "Sources and Sinks Analysis",
        description: str = "Identifies potential sources and sinks in code repositories",
    ):
        """Initialize the sources and sinks workflow.

        Args:
            llm_client: LLM client for analysis (required)
            investigation_id: ID of the investigation to analyze (optional)
            name: Name of the workflow
            description: Description of the workflow
        """
        super().__init__(name=name, description=description)
        self.llm_client = llm_client
        self.investigation_id = investigation_id

        # Initialize funnels and analyzers
        self.funnels: List[FunnelQuery] = []
        self.analyzers: List[Analyzer] = []

        # Results
        self.result: Optional[SourcesAndSinksResult] = None

    def register_funnel(self, funnel: FunnelQuery) -> None:
        """Register a funnel query.

        Args:
            funnel: Funnel query to register
        """
        self.funnels.append(funnel)
        logger.info(f"Registered funnel: {funnel.name}")

    def register_analyzer(self, analyzer: Analyzer) -> None:
        """Register an analyzer.

        Args:
            analyzer: Analyzer to register
        """
        self.analyzers.append(analyzer)
        logger.info(f"Registered analyzer: {analyzer.name}")

    async def setup(self) -> None:
        """Set up the workflow with default funnels and analyzers."""
        # Register default funnel
        self.register_funnel(CodeSummaryFunnel(connector=self.connector))

        # Register default analyzers if LLM client is provided
        if self.llm_client:
            self.register_analyzer(
                LLMAnalyzer(llm_client=self.llm_client, connector=self.connector)
            )

        # Register documentation analyzer
        self.register_analyzer(DocumentationAnalyzer(connector=self.connector))

        logger.info(
            f"Setup complete with {len(self.funnels)} funnels and {len(self.analyzers)} analyzers"
        )

    async def query_codebase(self) -> Dict[str, List[Dict[str, Any]]]:
        """Query the codebase for potential sources and sinks.

        Returns:
            Dictionary with potential source and sink node data
        """
        if not self.investigation_id:
            raise ValueError("Investigation ID is required for the workflow")

        # Verify investigation exists
        query = """
        MATCH (i:Investigation {id: $investigation_id})
        RETURN i
        """

        results = self.connector.run_query(
            query, {"investigation_id": self.investigation_id}
        )
        if not results:
            raise ValueError(f"Investigation {self.investigation_id} not found")

        # Query for potential sources and sinks using registered funnels
        potential_sources = []
        potential_sinks = []

        for funnel in self.funnels:
            # Query for potential sources
            logger.info(f"Querying for potential sources using {funnel.name}")
            sources = await funnel.query_sources(self.investigation_id)
            potential_sources.extend(sources)

            # Query for potential sinks
            logger.info(f"Querying for potential sinks using {funnel.name}")
            sinks = await funnel.query_sinks(self.investigation_id)
            potential_sinks.extend(sinks)

        logger.info(
            f"Found {len(potential_sources)} potential source nodes and {len(potential_sinks)} potential sink nodes"
        )

        return {
            "potential_sources": potential_sources,
            "potential_sinks": potential_sinks,
        }

    async def analyze_code(
        self,
        potential_sources: List[Dict[str, Any]],
        potential_sinks: List[Dict[str, Any]],
    ) -> Dict[str, List[Any]]:
        """Analyze potential sources and sinks to determine if they are valid.

        Args:
            potential_sources: List of potential source node data
            potential_sinks: List of potential sink node data

        Returns:
            Dictionary with confirmed sources, sinks, and data flow paths
        """
        if not self.analyzers:
            logger.warning("No analyzers registered")
            return {"sources": [], "sinks": [], "data_flow_paths": [], "summary": ""}

        sources = []
        sinks = []

        # Analyze potential sources
        for node_data in potential_sources:
            for analyzer in self.analyzers:
                logger.debug(
                    f"Analyzing potential source {node_data.get('name', 'Unknown')} with {analyzer.name}"
                )
                source = await analyzer.analyze_source(node_data, self.investigation_id)
                if source:
                    sources.append(source)
                    break  # If one analyzer confirms it's a source, we don't need to check others

        # Analyze potential sinks
        for node_data in potential_sinks:
            for analyzer in self.analyzers:
                logger.debug(
                    f"Analyzing potential sink {node_data.get('name', 'Unknown')} with {analyzer.name}"
                )
                sink = await analyzer.analyze_sink(node_data, self.investigation_id)
                if sink:
                    sinks.append(sink)
                    break  # If one analyzer confirms it's a sink, we don't need to check others

        logger.info(
            f"Identified {len(sources)} confirmed sources and {len(sinks)} confirmed sinks"
        )

        # Analyze data flow paths
        data_flow_paths = []

        for analyzer in self.analyzers:
            logger.info(f"Analyzing data flow paths with {analyzer.name}")
            paths = await analyzer.analyze_data_flow(
                sources, sinks, self.investigation_id
            )
            data_flow_paths.extend(paths)

        logger.info(f"Identified {len(data_flow_paths)} potential data flow paths")

        # Generate summary if LLM analyzer is available
        summary = ""
        for analyzer in self.analyzers:
            if isinstance(analyzer, LLMAnalyzer):
                logger.info("Generating summary with LLM analyzer")
                summary = await analyzer.generate_summary(
                    sources, sinks, data_flow_paths, self.investigation_id
                )
                break

        return {
            "sources": sources,
            "sinks": sinks,
            "data_flow_paths": data_flow_paths,
            "summary": summary,
        }

    async def update_graph(
        self,
        sources: List[SourceNode],
        sinks: List[SinkNode],
        data_flow_paths: List[DataFlowPath],
    ) -> None:
        """Update the graph with sources, sinks, and data flow paths.

        Args:
            sources: List of confirmed source nodes
            sinks: List of confirmed sink nodes
            data_flow_paths: List of confirmed data flow paths
        """
        if not self.investigation_id:
            raise ValueError("Investigation ID is required for the workflow")

        # Create Source nodes in the graph
        for source in sources:
            # Create Source node
            source_properties = {
                "name": source.name,
                "source_type": source.source_type.value,
                "description": source.description,
                "confidence": source.confidence,
                "metadata": json.dumps(source.metadata),
            }

            # Add optional properties
            if source.line_number is not None:
                source_properties["line_number"] = source.line_number

            # Create Source node
            query = """
            MATCH (i:Investigation {id: $investigation_id})
            MATCH (func) WHERE id(func) = $function_node_id
            MATCH (file) WHERE id(file) = $file_node_id
            CREATE (s:Source $properties)
            CREATE (s)-[:DEFINED_IN]->(file)
            CREATE (s)-[:REPRESENTS]->(func)
            CREATE (i)-[:HAS_SOURCE]->(s)
            RETURN id(s) AS source_graph_id
            """

            params = {
                "investigation_id": self.investigation_id,
                "function_node_id": source.node_id,
                "file_node_id": source.file_node_id,
                "properties": source_properties,
            }

            result = self.connector.run_query(query, params)
            if result:
                source_graph_id = result[0].get("source_graph_id")
                logger.info(f"Created Source node in graph with ID: {source_graph_id}")

                # Add class relationship if applicable
                if source.class_node_id is not None:
                    query = """
                    MATCH (s:Source) WHERE id(s) = $source_graph_id
                    MATCH (c:Class) WHERE id(c) = $class_node_id
                    CREATE (s)-[:BELONGS_TO]->(c)
                    """

                    self.connector.run_query(
                        query,
                        {
                            "source_graph_id": source_graph_id,
                            "class_node_id": source.class_node_id,
                        },
                    )

        # Create Sink nodes in the graph
        for sink in sinks:
            # Create Sink node
            sink_properties = {
                "name": sink.name,
                "sink_type": sink.sink_type.value,
                "description": sink.description,
                "confidence": sink.confidence,
                "metadata": json.dumps(sink.metadata),
            }

            # Add optional properties
            if sink.line_number is not None:
                sink_properties["line_number"] = sink.line_number

            # Create Sink node
            query = """
            MATCH (i:Investigation {id: $investigation_id})
            MATCH (func) WHERE id(func) = $function_node_id
            MATCH (file) WHERE id(file) = $file_node_id
            CREATE (s:Sink $properties)
            CREATE (s)-[:DEFINED_IN]->(file)
            CREATE (s)-[:REPRESENTS]->(func)
            CREATE (i)-[:HAS_SINK]->(s)
            RETURN id(s) AS sink_graph_id
            """

            params = {
                "investigation_id": self.investigation_id,
                "function_node_id": sink.node_id,
                "file_node_id": sink.file_node_id,
                "properties": sink_properties,
            }

            result = self.connector.run_query(query, params)
            if result:
                sink_graph_id = result[0].get("sink_graph_id")
                logger.info(f"Created Sink node in graph with ID: {sink_graph_id}")

                # Add class relationship if applicable
                if sink.class_node_id is not None:
                    query = """
                    MATCH (s:Sink) WHERE id(s) = $sink_graph_id
                    MATCH (c:Class) WHERE id(c) = $class_node_id
                    CREATE (s)-[:BELONGS_TO]->(c)
                    """

                    self.connector.run_query(
                        query,
                        {
                            "sink_graph_id": sink_graph_id,
                            "class_node_id": sink.class_node_id,
                        },
                    )

        # Create DataFlowPath nodes in the graph
        for path in data_flow_paths:
            # Create DataFlowPath node
            path_properties = {
                "vulnerability_type": path.vulnerability_type,
                "impact": path.impact.value,
                "description": path.description,
                "recommendations": json.dumps(path.recommendations),
                "confidence": path.confidence,
                "metadata": json.dumps(path.metadata),
            }

            # First, find the Source and Sink nodes we created
            source_query = """
            MATCH (i:Investigation {id: $investigation_id})
            MATCH (i)-[:HAS_SOURCE]->(s:Source)-[:REPRESENTS]->(func)
            WHERE id(func) = $function_node_id
            RETURN id(s) AS source_graph_id
            """

            source_result = self.connector.run_query(
                source_query,
                {
                    "investigation_id": self.investigation_id,
                    "function_node_id": path.source_node.node_id,
                },
            )

            sink_query = """
            MATCH (i:Investigation {id: $investigation_id})
            MATCH (i)-[:HAS_SINK]->(s:Sink)-[:REPRESENTS]->(func)
            WHERE id(func) = $function_node_id
            RETURN id(s) AS sink_graph_id
            """

            sink_result = self.connector.run_query(
                sink_query,
                {
                    "investigation_id": self.investigation_id,
                    "function_node_id": path.sink_node.node_id,
                },
            )

            if source_result and sink_result:
                source_graph_id = source_result[0].get("source_graph_id")
                sink_graph_id = sink_result[0].get("sink_graph_id")

                # Create DataFlowPath node and relationships
                query = """
                MATCH (i:Investigation {id: $investigation_id})
                MATCH (source) WHERE id(source) = $source_graph_id
                MATCH (sink) WHERE id(sink) = $sink_graph_id
                CREATE (p:DataFlowPath $properties)
                CREATE (source)-[:FLOWS_TO]->(p)
                CREATE (p)-[:FLOWS_TO]->(sink)
                CREATE (i)-[:HAS_DATA_FLOW_PATH]->(p)
                RETURN id(p) AS path_graph_id
                """

                params = {
                    "investigation_id": self.investigation_id,
                    "source_graph_id": source_graph_id,
                    "sink_graph_id": sink_graph_id,
                    "properties": path_properties,
                }

                result = self.connector.run_query(query, params)
                if result:
                    path_graph_id = result[0].get("path_graph_id")
                    logger.info(
                        f"Created DataFlowPath node in graph with ID: {path_graph_id}"
                    )

        logger.info(
            f"Updated graph with {len(sources)} sources, {len(sinks)} sinks, and {len(data_flow_paths)} data flow paths"
        )

    async def generate_report(
        self,
        sources: List[SourceNode],
        sinks: List[SinkNode],
        data_flow_paths: List[DataFlowPath],
        summary: str,
    ) -> SourcesAndSinksResult:
        """Generate a report of the sources and sinks analysis.

        Args:
            sources: List of confirmed source nodes
            sinks: List of confirmed sink nodes
            data_flow_paths: List of confirmed data flow paths
            summary: Summary of the analysis

        Returns:
            SourcesAndSinksResult object
        """
        if not self.investigation_id:
            raise ValueError("Investigation ID is required for the workflow")

        # Create SourcesAndSinksResult
        result = SourcesAndSinksResult(
            investigation_id=self.investigation_id,
            sources=sources,
            sinks=sinks,
            data_flow_paths=data_flow_paths,
            summary=summary,
            metadata={
                "workflow_name": self.name,
                "workflow_description": self.description,
                "timestamp": self._get_timestamp(),
                "funnels": [funnel.name for funnel in self.funnels],
                "analyzers": [analyzer.name for analyzer in self.analyzers],
            },
        )

        return result

    async def run(self, *args: Any, **kwargs: Any) -> SourcesAndSinksResult:
        """Run the sources and sinks workflow.

        Args:
            *args: Positional arguments
            **kwargs: Keyword arguments including:
                - investigation_id: ID of the investigation to analyze
                - llm_client: LLM client for analysis

        Returns:
            SourcesAndSinksResult object
        """
        # Get investigation ID if provided
        if "investigation_id" in kwargs:
            self.investigation_id = kwargs["investigation_id"]

        # Get LLM client if provided
        if "llm_client" in kwargs:
            self.llm_client = kwargs["llm_client"]

        if not self.investigation_id:
            raise ValueError("Investigation ID is required for the workflow")

        if not self.llm_client:
            raise ValueError("LLM client is required for the workflow")

        # Setup the workflow
        await self.setup()

        # Step 1: Query codebase
        logger.info("Step 1: Querying codebase for potential sources and sinks")
        query_results = await self.query_codebase()
        potential_sources = query_results["potential_sources"]
        potential_sinks = query_results["potential_sinks"]

        # Step 2: Analyze code
        logger.info("Step 2: Analyzing potential sources and sinks")
        analysis_results = await self.analyze_code(potential_sources, potential_sinks)
        sources = analysis_results["sources"]
        sinks = analysis_results["sinks"]
        data_flow_paths = analysis_results["data_flow_paths"]
        summary = analysis_results["summary"]

        # Step 3: Update graph
        logger.info("Step 3: Updating graph with sources and sinks")
        await self.update_graph(sources, sinks, data_flow_paths)

        # Step 4: Generate report
        logger.info("Step 4: Generating report")
        self.result = await self.generate_report(
            sources, sinks, data_flow_paths, summary
        )

        return self.result

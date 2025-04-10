"""Unit tests for the sources and sinks workflow module."""

import pytest
from unittest.mock import MagicMock, AsyncMock, patch
import json
from enum import Enum
from typing import Dict, List, Any, Optional

from skwaq.workflows.sources_and_sinks import (
    SourceSinkType,
    DataFlowImpact,
    SourceNode,
    SinkNode,
    DataFlowPath,
    SourcesAndSinksResult,
    FunnelQuery,
    CodeSummaryFunnel,
    Analyzer,
    LLMAnalyzer,
    DocumentationAnalyzer,
    SourcesAndSinksWorkflow,
)


class TestSourcesAndSinksDataModels:
    """Tests for the data models in the sources and sinks module."""

    def test_source_node_serialization(self):
        """Test serialization and deserialization of SourceNode."""
        # Create a source node
        source_node = SourceNode(
            node_id=123,
            name="get_user_input",
            source_type=SourceSinkType.USER_INPUT,
            file_node_id=456,
            function_node_id=123,
            class_node_id=789,
            line_number=42,
            description="Gets input from the user",
            confidence=0.8,
            metadata={"key": "value"},
        )

        # Convert to dict
        source_dict = source_node.to_dict()

        # Verify serialization
        assert source_dict["node_id"] == 123
        assert source_dict["name"] == "get_user_input"
        assert source_dict["source_type"] == "user_input"
        assert source_dict["file_node_id"] == 456
        assert source_dict["function_node_id"] == 123
        assert source_dict["class_node_id"] == 789
        assert source_dict["line_number"] == 42
        assert source_dict["description"] == "Gets input from the user"
        assert source_dict["confidence"] == 0.8
        assert source_dict["metadata"] == {"key": "value"}

        # Deserialize back to source node
        recreated_source = SourceNode.from_dict(source_dict)

        # Verify deserialization
        assert recreated_source.node_id == source_node.node_id
        assert recreated_source.name == source_node.name
        assert recreated_source.source_type == source_node.source_type
        assert recreated_source.file_node_id == source_node.file_node_id
        assert recreated_source.function_node_id == source_node.function_node_id
        assert recreated_source.class_node_id == source_node.class_node_id
        assert recreated_source.line_number == source_node.line_number
        assert recreated_source.description == source_node.description
        assert recreated_source.confidence == source_node.confidence
        assert recreated_source.metadata == source_node.metadata

    def test_sink_node_serialization(self):
        """Test serialization and deserialization of SinkNode."""
        # Create a sink node
        sink_node = SinkNode(
            node_id=123,
            name="execute_sql_query",
            sink_type=SourceSinkType.DATABASE_WRITE,
            file_node_id=456,
            function_node_id=123,
            class_node_id=789,
            line_number=42,
            description="Executes an SQL query",
            confidence=0.9,
            metadata={"key": "value"},
        )

        # Convert to dict
        sink_dict = sink_node.to_dict()

        # Verify serialization
        assert sink_dict["node_id"] == 123
        assert sink_dict["name"] == "execute_sql_query"
        assert sink_dict["sink_type"] == "database_write"
        assert sink_dict["file_node_id"] == 456
        assert sink_dict["function_node_id"] == 123
        assert sink_dict["class_node_id"] == 789
        assert sink_dict["line_number"] == 42
        assert sink_dict["description"] == "Executes an SQL query"
        assert sink_dict["confidence"] == 0.9
        assert sink_dict["metadata"] == {"key": "value"}

        # Deserialize back to sink node
        recreated_sink = SinkNode.from_dict(sink_dict)

        # Verify deserialization
        assert recreated_sink.node_id == sink_node.node_id
        assert recreated_sink.name == sink_node.name
        assert recreated_sink.sink_type == sink_node.sink_type
        assert recreated_sink.file_node_id == sink_node.file_node_id
        assert recreated_sink.function_node_id == sink_node.function_node_id
        assert recreated_sink.class_node_id == sink_node.class_node_id
        assert recreated_sink.line_number == sink_node.line_number
        assert recreated_sink.description == sink_node.description
        assert recreated_sink.confidence == sink_node.confidence
        assert recreated_sink.metadata == sink_node.metadata

    def test_data_flow_path_serialization(self):
        """Test serialization and deserialization of DataFlowPath."""
        # Create source and sink nodes
        source_node = SourceNode(
            node_id=123,
            name="get_user_input",
            source_type=SourceSinkType.USER_INPUT,
            file_node_id=456,
        )

        sink_node = SinkNode(
            node_id=789,
            name="execute_sql_query",
            sink_type=SourceSinkType.DATABASE_WRITE,
            file_node_id=456,
        )

        # Create data flow path
        data_flow_path = DataFlowPath(
            source_node=source_node,
            sink_node=sink_node,
            intermediate_nodes=[101, 102],
            vulnerability_type="SQL Injection",
            impact=DataFlowImpact.HIGH,
            description="User input flows to SQL query without sanitization",
            recommendations=["Use parameterized queries", "Sanitize input data"],
            confidence=0.85,
            metadata={"key": "value"},
        )

        # Convert to dict
        path_dict = data_flow_path.to_dict()

        # Verify serialization
        assert path_dict["source_node"]["node_id"] == 123
        assert path_dict["sink_node"]["node_id"] == 789
        assert path_dict["intermediate_nodes"] == [101, 102]
        assert path_dict["vulnerability_type"] == "SQL Injection"
        assert path_dict["impact"] == "high"
        assert (
            path_dict["description"]
            == "User input flows to SQL query without sanitization"
        )
        assert path_dict["recommendations"] == [
            "Use parameterized queries",
            "Sanitize input data",
        ]
        assert path_dict["confidence"] == 0.85
        assert path_dict["metadata"] == {"key": "value"}

        # Deserialize back to data flow path
        recreated_path = DataFlowPath.from_dict(path_dict)

        # Verify deserialization
        assert recreated_path.source_node.node_id == source_node.node_id
        assert recreated_path.source_node.name == source_node.name
        assert recreated_path.source_node.source_type == source_node.source_type
        assert recreated_path.sink_node.node_id == sink_node.node_id
        assert recreated_path.sink_node.name == sink_node.name
        assert recreated_path.sink_node.sink_type == sink_node.sink_type
        assert recreated_path.intermediate_nodes == data_flow_path.intermediate_nodes
        assert recreated_path.vulnerability_type == data_flow_path.vulnerability_type
        assert recreated_path.impact == data_flow_path.impact
        assert recreated_path.description == data_flow_path.description
        assert recreated_path.recommendations == data_flow_path.recommendations
        assert recreated_path.confidence == data_flow_path.confidence
        assert recreated_path.metadata == data_flow_path.metadata

    def test_sources_and_sinks_result_serialization(self):
        """Test serialization methods of SourcesAndSinksResult."""
        # Create source and sink nodes
        source_node = SourceNode(
            node_id=123,
            name="get_user_input",
            source_type=SourceSinkType.USER_INPUT,
            file_node_id=456,
        )

        sink_node = SinkNode(
            node_id=789,
            name="execute_sql_query",
            sink_type=SourceSinkType.DATABASE_WRITE,
            file_node_id=456,
        )

        # Create data flow path
        data_flow_path = DataFlowPath(
            source_node=source_node,
            sink_node=sink_node,
            vulnerability_type="SQL Injection",
            impact=DataFlowImpact.HIGH,
            description="User input flows to SQL query without sanitization",
        )

        # Create result
        result = SourcesAndSinksResult(
            investigation_id="inv-123",
            sources=[source_node],
            sinks=[sink_node],
            data_flow_paths=[data_flow_path],
            summary="Analysis found potential SQL injection vulnerability",
            metadata={"timestamp": "2023-01-01T00:00:00"},
        )

        # Test to_dict method
        result_dict = result.to_dict()
        assert result_dict["investigation_id"] == "inv-123"
        assert len(result_dict["sources"]) == 1
        assert len(result_dict["sinks"]) == 1
        assert len(result_dict["data_flow_paths"]) == 1
        assert (
            result_dict["summary"]
            == "Analysis found potential SQL injection vulnerability"
        )
        assert result_dict["metadata"] == {"timestamp": "2023-01-01T00:00:00"}

        # Test to_json method
        json_str = result.to_json()
        parsed_json = json.loads(json_str)
        assert parsed_json["investigation_id"] == "inv-123"

        # Test to_markdown method
        markdown = result.to_markdown()
        assert "# Sources and Sinks Analysis Results" in markdown
        assert "## Investigation ID: inv-123" in markdown
        assert "## Sources (1)" in markdown
        assert "## Sinks (1)" in markdown
        assert "## Data Flow Paths (1)" in markdown
        assert "### Path 1: SQL Injection" in markdown
        assert "**Impact**: high" in markdown


class MockCodeSummaryFunnel(FunnelQuery):
    """Mock implementation of CodeSummaryFunnel for testing."""

    async def query_sources(self, investigation_id: str) -> List[Dict[str, Any]]:
        """Return mock source data."""
        return [
            {
                "node_id": 1,
                "name": "get_user_data",
                "file_node_id": 101,
                "line_number": 42,
                "description": "Gets user data from the form",
                "file_path": "/src/app/forms.py",
            }
        ]

    async def query_sinks(self, investigation_id: str) -> List[Dict[str, Any]]:
        """Return mock sink data."""
        return [
            {
                "node_id": 2,
                "name": "execute_query",
                "file_node_id": 102,
                "line_number": 55,
                "description": "Executes a database query",
                "file_path": "/src/app/db.py",
            }
        ]


class MockAnalyzer(Analyzer):
    """Mock implementation of Analyzer for testing."""

    async def analyze_source(
        self, node_data: Dict[str, Any], investigation_id: str
    ) -> Optional[SourceNode]:
        """Analyze if a node is a source."""
        return SourceNode(
            node_id=node_data["node_id"],
            name=node_data["name"],
            source_type=SourceSinkType.USER_INPUT,
            file_node_id=node_data["file_node_id"],
            line_number=node_data.get("line_number"),
            description=node_data.get("description", ""),
            confidence=0.8,
        )

    async def analyze_sink(
        self, node_data: Dict[str, Any], investigation_id: str
    ) -> Optional[SinkNode]:
        """Analyze if a node is a sink."""
        return SinkNode(
            node_id=node_data["node_id"],
            name=node_data["name"],
            sink_type=SourceSinkType.DATABASE_WRITE,
            file_node_id=node_data["file_node_id"],
            line_number=node_data.get("line_number"),
            description=node_data.get("description", ""),
            confidence=0.8,
        )

    async def analyze_data_flow(
        self, sources: List[SourceNode], sinks: List[SinkNode], investigation_id: str
    ) -> List[DataFlowPath]:
        """Analyze potential data flow paths between sources and sinks."""
        if not sources or not sinks:
            return []

        return [
            DataFlowPath(
                source_node=sources[0],
                sink_node=sinks[0],
                vulnerability_type="SQL Injection",
                impact=DataFlowImpact.HIGH,
                description="User input flows to SQL query without sanitization",
                recommendations=["Use parameterized queries", "Sanitize input"],
                confidence=0.7,
            )
        ]


@pytest.fixture
def mock_llm_client():
    """Create a mock LLM client."""
    client = AsyncMock()

    # Configure the mock to return different responses based on the prompt
    async def mock_chat_completion(messages=None, **kwargs):
        system_message = (
            messages[0]["content"] if messages and len(messages) > 0 else ""
        )
        user_message = messages[1]["content"] if messages and len(messages) > 1 else ""

        # Check if this is a sink analysis request
        if "sink" in system_message.lower():
            return {
                "content": "This function is a sink that executes SQL queries. It directly writes data to a database without proper sanitization, which could be vulnerable to SQL injection attacks."
            }
        # Default response for source analysis
        else:
            return {
                "content": "This is a source function that gets user input from a form."
            }

    client.chat_completion = AsyncMock(side_effect=mock_chat_completion)
    return client


@pytest.mark.asyncio
class TestSourcesAndSinksWorkflow:
    """Tests for the SourcesAndSinksWorkflow class."""

    async def test_workflow_initialization(self, mock_connector):
        """Test workflow initialization."""
        # Mock the get_connector function in the Workflow base class
        with patch("skwaq.workflows.base.get_connector") as mock_get_connector:
            mock_get_connector.return_value = mock_connector

            # Create a mock LLM client
            mock_llm_client = AsyncMock()

            workflow = SourcesAndSinksWorkflow(
                llm_client=mock_llm_client,
                investigation_id="inv-123",
                name="Test Sources and Sinks",
                description="Test workflow",
            )

            assert workflow.name == "Test Sources and Sinks"
            assert workflow.description == "Test workflow"
            assert workflow.llm_client is mock_llm_client
            assert workflow.investigation_id == "inv-123"
            assert workflow.connector is mock_connector
            assert workflow.funnels == []
            assert workflow.analyzers == []
            assert workflow.result is None

    async def test_workflow_setup(self, mock_connector, mock_llm_client):
        """Test workflow setup with default funnels and analyzers."""
        # Mock the get_connector function in both the base Workflow and the CodeSummaryFunnel
        with patch("skwaq.workflows.base.get_connector") as mock_get_connector:
            mock_get_connector.return_value = mock_connector

            workflow = SourcesAndSinksWorkflow(
                llm_client=mock_llm_client, investigation_id="inv-123"
            )

            # Mock the connector initialization in the analyzers
            with patch(
                "skwaq.workflows.sources_and_sinks.get_connector"
            ) as mock_get_analyzer_connector:
                mock_get_analyzer_connector.return_value = mock_connector

                await workflow.setup()

                assert len(workflow.funnels) == 1
                assert isinstance(workflow.funnels[0], CodeSummaryFunnel)

                assert len(workflow.analyzers) == 2
                assert isinstance(workflow.analyzers[0], LLMAnalyzer)
                assert isinstance(workflow.analyzers[1], DocumentationAnalyzer)

    async def test_register_funnel_and_analyzer(self, mock_connector):
        """Test registering custom funnels and analyzers."""
        with patch("skwaq.workflows.base.get_connector") as mock_get_connector:
            mock_get_connector.return_value = mock_connector

            # Create a mock LLM client
            mock_llm_client = AsyncMock()

            workflow = SourcesAndSinksWorkflow(
                llm_client=mock_llm_client, investigation_id="inv-123"
            )

            # Register custom funnel and analyzer
            funnel = MockCodeSummaryFunnel()
            analyzer = MockAnalyzer()

            workflow.register_funnel(funnel)
            workflow.register_analyzer(analyzer)

            assert len(workflow.funnels) == 1
            assert workflow.funnels[0] is funnel

            assert len(workflow.analyzers) == 1
            assert workflow.analyzers[0] is analyzer

    async def test_query_codebase(self, mock_connector):
        """Test querying codebase for potential sources and sinks."""
        with patch("skwaq.workflows.base.get_connector") as mock_get_connector:
            mock_get_connector.return_value = mock_connector

            # Mock the connector to return investigation data
            mock_connector.run_query.return_value = [{"i": {"id": "inv-123"}}]

            # Create a mock LLM client
            mock_llm_client = AsyncMock()

            # Create workflow
            workflow = SourcesAndSinksWorkflow(
                llm_client=mock_llm_client, investigation_id="inv-123"
            )

            # Register mock funnel
            funnel = MockCodeSummaryFunnel()
            workflow.register_funnel(funnel)

            # Query codebase
            result = await workflow.query_codebase()

            # Verify results
            assert "potential_sources" in result
            assert "potential_sinks" in result
            assert len(result["potential_sources"]) == 1
            assert len(result["potential_sinks"]) == 1
            assert result["potential_sources"][0]["name"] == "get_user_data"
            assert result["potential_sinks"][0]["name"] == "execute_query"

    async def test_analyze_code(self, mock_connector):
        """Test analyzing potential sources and sinks."""
        with patch("skwaq.workflows.base.get_connector") as mock_get_connector:
            mock_get_connector.return_value = mock_connector

            # Create a mock LLM client
            mock_llm_client = AsyncMock()

            # Create workflow
            workflow = SourcesAndSinksWorkflow(
                llm_client=mock_llm_client, investigation_id="inv-123"
            )

            # Register mock analyzer
            analyzer = MockAnalyzer()
            workflow.register_analyzer(analyzer)

            # Mock potential sources and sinks
            potential_sources = [
                {
                    "node_id": 1,
                    "name": "get_user_data",
                    "file_node_id": 101,
                    "line_number": 42,
                    "description": "Gets user data from the form",
                }
            ]

            potential_sinks = [
                {
                    "node_id": 2,
                    "name": "execute_query",
                    "file_node_id": 102,
                    "line_number": 55,
                    "description": "Executes a database query",
                }
            ]

            # Analyze code
            result = await workflow.analyze_code(potential_sources, potential_sinks)

            # Verify results
            assert "sources" in result
            assert "sinks" in result
            assert "data_flow_paths" in result
            assert len(result["sources"]) == 1
            assert len(result["sinks"]) == 1
            assert len(result["data_flow_paths"]) == 1
            assert result["sources"][0].name == "get_user_data"
            assert result["sinks"][0].name == "execute_query"
            assert result["data_flow_paths"][0].vulnerability_type == "SQL Injection"

    async def test_update_graph(self, mock_connector):
        """Test updating the graph with sources, sinks, and data flow paths."""
        with patch("skwaq.workflows.base.get_connector") as mock_get_connector:
            mock_get_connector.return_value = mock_connector

            # Mock successful graph operations with sequential query results
            mock_connector.run_query.side_effect = [
                [{"source_graph_id": 201}],  # Source creation
                None,  # Class relationship
                [{"sink_graph_id": 202}],  # Sink creation
                None,  # Class relationship
                [{"source_graph_id": 201}],  # Source query
                [{"sink_graph_id": 202}],  # Sink query
                [{"path_graph_id": 203}],  # Path creation
            ]

            # Create a mock LLM client
            mock_llm_client = AsyncMock()

            # Create workflow
            workflow = SourcesAndSinksWorkflow(
                llm_client=mock_llm_client, investigation_id="inv-123"
            )

            # Create source and sink nodes
            source = SourceNode(
                node_id=1,
                name="get_user_data",
                source_type=SourceSinkType.USER_INPUT,
                file_node_id=101,
                class_node_id=301,
                line_number=42,
                description="Gets user data from the form",
            )

            sink = SinkNode(
                node_id=2,
                name="execute_query",
                sink_type=SourceSinkType.DATABASE_WRITE,
                file_node_id=102,
                class_node_id=302,
                line_number=55,
                description="Executes a database query",
            )

            path = DataFlowPath(
                source_node=source,
                sink_node=sink,
                vulnerability_type="SQL Injection",
                impact=DataFlowImpact.HIGH,
                description="User input flows to SQL query without sanitization",
            )

            # Update graph
            await workflow.update_graph([source], [sink], [path])

            # Verify connector calls (simplified check)
            assert mock_connector.run_query.call_count >= 7

    async def test_generate_report(self, mock_connector):
        """Test generating a report of the sources and sinks analysis."""
        with patch("skwaq.workflows.base.get_connector") as mock_get_connector:
            mock_get_connector.return_value = mock_connector

            # Create a mock LLM client
            mock_llm_client = AsyncMock()

            # Create workflow
            workflow = SourcesAndSinksWorkflow(
                llm_client=mock_llm_client, investigation_id="inv-123"
            )

            # Create source and sink nodes
            source = SourceNode(
                node_id=1,
                name="get_user_data",
                source_type=SourceSinkType.USER_INPUT,
                file_node_id=101,
                line_number=42,
                description="Gets user data from the form",
            )

            sink = SinkNode(
                node_id=2,
                name="execute_query",
                sink_type=SourceSinkType.DATABASE_WRITE,
                file_node_id=102,
                line_number=55,
                description="Executes a database query",
            )

            path = DataFlowPath(
                source_node=source,
                sink_node=sink,
                vulnerability_type="SQL Injection",
                impact=DataFlowImpact.HIGH,
                description="User input flows to SQL query without sanitization",
            )

            summary = "Analysis found potential SQL injection vulnerability"

            # Generate report
            result = await workflow.generate_report([source], [sink], [path], summary)

            # Verify result
            assert isinstance(result, SourcesAndSinksResult)
            assert result.investigation_id == "inv-123"
            assert len(result.sources) == 1
            assert len(result.sinks) == 1
            assert len(result.data_flow_paths) == 1
            assert result.summary == summary
            assert "workflow_name" in result.metadata
            assert "workflow_description" in result.metadata
            assert "timestamp" in result.metadata
            assert "funnels" in result.metadata
            assert "analyzers" in result.metadata

    async def test_full_workflow_run(self, mock_connector):
        """Test running the full workflow."""
        with patch("skwaq.workflows.base.get_connector") as mock_get_connector:
            mock_get_connector.return_value = mock_connector

            # Create a mock LLM client
            mock_llm_client = AsyncMock()

            # Mock the stages of the workflow
            with (
                patch.object(SourcesAndSinksWorkflow, "setup") as mock_setup,
                patch.object(SourcesAndSinksWorkflow, "query_codebase") as mock_query,
                patch.object(SourcesAndSinksWorkflow, "analyze_code") as mock_analyze,
                patch.object(SourcesAndSinksWorkflow, "update_graph") as mock_update,
                patch.object(SourcesAndSinksWorkflow, "generate_report") as mock_report,
            ):

                mock_setup.return_value = None

                mock_query.return_value = {
                    "potential_sources": [
                        {"node_id": 1, "name": "get_user_data", "file_node_id": 101}
                    ],
                    "potential_sinks": [
                        {"node_id": 2, "name": "execute_query", "file_node_id": 102}
                    ],
                }

                source = SourceNode(
                    node_id=1,
                    name="get_user_data",
                    source_type=SourceSinkType.USER_INPUT,
                    file_node_id=101,
                )

                sink = SinkNode(
                    node_id=2,
                    name="execute_query",
                    sink_type=SourceSinkType.DATABASE_WRITE,
                    file_node_id=102,
                )

                path = DataFlowPath(
                    source_node=source,
                    sink_node=sink,
                    vulnerability_type="SQL Injection",
                    impact=DataFlowImpact.HIGH,
                    description="User input flows to SQL query without sanitization",
                )

                mock_analyze.return_value = {
                    "sources": [source],
                    "sinks": [sink],
                    "data_flow_paths": [path],
                    "summary": "Analysis found potential SQL injection vulnerability",
                }

                mock_update.return_value = None

                expected_result = SourcesAndSinksResult(
                    investigation_id="inv-123",
                    sources=[source],
                    sinks=[sink],
                    data_flow_paths=[path],
                    summary="Analysis found potential SQL injection vulnerability",
                )

                mock_report.return_value = expected_result

                # Create workflow
                workflow = SourcesAndSinksWorkflow(
                    llm_client=mock_llm_client, investigation_id="inv-123"
                )

                # Run the workflow
                result = await workflow.run()

                # Verify the workflow steps were called
                mock_setup.assert_called_once()
                mock_query.assert_called_once()
                mock_analyze.assert_called_once()
                mock_update.assert_called_once()
                mock_report.assert_called_once()

                # Verify result
                assert result is expected_result


@pytest.mark.asyncio
class TestLLMAnalyzer:
    """Tests for the LLMAnalyzer class."""

    async def test_analyze_source(self, mock_connector, mock_llm_client):
        """Test analyzing if a node is a source using LLM."""
        with patch(
            "skwaq.workflows.sources_and_sinks.get_connector"
        ) as mock_get_connector:
            mock_get_connector.return_value = mock_connector

            # Mock function code retrieval
            mock_connector.run_query.return_value = [
                {
                    "code": "def get_user_input(request):\n    return request.POST.get('username', '')"
                }
            ]

            # Mock LLM response - the mock_llm_client fixture already configures this
            # Set up _prompts property directly
            analyzer = LLMAnalyzer(llm_client=mock_llm_client, connector=mock_connector)
            analyzer._prompts = {"identify_sources": "Identify if this is a source"}

            # Node data to analyze
            node_data = {
                "node_id": 1,
                "name": "get_user_input",
                "file_node_id": 101,
                "line_number": 42,
                "description": "Gets user input from a form",
                "file_path": "/src/app/forms.py",
            }

            # Analyze source
            source_node = await analyzer.analyze_source(node_data, "inv-123")

            # Verify source was identified correctly
            assert source_node is not None
            assert source_node.node_id == 1
            assert source_node.name == "get_user_input"
            assert source_node.file_node_id == 101
            assert source_node.line_number == 42
            assert source_node.confidence > 0
            assert "llm_response" in source_node.metadata

            # Verify method calls
            mock_llm_client.chat_completion.assert_called_once()

    async def test_analyze_sink(self, mock_connector, mock_llm_client):
        """Test analyzing if a node is a sink using LLM."""
        with patch(
            "skwaq.workflows.sources_and_sinks.get_connector"
        ) as mock_get_connector:
            mock_get_connector.return_value = mock_connector

            # Mock function code retrieval
            mock_connector.run_query.return_value = [
                {
                    "code": "def execute_query(sql):\n    conn = get_db_connection()\n    return conn.execute(sql)"
                }
            ]

            # Mock LLM response - the mock_llm_client fixture already configures this
            # Set up _prompts property directly
            analyzer = LLMAnalyzer(llm_client=mock_llm_client, connector=mock_connector)
            analyzer._prompts = {"identify_sinks": "Identify if this is a sink"}

            # Node data to analyze
            node_data = {
                "node_id": 2,
                "name": "execute_query",
                "file_node_id": 102,
                "line_number": 55,
                "description": "Executes a database query",
                "file_path": "/src/app/db.py",
            }

            # Analyze sink
            sink_node = await analyzer.analyze_sink(node_data, "inv-123")

            # Verify sink was identified
            assert sink_node is not None
            assert sink_node.node_id == 2
            assert sink_node.name == "execute_query"
            assert sink_node.file_node_id == 102
            assert sink_node.line_number == 55
            assert "llm_response" in sink_node.metadata

            # Verify method calls
            mock_llm_client.chat_completion.assert_called_once()

    async def test_analyze_data_flow(self, mock_connector, mock_llm_client):
        """Test analyzing data flow between sources and sinks using LLM."""
        with patch(
            "skwaq.workflows.sources_and_sinks.get_connector"
        ) as mock_get_connector:
            mock_get_connector.return_value = mock_connector

            # Mock function code retrieval and file path query
            mock_connector.run_query.side_effect = [
                [{"file_path": "/src/app/forms.py"}],  # File path query
                [
                    {
                        "code": "def get_user_input(request):\n    return request.POST.get('username', '')"
                    }
                ],  # Source code
                [
                    {
                        "code": "def execute_query(sql):\n    conn = get_db_connection()\n    return conn.execute(sql)"
                    }
                ],  # Sink code
            ]

            # Set up analyzer with directly configured prompts
            analyzer = LLMAnalyzer(llm_client=mock_llm_client, connector=mock_connector)
            analyzer._prompts = {
                "analyze_data_flow": "Analyze data flow between sources and sinks"
            }

            # Create source and sink nodes
            source = SourceNode(
                node_id=1,
                name="get_user_input",
                source_type=SourceSinkType.USER_INPUT,
                file_node_id=101,
            )

            sink = SinkNode(
                node_id=2,
                name="execute_query",
                sink_type=SourceSinkType.DATABASE_WRITE,
                file_node_id=101,  # Same file_node_id as the source for this test
            )

            # Analyze data flow
            paths = await analyzer.analyze_data_flow([source], [sink], "inv-123")

            # Verify method calls - even if no paths were identified, the call should have been made
            mock_llm_client.chat_completion.assert_called_once()

    async def test_generate_summary(self, mock_connector, mock_llm_client):
        """Test generating a summary of the sources and sinks analysis."""
        with patch(
            "skwaq.workflows.sources_and_sinks.get_connector"
        ) as mock_get_connector:
            mock_get_connector.return_value = mock_connector

            # Set up analyzer with directly configured prompts
            analyzer = LLMAnalyzer(llm_client=mock_llm_client, connector=mock_connector)
            analyzer._prompts = {
                "summarize_results": "Summarize the sources and sinks analysis"
            }

            # Create source and sink nodes
            source = SourceNode(
                node_id=1,
                name="get_user_input",
                source_type=SourceSinkType.USER_INPUT,
                file_node_id=101,
            )

            sink = SinkNode(
                node_id=2,
                name="execute_query",
                sink_type=SourceSinkType.DATABASE_WRITE,
                file_node_id=102,
            )

            path = DataFlowPath(
                source_node=source,
                sink_node=sink,
                vulnerability_type="SQL Injection",
                impact=DataFlowImpact.HIGH,
                description="User input flows to SQL query without sanitization",
            )

            # Generate summary
            summary = await analyzer.generate_summary(
                [source], [sink], [path], "inv-123"
            )

            # Verify summary generation
            assert summary is not None
            assert len(summary) > 0

            # Verify method calls
            mock_llm_client.chat_completion.assert_called_once()


@pytest.mark.asyncio
class TestDocumentationAnalyzer:
    """Tests for the DocumentationAnalyzer class."""

    async def test_analyze_source(self, mock_connector):
        """Test analyzing if a node is a source using documentation."""
        with patch(
            "skwaq.workflows.sources_and_sinks.get_connector"
        ) as mock_get_connector:
            mock_get_connector.return_value = mock_connector

            # Mock documentation retrieval
            mock_connector.run_query.return_value = [
                {
                    "doc_content": "This function gets user input from a form and returns it."
                }
            ]

            # Create analyzer
            analyzer = DocumentationAnalyzer(connector=mock_connector)

            # Node data to analyze
            node_data = {
                "node_id": 1,
                "name": "get_user_input",
                "file_node_id": 101,
                "line_number": 42,
                "description": "Gets user input from a form",
            }

            # Analyze source
            source_node = await analyzer.analyze_source(node_data, "inv-123")

            # Verify source was identified correctly
            assert source_node is not None
            assert source_node.node_id == 1
            assert source_node.name == "get_user_input"
            assert source_node.source_type == SourceSinkType.USER_INPUT
            assert source_node.file_node_id == 101
            assert source_node.line_number == 42
            assert source_node.confidence > 0
            assert "documentation" in source_node.metadata

    async def test_analyze_sink(self, mock_connector):
        """Test analyzing if a node is a sink using documentation."""
        with patch(
            "skwaq.workflows.sources_and_sinks.get_connector"
        ) as mock_get_connector:
            mock_get_connector.return_value = mock_connector

            # Mock documentation retrieval
            mock_connector.run_query.return_value = [
                {"doc_content": "This function executes an SQL query on the database."}
            ]

            # Create analyzer
            analyzer = DocumentationAnalyzer(connector=mock_connector)

            # Node data to analyze
            node_data = {
                "node_id": 2,
                "name": "execute_query",
                "file_node_id": 102,
                "line_number": 55,
                "description": "Executes a database query",
            }

            # Analyze sink
            sink_node = await analyzer.analyze_sink(node_data, "inv-123")

            # Verify sink was identified correctly
            assert sink_node is not None
            assert sink_node.node_id == 2
            assert sink_node.name == "execute_query"
            assert sink_node.sink_type == SourceSinkType.DATABASE_WRITE
            assert sink_node.file_node_id == 102
            assert sink_node.line_number == 55
            assert sink_node.confidence > 0
            assert "documentation" in sink_node.metadata

    async def test_analyze_data_flow(self, mock_connector):
        """Test analyzing data flow between sources and sinks using documentation."""
        with patch(
            "skwaq.workflows.sources_and_sinks.get_connector"
        ) as mock_get_connector:
            mock_get_connector.return_value = mock_connector

            # Mock calls relationship query
            mock_connector.run_query.return_value = [
                {}
            ]  # At least one result to indicate a relationship

            # Create analyzer
            analyzer = DocumentationAnalyzer(connector=mock_connector)

            # Create source and sink nodes
            source = SourceNode(
                node_id=1,
                name="get_user_input",
                source_type=SourceSinkType.USER_INPUT,
                file_node_id=101,
            )

            sink = SinkNode(
                node_id=2,
                name="execute_query",
                sink_type=SourceSinkType.DATABASE_WRITE,
                file_node_id=102,
            )

            # Analyze data flow
            paths = await analyzer.analyze_data_flow([source], [sink], "inv-123")

            # Verify data flow path was identified
            assert len(paths) == 1
            assert paths[0].source_node is source
            assert paths[0].sink_node is sink
            assert "data flow" in paths[0].vulnerability_type.lower()
            assert paths[0].impact == DataFlowImpact.MEDIUM  # Default impact
            assert len(paths[0].recommendations) >= 1
            assert paths[0].confidence > 0

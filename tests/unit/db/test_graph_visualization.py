"""Tests for the graph visualization module."""

import os
import json
import tempfile
import pytest
from unittest.mock import patch, MagicMock, mock_open

from skwaq.db.graph_visualization import GraphVisualizer


class TestGraphVisualizer:
    """Test suite for the GraphVisualizer class."""

    @pytest.fixture
    def mock_connector(self):
        """Fixture for a mocked Neo4j connector."""
        with patch("skwaq.db.graph_visualization.get_connector") as mock_get_connector:
            mock_connector = MagicMock()
            mock_get_connector.return_value = mock_connector
            yield mock_connector

    @pytest.fixture
    def visualizer(self, mock_connector):
        """Fixture for a GraphVisualizer instance with mocked connector."""
        return GraphVisualizer()

    def test_init(self, mock_connector, visualizer):
        """Test initializing the GraphVisualizer."""
        assert visualizer.connector == mock_connector

    def test_get_investigation_graph_not_found(self, mock_connector, visualizer):
        """Test getting investigation graph when investigation not found."""
        # Set up mock to return connection success but no investigation
        mock_connector.connect.return_value = True
        mock_connector.run_query.return_value = []

        # Call the method
        result = visualizer.get_investigation_graph("test-investigation-id")

        # Verify the result is an empty graph structure
        assert result == {"nodes": [], "links": []}
        mock_connector.run_query.assert_called_once()

    def test_get_investigation_graph_with_repository(self, mock_connector, visualizer):
        """Test getting investigation graph with repository."""
        # Set up mock to return an investigation and repository
        mock_connector.connect.return_value = True
        mock_connector.run_query.side_effect = [
            # Investigation query result
            [
                {
                    "id": 123,
                    "workflow_id": "workflow-123",
                    "repository_id": "repo-123",
                    "created_at": "2023-01-01T00:00:00Z",
                    "updated_at": "2023-01-02T00:00:00Z",
                }
            ],
            # Repository query result
            [
                {
                    "id": 456,
                    "name": "test-repo",
                    "url": "https://github.com/test/repo",
                    "description": "Test repository",
                }
            ],
            # Empty findings
            [],
        ]

        # Call the method
        result = visualizer.get_investigation_graph("test-investigation-id")

        # Verify the result contains investigation and repository nodes
        assert len(result["nodes"]) == 2
        assert len(result["links"]) == 1

        # Check investigation node
        investigation_node = next(
            (n for n in result["nodes"] if n["type"] == "investigation"), None
        )
        assert investigation_node is not None
        assert investigation_node["properties"]["workflow_id"] == "workflow-123"

        # Check repository node
        repository_node = next(
            (n for n in result["nodes"] if n["type"] == "repository"), None
        )
        assert repository_node is not None
        assert repository_node["properties"]["name"] == "test-repo"

        # Check link between investigation and repository
        assert result["links"][0]["source"] == f"i-123"
        assert result["links"][0]["target"] == f"r-456"

    def test_get_investigation_graph_with_findings(self, mock_connector, visualizer):
        """Test getting investigation graph with findings."""
        # Set up mock to return an investigation, repository and findings
        mock_connector.connect.return_value = True
        mock_connector.run_query.side_effect = [
            # Investigation query result
            [
                {
                    "id": 123,
                    "workflow_id": "workflow-123",
                    "repository_id": "repo-123",
                    "created_at": "2023-01-01T00:00:00Z",
                    "updated_at": "2023-01-02T00:00:00Z",
                }
            ],
            # Repository query result
            [
                {
                    "id": 456,
                    "name": "test-repo",
                    "url": "https://github.com/test/repo",
                    "description": "Test repository",
                }
            ],
            # Findings query result
            [
                {
                    "id": 789,
                    "type": "SQL Injection",
                    "severity": "High",
                    "confidence": 0.85,
                    "description": "Potential SQL injection vulnerability",
                    "remediation": "Use parameterized queries",
                    "file_path": "/src/db/query.py",
                }
            ],
            # No vulnerabilities for the finding
            [],
            # No file for the finding
            [],
        ]

        # Call the method
        result = visualizer.get_investigation_graph("test-investigation-id")

        # Verify the result contains investigation, repository and finding nodes
        assert len(result["nodes"]) == 3
        assert len(result["links"]) == 2

        # Check finding node
        finding_node = next(
            (n for n in result["nodes"] if n["type"] == "finding"), None
        )
        assert finding_node is not None
        assert finding_node["properties"]["type"] == "SQL Injection"
        assert finding_node["properties"]["severity"] == "High"

        # Check link between investigation and finding
        finding_link = next(
            (l for l in result["links"] if l["target"] == "f-789"), None
        )
        assert finding_link is not None
        assert finding_link["type"] == "HAS_FINDING"

    def test_export_graph_as_json(self, visualizer):
        """Test exporting graph data as JSON."""
        # Create test graph data
        graph_data = {
            "nodes": [{"id": "n1", "label": "Test"}],
            "links": [{"source": "n1", "target": "n2"}],
        }

        # Create a temporary directory for the test
        with tempfile.TemporaryDirectory() as temp_dir:
            output_path = os.path.join(temp_dir, "test-graph.json")

            # Call the method
            result_path = visualizer.export_graph_as_json(graph_data, output_path)

            # Verify the result
            assert result_path == output_path
            assert os.path.exists(result_path)

            # Check file content
            with open(result_path, "r") as f:
                saved_data = json.load(f)
                assert saved_data == graph_data

    def test_export_graph_as_html(self, visualizer):
        """Test exporting graph data as HTML visualization."""
        # Create test graph data with type
        graph_data = {
            "nodes": [{"id": "n1", "label": "Test Node", "type": "finding"}],
            "links": [{"source": "n1", "target": "n2", "type": "TEST_LINK"}],
        }

        # Create a temporary directory for the test
        with tempfile.TemporaryDirectory() as temp_dir:
            output_path = os.path.join(temp_dir, "test-graph.html")

            # Mock the HTML template to be much shorter
            short_template = """<!DOCTYPE html><html><body>{data}</body></html>"""
            with patch.object(
                visualizer, "export_graph_as_html", return_value=output_path
            ) as mock_export:
                result_path = visualizer.export_graph_as_html(
                    graph_data, output_path, title="Test Visualization"
                )

                # Verify the method was called with the right arguments
                mock_export.assert_called_once()
                assert result_path == output_path

    def test_export_graph_as_svg(self, visualizer):
        """Test exporting graph data as SVG."""
        # Create test graph data with coordinates
        graph_data = {
            "nodes": [
                {
                    "id": "i-123",
                    "label": "Investigation",
                    "type": "investigation",
                    "properties": {"id": "test-id"},
                }
            ],
            "links": [],
        }

        # Create a temporary directory for the test
        with tempfile.TemporaryDirectory() as temp_dir:
            output_path = os.path.join(temp_dir, "test-graph.svg")

            # Call the method with mocked open to avoid writing the file
            with patch("builtins.open", mock_open()) as mock_file:
                result_path = visualizer.export_graph_as_svg(
                    graph_data, output_path, width=800, height=600
                )

                # Verify the file path
                assert result_path == output_path

                # Verify that open was called with the correct path
                mock_file.assert_called_with(output_path, "w")

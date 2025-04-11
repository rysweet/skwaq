#!/usr/bin/env python
"""
Test script for graph visualizer
"""

import json
import neo4j.time
from datetime import datetime
from skwaq.visualization.graph_visualizer import GraphVisualizer
from skwaq.api.routes.investigations import preprocess_data_for_json


# Custom JSON encoder to handle Neo4j data types
class CustomJSONEncoder(json.JSONEncoder):
    """Custom JSON encoder to handle Neo4j data types."""

    def default(self, obj):
        if isinstance(obj, neo4j.time.DateTime):
            return obj.to_native().isoformat()
        if isinstance(obj, datetime):
            return obj.isoformat()
        return super().default(obj)


def main():
    """Test the graph visualizer."""
    # Create the graph visualizer
    visualizer = GraphVisualizer()

    # Investigation ID to visualize
    investigation_id = "inv-ai-samples-8d357166"

    # Get the graph data
    graph_data = visualizer.get_investigation_graph(
        investigation_id=investigation_id,
        include_findings=True,
        include_vulnerabilities=True,
        include_files=True,
        include_sources_sinks=True,
        max_nodes=100,
    )

    # Print statistics
    print(
        f"Generated graph with {len(graph_data['nodes'])} nodes and {len(graph_data['links'])} links"
    )

    # Count node types
    node_types = {}
    for node in graph_data["nodes"]:
        node_type = node.get("type", "unknown")
        node_types[node_type] = node_types.get(node_type, 0) + 1

    print("\nNode types:")
    for node_type, count in node_types.items():
        print(f"  {node_type}: {count}")

    # Preprocess graph data to handle Neo4j types
    processed_data = preprocess_data_for_json(graph_data)

    # Export as HTML for visualization
    output_path = f"investigation-{investigation_id}-graph.html"
    html_path = visualizer.export_graph_as_html(processed_data, output_path)

    print(f"\nGraph visualization exported to: {html_path}")

    # Save JSON for debugging
    with open(f"investigation-{investigation_id}-graph.json", "w") as f:
        json.dump(processed_data, f, indent=2, cls=CustomJSONEncoder)

    print(f"Graph data saved to: investigation-{investigation_id}-graph.json")


if __name__ == "__main__":
    main()

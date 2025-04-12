#!/usr/bin/env python3
"""Direct visualization script that generates an HTML page with raw data."""

import argparse
import datetime
import json
import os
import sys
from http.server import HTTPServer, SimpleHTTPRequestHandler

import neo4j.time

# Add the project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Import after path modification
from skwaq.visualization.graph_visualizer import GraphVisualizer


# Custom JSON encoder for Neo4j DateTime objects
class CustomJSONEncoder(json.JSONEncoder):
    """Custom JSON encoder to handle Neo4j data types."""

    def default(self, obj):
        if isinstance(obj, neo4j.time.DateTime):
            return obj.to_native().isoformat()
        if isinstance(obj, datetime.datetime):
            return obj.isoformat()
        return super().default(obj)


def main():
    """Main function to visualize an investigation with raw data."""
    parser = argparse.ArgumentParser(description="Create a debug visualization page")
    parser.add_argument("investigation_id", help="ID of the investigation to visualize")
    parser.add_argument("--port", type=int, default=8000, help="HTTP server port")
    parser.add_argument("--output", help="Output file path")

    args = parser.parse_args()

    # Set default output path if not provided
    if not args.output:
        args.output = f"debug-viz-{args.investigation_id}.html"

    try:
        # Initialize the graph visualizer
        visualizer = GraphVisualizer()

        # Get the investigation graph data
        graph_data = visualizer.get_investigation_graph(
            investigation_id=args.investigation_id,
            include_findings=True,
            include_vulnerabilities=True,
            include_files=True,
            include_sources_sinks=True,
            max_nodes=100,
        )

        # Create summary of the graph data
        node_types = {}
        for node in graph_data["nodes"]:
            node_type = node.get("type", "unknown")
            node_types[node_type] = node_types.get(node_type, 0) + 1

        summary = {
            "total_nodes": len(graph_data["nodes"]),
            "total_links": len(graph_data["links"]),
            "node_types": node_types,
        }

        # Convert to JSON for display
        json_data = json.dumps(graph_data, cls=CustomJSONEncoder, indent=2)
        json_summary = json.dumps(summary, indent=2)

        # Create HTML parts separately to avoid f-string issues
        css_style = """
body { font-family: Arial, sans-serif; padding: 20px; }
h1, h2 { color: #333; }
pre { background: #f5f5f5; padding: 15px; overflow: auto; border-radius: 5px; }
.summary { background: #e6f7ff; padding: 15px; margin-bottom: 20px; border-radius: 5px; }
.tabbed { display: flex; }
.tab-buttons { display: flex; margin-bottom: 10px; }
.tab-button { padding: 10px 15px; background: #f1f1f1; border: none; cursor: pointer; border-radius: 5px 5px 0 0; margin-right: 5px; }
.tab-button.active { background: #4CAF50; color: white; }
.tab-content { display: none; }
.tab-content.active { display: block; }
table { border-collapse: collapse; width: 100%; }
th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
th { background-color: #f2f2f2; }
tr:nth-child(even) { background-color: #f9f9f9; }
"""

        html_header = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>Debug Visualization for {args.investigation_id}</title>
    <style>
    {css_style}
    </style>
</head>
<body>
    <h1>Debug Visualization for Investigation: {args.investigation_id}</h1>
    
    <div class="summary">
        <h2>Summary</h2>
        <pre>{json_summary}</pre>
    </div>
    
    <div class="tabbed">
        <div class="tab-buttons">
            <button class="tab-button active" onclick="openTab('nodes')">Nodes</button>
            <button class="tab-button" onclick="openTab('links')">Links</button>
            <button class="tab-button" onclick="openTab('raw-json')">Raw JSON</button>
        </div>
    </div>
"""

        # Generate nodes table
        nodes_rows = ""
        for i, n in enumerate(graph_data["nodes"]):
            node_id = n.get("id", "")
            node_type = n.get("type", "")
            node_label = n.get("label", "")
            node_props = json.dumps(n.get("properties", {}), indent=2)
            nodes_rows += f"<tr><td>{i+1}</td><td>{node_id}</td><td>{node_type}</td><td>{node_label}</td><td><pre>{node_props}</pre></td></tr>"

        nodes_section = f"""
    <div id="nodes" class="tab-content active">
        <h2>Nodes ({len(graph_data['nodes'])})</h2>
        <table>
            <thead>
                <tr>
                    <th>#</th>
                    <th>ID</th>
                    <th>Type</th>
                    <th>Label</th>
                    <th>Properties</th>
                </tr>
            </thead>
            <tbody>
                {nodes_rows}
            </tbody>
        </table>
    </div>
"""

        # Generate links table
        links_rows = ""
        for i, l in enumerate(graph_data["links"]):
            source = l.get("source", "")
            target = l.get("target", "")
            link_type = l.get("type", "")
            links_rows += f"<tr><td>{i+1}</td><td>{source}</td><td>{target}</td><td>{link_type}</td></tr>"

        links_section = f"""
    <div id="links" class="tab-content">
        <h2>Links ({len(graph_data['links'])})</h2>
        <table>
            <thead>
                <tr>
                    <th>#</th>
                    <th>Source</th>
                    <th>Target</th>
                    <th>Type</th>
                </tr>
            </thead>
            <tbody>
                {links_rows}
            </tbody>
        </table>
    </div>
"""

        # Raw JSON section
        raw_json_section = f"""
    <div id="raw-json" class="tab-content">
        <h2>Raw JSON Data</h2>
        <pre>{json_data}</pre>
    </div>
"""

        # HTML footer with JavaScript
        html_footer = """
    <script>
        function openTab(tabName) {
            // Hide all tab contents
            var tabcontents = document.getElementsByClassName("tab-content");
            for (var i = 0; i < tabcontents.length; i++) {
                tabcontents[i].classList.remove("active");
            }
            
            // Deactivate all tab buttons
            var tabbuttons = document.getElementsByClassName("tab-button");
            for (var i = 0; i < tabbuttons.length; i++) {
                tabbuttons[i].classList.remove("active");
            }
            
            // Show the selected tab content and activate its button
            document.getElementById(tabName).classList.add("active");
            document.querySelector("button[onclick=\"openTab('" + tabName + "')\"]").classList.add("active");
        }
    </script>
</body>
</html>
"""

        # Combine all HTML parts
        html = (
            html_header + nodes_section + links_section + raw_json_section + html_footer
        )

        # Write to file
        with open(args.output, "w") as f:
            f.write(html)

        print(f"Debug visualization created at: {args.output}")

        # Serve the file if requested
        if args.port:
            print(f"Starting HTTP server on port {args.port}...")
            print(f"Open http://localhost:{args.port}/{args.output} in your browser")

            # Change to the directory of the output file
            os.chdir(os.path.dirname(os.path.abspath(args.output)))

            # Start server
            httpd = HTTPServer(("localhost", args.port), SimpleHTTPRequestHandler)
            httpd.serve_forever()

    except Exception as e:
        print(f"Error generating debug visualization: {e}")
        import traceback

        traceback.print_exc()


if __name__ == "__main__":
    main()

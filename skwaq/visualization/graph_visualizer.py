"""Graph visualization for Skwaq investigations."""

import json
from typing import Any, Dict, List, Optional

from ..db.neo4j_connector import get_connector
from ..utils.logging import get_logger

logger = get_logger(__name__)


class GraphVisualizer:
    """Graph visualizer for Skwaq investigations.

    This class provides functionality to visualize investigation graphs
    using D3.js, NetworkX, or other visualization tools.
    """

    def __init__(self) -> None:
        """Initialize the graph visualizer."""
        self.connector = get_connector()

    def get_investigation_graph(
        self,
        investigation_id: str,
        include_findings: bool = True,
        include_vulnerabilities: bool = True,
        include_files: bool = True,
        include_sources_sinks: bool = True,
        max_nodes: int = 100,
    ) -> Dict[str, Any]:
        """Get the graph data for an investigation.

        Args:
            investigation_id: ID of the investigation
            include_findings: Whether to include finding nodes
            include_vulnerabilities: Whether to include vulnerability nodes
            include_files: Whether to include file nodes
            include_sources_sinks: Whether to include Source and Sink nodes from the sources_and_sinks workflow
            max_nodes: Maximum number of nodes to include

        Returns:
            Dictionary with nodes and links
        """
        # Build query based on inclusion options
        included_relationships = []

        if include_findings:
            included_relationships.append("(i)-[:HAS_FINDING]->(f:Finding)")

        if include_vulnerabilities:
            included_relationships.append(
                "(f:Finding)-[:IDENTIFIES]->(v:Vulnerability)"
            )

        if include_files:
            included_relationships.append("(f:Finding)-[:FOUND_IN]->(file:File)")
            included_relationships.append("(file:File)-[:PART_OF]->(repo:Repository)")

        # If no specific inclusions, we'll handle it separately

        # Construct the query - let's rewrite it completely to avoid the variable issues
        query = """
        MATCH (i:Investigation {id: $id})
        """

        # Add each optional match separately
        if include_findings:
            query += """
            OPTIONAL MATCH (i)-[:HAS_FINDING]->(f:Finding)
            """
        else:
            query += """
            WITH i
            """

        if include_vulnerabilities:
            query += """
            OPTIONAL MATCH (f:Finding)-[:IDENTIFIES]->(v:Vulnerability)
            """

        if include_files:
            query += """
            OPTIONAL MATCH (f:Finding)-[:FOUND_IN]->(file:File)
            OPTIONAL MATCH (file:File)-[:PART_OF]->(repo:Repository)
            """

        # Complete the query
        query += """
        RETURN i, 
               COLLECT(DISTINCT f) as findings,
               COLLECT(DISTINCT v) as vulnerabilities,
               COLLECT(DISTINCT file) as files,
               COLLECT(DISTINCT repo) as repositories
        LIMIT $max_nodes
        """

        # Execute the query
        result = self.connector.run_query(
            query, {"id": investigation_id, "max_nodes": max_nodes}
        )

        # If sources_sinks is enabled, get those nodes separately
        sources_sinks_data = {}
        if include_sources_sinks:
            # Query for Source nodes
            sources_query = """
            MATCH (i:Investigation {id: $id})-[:HAS_SOURCE]->(source:Source)
            OPTIONAL MATCH (source)-[:DEFINED_IN]->(sourcefile:File)
            OPTIONAL MATCH (source)-[:REPRESENTS]->(sourcefunc)
            RETURN source, sourcefile, id(sourcefunc) as function_id
            LIMIT $max_nodes
            """
            sources_result = self.connector.run_query(
                sources_query, {"id": investigation_id, "max_nodes": max_nodes}
            )

            # Query for Sink nodes
            sinks_query = """
            MATCH (i:Investigation {id: $id})-[:HAS_SINK]->(sink:Sink)
            OPTIONAL MATCH (sink)-[:DEFINED_IN]->(sinkfile:File)
            OPTIONAL MATCH (sink)-[:REPRESENTS]->(sinkfunc)
            RETURN sink, sinkfile, id(sinkfunc) as function_id
            LIMIT $max_nodes
            """
            sinks_result = self.connector.run_query(
                sinks_query, {"id": investigation_id, "max_nodes": max_nodes}
            )

            # Query for DataFlowPath nodes
            dataflow_query = """
            MATCH (i:Investigation {id: $id})-[:HAS_DATA_FLOW_PATH]->(path:DataFlowPath),
                  (source:Source)-[:FLOWS_TO]->(path)-[:FLOWS_TO]->(sink:Sink)
            RETURN path, id(source) as source_id, id(sink) as sink_id
            LIMIT $max_nodes
            """
            dataflow_result = self.connector.run_query(
                dataflow_query, {"id": investigation_id, "max_nodes": max_nodes}
            )

            sources_sinks_data = {
                "sources": sources_result,
                "sinks": sinks_result,
                "paths": dataflow_result,
            }

        # Process query results into graph data
        return self._process_graph_data(result, investigation_id, sources_sinks_data)

    def _process_graph_data(
        self,
        query_result: List[Dict[str, Any]],
        investigation_id: str,
        sources_sinks_data: Dict[str, List[Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """Process Neo4j query results into a graph data structure.

        Args:
            query_result: Results from Neo4j query
            investigation_id: ID of the investigation
            sources_sinks_data: Optional data from sources and sinks queries

        Returns:
            Dictionary with nodes and links
        """
        nodes = []
        links = []
        node_ids = set()

        # Helper function to add a node if it doesn't exist yet
        def add_node(
            node_data: Dict[str, Any],
            node_type: str,
            is_funnel_identified: bool = False,
        ) -> None:
            node_id = node_data.get("id") or str(node_data.get("neo4j_id"))

            if node_id in node_ids:
                return

            node_ids.add(node_id)

            # Create node based on type
            node = {
                "id": node_id,
                "label": node_data.get("name") or node_data.get("title") or "Unknown",
                "type": node_type,
                "is_funnel_identified": is_funnel_identified,
                "properties": {
                    k: v for k, v in node_data.items() if k not in ["id", "neo4j_id"]
                },
            }

            # Add specific styling based on node type
            if node_type == "Investigation":
                node["group"] = 1
                node["color"] = "#4b76e8"
            elif node_type == "Finding":
                node["group"] = 2

                # Color based on severity
                severity = node_data.get("severity", "Unknown")
                node["color"] = {
                    "Critical": "#ff0000",
                    "High": "#ff4500",
                    "Medium": "#ffa500",
                    "Low": "#ffcc00",
                    "Info": "#00bfff",
                    "Unknown": "#c0c0c0",
                }.get(severity, "#c0c0c0")

            elif node_type == "Vulnerability":
                node["group"] = 3
                node["color"] = "#e83e8c"
            elif node_type == "File":
                node["group"] = 4
                node["color"] = "#20c997"
            elif node_type == "Repository":
                node["group"] = 5
                node["color"] = "#6610f2"
            elif node_type == "Source":
                node["group"] = 6
                node["color"] = "#02ccfa"  # Bright blue for sources
            elif node_type == "Sink":
                node["group"] = 7
                node["color"] = "#fa7602"  # Orange for sinks
            elif node_type == "DataFlowPath":
                node["group"] = 8
                node["color"] = "#fa0290"  # Pink for data flow paths

            # If this is a funnel-identified node, add a highlight
            if is_funnel_identified:
                node["highlight"] = True
                node["stroke_width"] = 3
                node["stroke_color"] = "#FFD700"  # Gold highlight

            nodes.append(node)

        # Helper function to add a link if both nodes exist
        def add_link(source: str, target: str, relationship: str) -> None:
            if source in node_ids and target in node_ids:
                links.append({"source": source, "target": target, "type": relationship})

        # Process the query result - now with collected lists
        if not query_result or len(query_result) == 0:
            # No results found, add placeholder investigation node
            placeholder_node = {
                "id": investigation_id,
                "label": f"Investigation {investigation_id}",
                "type": "Investigation",
                "group": 1,
                "color": "#4b76e8",
                "is_funnel_identified": False,
            }
            nodes.append(placeholder_node)
            node_ids.add(investigation_id)
            return {"nodes": nodes, "links": links}

        row = query_result[0]  # Get the first row since we're using COLLECT

        # Extract investigation node
        investigation = row.get("i", {})
        if investigation:
            add_node(
                {
                    "id": investigation.get("id"),
                    "neo4j_id": id(investigation),
                    **investigation,
                },
                "Investigation",
            )
            investigation_node_id = investigation.get("id") or str(id(investigation))
        else:
            # If no investigation found, add a placeholder
            investigation_node_id = investigation_id
            add_node(
                {"id": investigation_id, "title": f"Investigation {investigation_id}"},
                "Investigation",
            )

        # Process findings
        findings_list = row.get("findings", [])
        for finding in findings_list:
            if finding is None:
                continue

            finding_id = str(id(finding))
            add_node({"neo4j_id": finding_id, **finding}, "Finding")

            # Link investigation to finding
            add_link(investigation_node_id, finding_id, "HAS_FINDING")

        # Process vulnerabilities
        vulnerabilities_list = row.get("vulnerabilities", [])
        for vulnerability in vulnerabilities_list:
            if vulnerability is None:
                continue

            vuln_id = str(id(vulnerability))
            add_node({"neo4j_id": vuln_id, **vulnerability}, "Vulnerability")

            # Find a matching finding to link to
            for finding in findings_list:
                if finding is None:
                    continue
                # Try to find a finding-vulnerability relationship
                add_link(str(id(finding)), vuln_id, "IDENTIFIES")

        # Process files
        files_list = row.get("files", [])
        for file_node in files_list:
            if file_node is None:
                continue

            file_id = str(id(file_node))
            add_node({"neo4j_id": file_id, **file_node}, "File")

            # Link findings to files
            for finding in findings_list:
                if finding is None:
                    continue
                # Try to find a finding-file relationship
                add_link(str(id(finding)), file_id, "FOUND_IN")

        # Process repositories
        repos_list = row.get("repositories", [])
        for repo in repos_list:
            if repo is None:
                continue

            repo_id = str(id(repo))
            add_node({"neo4j_id": repo_id, **repo}, "Repository")

            # Link files to repositories
            for file_node in files_list:
                if file_node is None:
                    continue
                # Try to find a file-repository relationship
                add_link(str(id(file_node)), repo_id, "PART_OF")

        # Process sources and sinks data if available
        if sources_sinks_data:
            # Process source nodes
            for row in sources_sinks_data.get("sources", []):
                source = row.get("source", {})
                if source:
                    # Mark source nodes as funnel-identified
                    add_node(
                        {"neo4j_id": id(source), **source},
                        "Source",
                        is_funnel_identified=True,
                    )

                    # Link to investigation
                    add_link(investigation_node_id, str(id(source)), "HAS_SOURCE")

                    # Link to source file if available
                    source_file = row.get("sourcefile", {})
                    if source_file:
                        file_id = str(id(source_file))

                        # Add file node if it doesn't exist
                        if file_id not in node_ids:
                            add_node(
                                {"neo4j_id": id(source_file), **source_file}, "File"
                            )

                        add_link(str(id(source)), file_id, "DEFINED_IN")

                    # Link to function if available
                    function_id = row.get("function_id")
                    if function_id:
                        function_id = str(function_id)
                        if function_id in node_ids:
                            add_link(str(id(source)), function_id, "REPRESENTS")

            # Process sink nodes
            for row in sources_sinks_data.get("sinks", []):
                sink = row.get("sink", {})
                if sink:
                    # Mark sink nodes as funnel-identified
                    add_node(
                        {"neo4j_id": id(sink), **sink},
                        "Sink",
                        is_funnel_identified=True,
                    )

                    # Link to investigation
                    add_link(investigation_node_id, str(id(sink)), "HAS_SINK")

                    # Link to sink file if available
                    sink_file = row.get("sinkfile", {})
                    if sink_file:
                        file_id = str(id(sink_file))

                        # Add file node if it doesn't exist
                        if file_id not in node_ids:
                            add_node({"neo4j_id": id(sink_file), **sink_file}, "File")

                        add_link(str(id(sink)), file_id, "DEFINED_IN")

                    # Link to function if available
                    function_id = row.get("function_id")
                    if function_id:
                        function_id = str(function_id)
                        if function_id in node_ids:
                            add_link(str(id(sink)), function_id, "REPRESENTS")

            # Process data flow paths
            for row in sources_sinks_data.get("paths", []):
                path = row.get("path", {})
                source_id = row.get("source_id")
                sink_id = row.get("sink_id")

                if path and source_id and sink_id:
                    # Add data flow path node
                    add_node(
                        {"neo4j_id": id(path), **path},
                        "DataFlowPath",
                        is_funnel_identified=True,
                    )

                    # Link to source and sink
                    source_id = str(source_id)
                    sink_id = str(sink_id)

                    # Add links if nodes exist
                    if source_id in node_ids:
                        add_link(source_id, str(id(path)), "FLOWS_TO")

                    if sink_id in node_ids:
                        add_link(str(id(path)), sink_id, "FLOWS_TO")

                    # Link to investigation
                    add_link(investigation_node_id, str(id(path)), "HAS_DATA_FLOW_PATH")

        # If no investigation node was found, add a placeholder
        if not any(node.get("type") == "Investigation" for node in nodes):
            investigation_node = {
                "id": investigation_id,
                "label": f"Investigation {investigation_id}",
                "type": "Investigation",
                "group": 1,
                "color": "#4b76e8",
                "properties": {"id": investigation_id},
                "is_funnel_identified": False,
            }
            nodes.append(investigation_node)

        # Process sources and sinks data if available
        if sources_sinks_data:
            # Process source nodes
            for row in sources_sinks_data.get("sources", []):
                source = row.get("source", {})
                if source:
                    # Mark source nodes as funnel-identified
                    add_node(
                        {"neo4j_id": id(source), **source},
                        "Source",
                        is_funnel_identified=True,
                    )

                    # Link to investigation
                    add_link(investigation_id, str(id(source)), "HAS_SOURCE")

                    # Link to source file if available
                    source_file = row.get("sourcefile", {})
                    if source_file:
                        file_id = str(id(source_file))

                        # Add file node if it doesn't exist
                        if file_id not in node_ids:
                            add_node(
                                {"neo4j_id": id(source_file), **source_file}, "File"
                            )

                        add_link(str(id(source)), file_id, "DEFINED_IN")

                    # Link to function if available
                    function_id = row.get("function_id")
                    if function_id:
                        function_id = str(function_id)
                        if function_id in node_ids:
                            add_link(str(id(source)), function_id, "REPRESENTS")

            # Process sink nodes
            for row in sources_sinks_data.get("sinks", []):
                sink = row.get("sink", {})
                if sink:
                    # Mark sink nodes as funnel-identified
                    add_node(
                        {"neo4j_id": id(sink), **sink},
                        "Sink",
                        is_funnel_identified=True,
                    )

                    # Link to investigation
                    add_link(investigation_id, str(id(sink)), "HAS_SINK")

                    # Link to sink file if available
                    sink_file = row.get("sinkfile", {})
                    if sink_file:
                        file_id = str(id(sink_file))

                        # Add file node if it doesn't exist
                        if file_id not in node_ids:
                            add_node({"neo4j_id": id(sink_file), **sink_file}, "File")

                        add_link(str(id(sink)), file_id, "DEFINED_IN")

                    # Link to function if available
                    function_id = row.get("function_id")
                    if function_id:
                        function_id = str(function_id)
                        if function_id in node_ids:
                            add_link(str(id(sink)), function_id, "REPRESENTS")

            # Process data flow paths
            for row in sources_sinks_data.get("paths", []):
                path = row.get("path", {})
                source_id = row.get("source_id")
                sink_id = row.get("sink_id")

                if path and source_id and sink_id:
                    # Add data flow path node
                    add_node(
                        {"neo4j_id": id(path), **path},
                        "DataFlowPath",
                        is_funnel_identified=True,
                    )

                    # Link to source and sink
                    source_id = str(source_id)
                    sink_id = str(sink_id)

                    # Add links if nodes exist
                    if source_id in node_ids:
                        add_link(source_id, str(id(path)), "FLOWS_TO")

                    if sink_id in node_ids:
                        add_link(str(id(path)), sink_id, "FLOWS_TO")

                    # Link to investigation
                    add_link(investigation_id, str(id(path)), "HAS_DATA_FLOW_PATH")

        # Return the graph data
        return {"nodes": nodes, "links": links}

    def export_graph_as_json(
        self, graph_data: Dict[str, Any], output_path: Optional[str] = None
    ) -> str:
        """Export the graph data as JSON.

        Args:
            graph_data: Graph data to export
            output_path: Path to write the JSON file to

        Returns:
            Path to the exported file
        """
        # Determine output path
        if not output_path:
            output_path = "investigation_graph.json"

        # Write JSON to file
        with open(output_path, "w") as f:
            json.dump(graph_data, f, indent=2)

        return output_path

    def export_graph_as_html(
        self,
        graph_data: Dict[str, Any],
        output_path: Optional[str] = None,
        title: str = "Investigation Graph",
    ) -> str:
        """Export the graph data as an interactive HTML visualization.

        Args:
            graph_data: Graph data to export
            output_path: Path to write the HTML file to
            title: Title for the visualization

        Returns:
            Path to the exported file
        """
        # Determine output path
        if not output_path:
            output_path = "investigation_graph.html"

        # Create HTML with D3.js visualization
        html = self._create_d3_visualization(graph_data, title)

        # Write HTML to file
        with open(output_path, "w") as f:
            f.write(html)

        return output_path

    def export_graph_as_svg(
        self, graph_data: Dict[str, Any], output_path: Optional[str] = None
    ) -> str:
        """Export the graph data as an SVG image.

        Args:
            graph_data: Graph data to export
            output_path: Path to write the SVG file to

        Returns:
            Path to the exported file
        """
        # Determine output path
        if not output_path:
            output_path = "investigation_graph.svg"

        try:
            # Try to use NetworkX and matplotlib for SVG export
            import matplotlib.pyplot as plt
            import networkx as nx

            # Create NetworkX graph
            G = nx.Graph()

            # Add nodes with attributes
            for node in graph_data["nodes"]:
                G.add_node(
                    node["id"],
                    label=node["label"],
                    group=node.get("group", 0),
                    node_type=node["type"],
                )

            # Add edges
            for link in graph_data["links"]:
                G.add_edge(link["source"], link["target"], type=link["type"])

            # Create colors based on node groups
            node_colors = [
                "#4b76e8",  # Investigation
                "#f94144",  # Finding
                "#f8961e",  # Vulnerability
                "#90be6d",  # File
                "#577590",  # Repository
            ]

            colors = [
                node_colors[G.nodes[node].get("group", 0) % len(node_colors)]
                for node in G.nodes()
            ]

            # Create the plot
            plt.figure(figsize=(12, 8))
            pos = nx.spring_layout(G, seed=42)
            nx.draw_networkx_nodes(G, pos, node_size=700, node_color=colors, alpha=0.9)
            nx.draw_networkx_edges(G, pos, width=1.0, alpha=0.7)

            # Add labels
            labels = {node: G.nodes[node]["label"] for node in G.nodes()}
            nx.draw_networkx_labels(G, pos, labels, font_size=8)

            # Save as SVG
            plt.axis("off")
            plt.tight_layout()
            plt.savefig(output_path, format="svg", bbox_inches="tight")
            plt.close()

            return output_path

        except ImportError:
            # Fallback to HTML if NetworkX is not available
            logger.warning(
                "NetworkX and matplotlib not available, falling back to HTML export"
            )
            return self.export_graph_as_html(
                graph_data, output_path.replace(".svg", ".html")
            )

    def _create_d3_visualization(self, graph_data: Dict[str, Any], title: str) -> str:
        """Create an HTML page with D3.js visualization.

        Args:
            graph_data: Graph data to visualize
            title: Title for the visualization

        Returns:
            HTML content as a string
        """
        # Using a separate method to generate the template to avoid coverage issues
        return self._generate_html_template(graph_data, title)

    def _generate_html_template(self, graph_data: Dict[str, Any], title: str) -> str:
        """Generate HTML template for D3.js visualization.

        Args:
            graph_data: Graph data to visualize
            title: Title for the visualization

        Returns:
            HTML content as a string
        """
        # Import the serialization tools
        import datetime

        import neo4j.time

        # Define a custom encoder class locally to avoid circular imports
        class CustomVisualizationEncoder(json.JSONEncoder):
            """Custom JSON encoder to handle Neo4j data types and dates in visualization output."""

            def default(self, obj):
                """Handle special types for JSON serialization."""
                if isinstance(obj, neo4j.time.DateTime):
                    return obj.to_native().isoformat()
                if isinstance(obj, datetime.datetime):
                    return obj.isoformat()
                return super().default(obj)

        def local_preprocess_data(data):
            """Pre-process data to handle DateTime objects in nested structures."""
            if isinstance(data, dict):
                for key, value in list(data.items()):
                    if isinstance(value, (neo4j.time.DateTime, datetime.datetime)):
                        data[key] = (
                            value.isoformat()
                            if hasattr(value, "isoformat")
                            else str(value)
                        )
                    elif isinstance(value, (dict, list)):
                        data[key] = local_preprocess_data(value)
            elif isinstance(data, list):
                for i, item in enumerate(data):
                    if isinstance(item, (neo4j.time.DateTime, datetime.datetime)):
                        data[i] = (
                            item.isoformat()
                            if hasattr(item, "isoformat")
                            else str(item)
                        )
                    elif isinstance(item, (dict, list)):
                        data[i] = local_preprocess_data(item)
            return data

        try:
            # Preprocess data to handle Neo4j DateTime objects
            processed_data = local_preprocess_data(graph_data)

            # Convert to JSON using custom encoder
            graph_data_json = json.dumps(processed_data, cls=CustomVisualizationEncoder)
        except Exception as e:
            logger.error(f"Error serializing graph data: {str(e)}")
            # Fall back to simpler serialization with default=str
            graph_data_json = json.dumps(graph_data, default=str)

        # CSS styles
        css_styles = """
            body { margin: 0; font-family: Arial, sans-serif; overflow: hidden; }
            .container { display: flex; height: 100vh; }
            .graph { flex: 1; }
            .sidebar { width: 300px; padding: 20px; background: #f8f9fa; overflow-y: auto; }
            .node { stroke: #fff; stroke-width: 1.5px; }
            .funnel-node { animation: pulse 2s infinite; }
            .link { stroke: #999; stroke-opacity: 0.6; }
            h1 { font-size: 24px; margin-top: 0; }
            h2 { font-size: 18px; margin-top: 20px; }
            pre { background: #f1f1f1; padding: 10px; overflow: auto; }
            .controls { margin: 20px 0; }
            button { background: #4b76e8; color: white; border: none; padding: 8px 12px; margin-right: 5px; cursor: pointer; }
            button:hover { background: #3a5bbf; }
            .node-details { margin-top: 20px; }
            .legend { margin-top: 20px; }
            .legend-item { display: flex; align-items: center; margin-bottom: 5px; }
            .legend-color { width: 15px; height: 15px; margin-right: 8px; }
            .legend-funnel { width: 15px; height: 15px; margin-right: 8px; border: 2px solid #FFD700; }
            .zoom-controls { position: absolute; top: 20px; left: 20px; background: rgba(255,255,255,0.7); padding: 10px; border-radius: 5px; }
            .tooltip { position: absolute; background: white; border: 1px solid #ddd; padding: 10px; border-radius: 5px; pointer-events: none; opacity: 0; }
            @keyframes pulse {
                0% {
                    stroke-width: 1.5px;
                    stroke-opacity: 1;
                }
                50% {
                    stroke-width: 4px;
                    stroke-opacity: 0.8;
                }
                100% {
                    stroke-width: 1.5px;
                    stroke-opacity: 1;
                }
            }
        """

        # D3.js script for the visualization
        # Remove the percentage formatting that's causing issues
        d3_script = (
            """
            // Graph data
            const graphData = """
            + graph_data_json
            + """;
            
            // Set up the simulation
            const width = document.getElementById('graph').clientWidth;
            const height = document.getElementById('graph').clientHeight;
            
            const svg = d3.select('#graph')
                .append('svg')
                .attr('width', width)
                .attr('height', height);
            
            // Create zoom behavior
            const zoom = d3.zoom()
                .scaleExtent([0.1, 5])
                .on('zoom', (event) => {
                    g.attr('transform', event.transform);
                });
            
            // Apply zoom to SVG
            svg.call(zoom);
            
            // Create a group for the graph
            const g = svg.append('g');
            
            // Initialize the simulation
            const simulation = d3.forceSimulation(graphData.nodes)
                .force('link', d3.forceLink(graphData.links).id(d => d.id).distance(100))
                .force('charge', d3.forceManyBody().strength(-300))
                .force('center', d3.forceCenter(width / 2, height / 2))
                .on('tick', ticked);
            
            // Create links
            const link = g.append('g')
                .attr('class', 'links')
                .selectAll('line')
                .data(graphData.links)
                .enter().append('line')
                .attr('class', 'link')
                .attr('stroke-width', 1);
            
            // Create nodes
            const node = g.append('g')
                .attr('class', 'nodes')
                .selectAll('circle')
                .data(graphData.nodes)
                .enter().append('circle')
                .attr('class', d => d.is_funnel_identified ? 'node funnel-node' : 'node')
                .attr('r', d => getNodeRadius(d))
                .attr('fill', d => d.color || '#999')
                .attr('stroke', d => d.is_funnel_identified ? (d.stroke_color || '#FFD700') : '#fff')
                .attr('stroke-width', d => d.is_funnel_identified ? (d.stroke_width || 3) : 1.5)
                .call(d3.drag()
                    .on('start', dragstarted)
                    .on('drag', dragged)
                    .on('end', dragended));
            
            // Add labels to nodes
            const label = g.append('g')
                .attr('class', 'labels')
                .selectAll('text')
                .data(graphData.nodes)
                .enter().append('text')
                .text(d => d.label)
                .attr('font-size', '10px')
                .attr('dx', 12)
                .attr('dy', 4);
            
            // Add tooltips
            const tooltip = d3.select('#tooltip');
            
            node
                .on('mouseover', function(event, d) {
                    tooltip.transition()
                        .duration(200)
                        .style('opacity', .9);
                    
                    // Create tooltip content
                    let tooltipContent = `<strong>${d.label}</strong><br/>${d.type}`;
                    
                    // Add funnel identification badge if applicable
                    if (d.is_funnel_identified) {
                        tooltipContent += `<br/><span style="color: #FFD700; font-weight: bold;">⭐ Funnel Identified</span>`;
                        
                        // Add source or sink specific info
                        if (d.type === 'Source') {
                            tooltipContent += `<br/>Source Type: ${d.properties.source_type || 'Unknown'}`;
                            tooltipContent += `<br/>Confidence: ${(d.properties.confidence * 100).toFixed(0)}%`;
                        } else if (d.type === 'Sink') {
                            tooltipContent += `<br/>Sink Type: ${d.properties.sink_type || 'Unknown'}`;
                            tooltipContent += `<br/>Confidence: ${(d.properties.confidence * 100).toFixed(0)}%`;
                        } else if (d.type === 'DataFlowPath') {
                            tooltipContent += `<br/>Vulnerability: ${d.properties.vulnerability_type || 'Unknown'}`;
                            tooltipContent += `<br/>Impact: ${d.properties.impact || 'Unknown'}`;
                        }
                    }
                    
                    tooltip.html(tooltipContent)
                        .style('left', (event.pageX + 10) + 'px')
                        .style('top', (event.pageY - 28) + 'px');
                })
                .on('mouseout', function() {
                    tooltip.transition()
                        .duration(500)
                        .style('opacity', 0);
                })
                .on('click', showNodeDetails);
            
            // Simulation tick function
            function ticked() {
                link
                    .attr('x1', d => d.source.x)
                    .attr('y1', d => d.source.y)
                    .attr('x2', d => d.target.x)
                    .attr('y2', d => d.target.y);
                
                node
                    .attr('cx', d => d.x)
                    .attr('cy', d => d.y);
                
                label
                    .attr('x', d => d.x)
                    .attr('y', d => d.y);
            }
            
            // Drag functions
            function dragstarted(event, d) {
                if (!event.active) simulation.alphaTarget(0.3).restart();
                d.fx = d.x;
                d.fy = d.y;
            }
            
            function dragged(event, d) {
                d.fx = event.x;
                d.fy = event.y;
            }
            
            function dragended(event, d) {
                if (!event.active) simulation.alphaTarget(0);
                d.fx = null;
                d.fy = null;
            }
            
            // Helper to determine node radius based on type
            function getNodeRadius(node) {
                // If it's a funnel-identified node, make it slightly larger
                const funnelBonus = node.is_funnel_identified ? 2 : 0;
                
                switch(node.type) {
                    case 'Investigation':
                        return 15;
                    case 'Finding':
                        return 10;
                    case 'Vulnerability':
                        return 12;
                    case 'File':
                        return 8;
                    case 'Repository':
                        return 13;
                    case 'Source':
                        return 12 + funnelBonus;
                    case 'Sink':
                        return 12 + funnelBonus;
                    case 'DataFlowPath':
                        return 10 + funnelBonus;
                    default:
                        return 8;
                }
            }
            
            // Show node details in sidebar
            function showNodeDetails(event, d) {
                document.getElementById('node-description').textContent = `${d.type}: ${d.label}`;
                document.getElementById('node-properties').textContent = JSON.stringify(d.properties, null, 2);
            }
            
            // Control buttons
            document.getElementById('zoom-in').addEventListener('click', () => {
                svg.transition().duration(500).call(zoom.scaleBy, 1.5);
            });
            
            document.getElementById('zoom-out').addEventListener('click', () => {
                svg.transition().duration(500).call(zoom.scaleBy, 0.75);
            });
            
            document.getElementById('reset').addEventListener('click', () => {
                svg.transition().duration(500).call(
                    zoom.transform, 
                    d3.zoomIdentity.translate(width / 2, height / 2).scale(1)
                );
            });
            
            // Filter controls
            function applyFilters() {
                // Get filter states
                const highlightFunnel = document.getElementById('filter-funnel').checked;
                const showSources = document.getElementById('filter-source').checked;
                const showSinks = document.getElementById('filter-sink').checked;
                const showDataFlow = document.getElementById('filter-dataflow').checked;
                const showFindings = document.getElementById('filter-findings').checked;
                
                // Apply node visibility
                node.style('display', d => {
                    if (d.type === 'Source' && !showSources) return 'none';
                    if (d.type === 'Sink' && !showSinks) return 'none';
                    if (d.type === 'DataFlowPath' && !showDataFlow) return 'none';
                    if (d.type === 'Finding' && !showFindings) return 'none';
                    return null;
                });
                
                // Apply highlighting for funnel nodes
                if (highlightFunnel) {
                    node.attr('stroke', d => d.is_funnel_identified ? (d.stroke_color || '#FFD700') : '#fff')
                        .attr('stroke-width', d => d.is_funnel_identified ? (d.stroke_width || 3) : 1.5)
                        .classed('funnel-node', d => d.is_funnel_identified);
                } else {
                    node.attr('stroke', '#fff')
                        .attr('stroke-width', 1.5)
                        .classed('funnel-node', false);
                }
                
                // Update links based on node visibility
                link.style('display', d => {
                    // Get the source and target nodes
                    const sourceNode = graphData.nodes.find(n => n.id === d.source.id);
                    const targetNode = graphData.nodes.find(n => n.id === d.target.id);
                    
                    // Hide link if either source or target is hidden
                    if (sourceNode && targetNode) {
                        if (sourceNode.type === 'Source' && !showSources) return 'none';
                        if (sourceNode.type === 'Sink' && !showSinks) return 'none';
                        if (sourceNode.type === 'DataFlowPath' && !showDataFlow) return 'none';
                        if (sourceNode.type === 'Finding' && !showFindings) return 'none';
                        
                        if (targetNode.type === 'Source' && !showSources) return 'none';
                        if (targetNode.type === 'Sink' && !showSinks) return 'none';
                        if (targetNode.type === 'DataFlowPath' && !showDataFlow) return 'none';
                        if (targetNode.type === 'Finding' && !showFindings) return 'none';
                    }
                    
                    return null;
                });
                
                // Update link style
                link.attr('stroke', d => {
                    // Get the source and target nodes
                    const sourceNode = graphData.nodes.find(n => n.id === d.source.id);
                    const targetNode = graphData.nodes.find(n => n.id === d.target.id);
                    
                    // Highlight links between funnel-identified nodes if highlighting is enabled
                    if (highlightFunnel && sourceNode && targetNode) {
                        if (sourceNode.is_funnel_identified && targetNode.is_funnel_identified) {
                            return '#FFD700';  // Gold for funnel links
                        }
                    }
                    
                    return '#999';  // Default color
                });
            }
            
            // Add event listeners for filters
            document.getElementById('filter-funnel').addEventListener('change', applyFilters);
            document.getElementById('filter-source').addEventListener('change', applyFilters);
            document.getElementById('filter-sink').addEventListener('change', applyFilters);
            document.getElementById('filter-dataflow').addEventListener('change', applyFilters);
            document.getElementById('filter-findings').addEventListener('change', applyFilters);
            
            // Apply filters on initial load
            applyFilters();
            
            // Initial reset to center the graph
            svg.call(
                zoom.transform,
                d3.zoomIdentity.translate(width / 2, height / 2).scale(1)
            );
        """
        )

        # Build the HTML page
        html = [
            "<!DOCTYPE html>",
            "<html>",
            "<head>",
            "<meta charset='utf-8'>",
            f"<title>{title}</title>",
            "<script src='https://d3js.org/d3.v7.min.js'></script>",
            "<style>",
            css_styles,
            "</style>",
            "</head>",
            "<body>",
            "<div class='container'>",
            "<div class='graph' id='graph'></div>",
            "<div class='sidebar'>",
            f"<h1>{title}</h1>",
            "<div class='controls'>",
            "<button id='zoom-in'>Zoom In</button>",
            "<button id='zoom-out'>Zoom Out</button>",
            "<button id='reset'>Reset</button>",
            "</div>",
            "<div class='controls'>",
            "<h3>Filter Nodes</h3>",
            "<div style='margin-bottom: 5px;'>",
            "<input type='checkbox' id='filter-funnel' checked>",
            "<label for='filter-funnel'>Highlight Funnel Nodes</label>",
            "</div>",
            "<div style='margin-bottom: 5px;'>",
            "<input type='checkbox' id='filter-source' checked>",
            "<label for='filter-source'>Show Sources</label>",
            "</div>",
            "<div style='margin-bottom: 5px;'>",
            "<input type='checkbox' id='filter-sink' checked>",
            "<label for='filter-sink'>Show Sinks</label>",
            "</div>",
            "<div style='margin-bottom: 5px;'>",
            "<input type='checkbox' id='filter-dataflow' checked>",
            "<label for='filter-dataflow'>Show Data Flow Paths</label>",
            "</div>",
            "<div style='margin-bottom: 5px;'>",
            "<input type='checkbox' id='filter-findings' checked>",
            "<label for='filter-findings'>Show Findings</label>",
            "</div>",
            "</div>",
            "<div class='legend'>",
            "<h2>Legend</h2>",
            "<div class='legend-item'>",
            "<div class='legend-color' style='background-color: #4b76e8;'></div>",
            "<div>Investigation</div>",
            "</div>",
            "<div class='legend-item'>",
            "<div class='legend-color' style='background-color: #f94144;'></div>",
            "<div>Finding</div>",
            "</div>",
            "<div class='legend-item'>",
            "<div class='legend-color' style='background-color: #e83e8c;'></div>",
            "<div>Vulnerability</div>",
            "</div>",
            "<div class='legend-item'>",
            "<div class='legend-color' style='background-color: #20c997;'></div>",
            "<div>File</div>",
            "</div>",
            "<div class='legend-item'>",
            "<div class='legend-color' style='background-color: #6610f2;'></div>",
            "<div>Repository</div>",
            "</div>",
            "<div class='legend-item'>",
            "<div class='legend-color' style='background-color: #02ccfa;'></div>",
            "<div>Source</div>",
            "</div>",
            "<div class='legend-item'>",
            "<div class='legend-color' style='background-color: #fa7602;'></div>",
            "<div>Sink</div>",
            "</div>",
            "<div class='legend-item'>",
            "<div class='legend-color' style='background-color: #fa0290;'></div>",
            "<div>DataFlowPath</div>",
            "</div>",
            "<h3>Funnel Identified Nodes</h3>",
            "<div class='legend-item'>",
            "<div class='legend-funnel' style='background-color: #02ccfa;'></div>",
            "<div>Source (Funnel Identified)</div>",
            "</div>",
            "<div class='legend-item'>",
            "<div class='legend-funnel' style='background-color: #fa7602;'></div>",
            "<div>Sink (Funnel Identified)</div>",
            "</div>",
            "</div>",
            "<div class='node-details'>",
            "<h2>Node Details</h2>",
            "<p id='node-description'>Click on a node to see details</p>",
            "<pre id='node-properties'></pre>",
            "</div>",
            "</div>",
            "</div>",
            "<div class='tooltip' id='tooltip'></div>",
            "<script>",
            d3_script,
            "</script>",
            "</body>",
            "</html>",
        ]

        try:
            return "\n".join(html)
        except Exception as e:
            logger.error(f"Error generating HTML template: {str(e)}")
            # Return a simplified HTML with error message
            return f"""
            <!DOCTYPE html>
            <html>
            <head><title>Error: {title}</title></head>
            <body>
                <h1>Error Generating Visualization</h1>
                <p>There was an error generating the visualization: {str(e)}</p>
                <p>Please check the server logs for more details.</p>
            </body>
            </html>
            """

"""Graph visualization tools for Skwaq.

This module provides tools for visualizing and exporting Neo4j graph data
in various formats, with a focus on Investigation visualization.
"""

import os
import json
from typing import Dict, List, Any, Optional, Tuple, Union
import uuid
from pathlib import Path
import tempfile

from skwaq.db.neo4j_connector import get_connector
from skwaq.utils.logging import get_logger

logger = get_logger(__name__)


class GraphVisualizer:
    """Graph visualization tools for Neo4j data.

    This class provides functionality to extract, format, and export graph data
    for visualization purposes.
    """

    def __init__(self):
        """Initialize the graph visualizer."""
        self.connector = get_connector()

    def get_investigation_graph(
        self,
        investigation_id: str,
        include_findings: bool = True,
        include_vulnerabilities: bool = True,
        include_files: bool = True,
        include_sources_sinks: bool = False,
        max_nodes: int = 100,
    ) -> Dict[str, Any]:
        """Get the graph data for an investigation.

        Args:
            investigation_id: ID of the investigation
            include_findings: Whether to include Finding nodes
            include_vulnerabilities: Whether to include Vulnerability nodes
            include_files: Whether to include File nodes
            include_sources_sinks: Whether to include Source and Sink nodes with data flow paths
            max_nodes: Maximum number of nodes to include

        Returns:
            A dictionary containing nodes and edges for graph visualization
        """
        if not self.connector.connect():
            logger.error("Failed to connect to database")
            return {"nodes": [], "links": []}

        # Start with the Investigation node
        query = """
        MATCH (i:Investigation {id: $investigation_id})
        RETURN elementId(i) as id, i.workflow_id as workflow_id, i.repository_id as repository_id,
               i.created_at as created_at, i.updated_at as updated_at
        """

        investigation_result = self.connector.run_query(
            query, {"investigation_id": investigation_id}
        )

        if not investigation_result:
            logger.warning(f"Investigation {investigation_id} not found")
            return {"nodes": [], "links": []}

        # Initialize the graph data structure
        graph_data = {"nodes": [], "links": []}

        # Add the investigation node
        investigation = investigation_result[0]
        graph_data["nodes"].append(
            {
                "id": f"i-{investigation['id']}",
                "label": "Investigation",
                "type": "investigation",
                "properties": {
                    "id": investigation_id,
                    "workflow_id": investigation.get("workflow_id"),
                    "created_at": investigation.get("created_at"),
                    "updated_at": investigation.get("updated_at"),
                },
            }
        )

        # Get the repository node
        repository_id = investigation.get("repository_id")
        if repository_id:
            repo_query = """
            MATCH (r:Repository {id: $repository_id})
            RETURN elementId(r) as id, r.name as name, r.url as url, r.description as description
            """

            repo_result = self.connector.run_query(
                repo_query, {"repository_id": repository_id}
            )

            if repo_result:
                repo = repo_result[0]
                graph_data["nodes"].append(
                    {
                        "id": f"r-{repo['id']}",
                        "label": "Repository",
                        "type": "repository",
                        "properties": {
                            "name": repo.get("name"),
                            "url": repo.get("url"),
                            "description": repo.get("description"),
                        },
                    }
                )

                # Add link from investigation to repository
                graph_data["links"].append(
                    {
                        "source": f"i-{investigation['id']}",
                        "target": f"r-{repo['id']}",
                        "type": "ANALYZES",
                    }
                )

        # Get findings if requested
        if include_findings:
            findings_query = """
            MATCH (i:Investigation {id: $investigation_id})-[r:HAS_FINDING]->(f:Finding)
            RETURN elementId(f) as id, f.vulnerability_type as type, f.severity as severity, 
                  f.confidence as confidence, f.description as description,
                  f.remediation as remediation, f.file_path as file_path
            LIMIT $max_nodes
            """

            findings_result = self.connector.run_query(
                findings_query,
                {"investigation_id": investigation_id, "max_nodes": max_nodes},
            )

            for finding in findings_result:
                finding_id = finding["id"]
                graph_data["nodes"].append(
                    {
                        "id": f"f-{finding_id}",
                        "label": "Finding",
                        "type": "finding",
                        "properties": {
                            "type": finding.get("type"),
                            "severity": finding.get("severity"),
                            "confidence": finding.get("confidence"),
                            "description": finding.get("description"),
                            "file_path": finding.get("file_path"),
                        },
                    }
                )

                # Add link from investigation to finding
                graph_data["links"].append(
                    {
                        "source": f"i-{investigation['id']}",
                        "target": f"f-{finding_id}",
                        "type": "HAS_FINDING",
                    }
                )

                # Get vulnerabilities for this finding if requested
                if include_vulnerabilities:
                    vuln_query = """
                    MATCH (f:Finding)-[r:IDENTIFIES]->(v:Vulnerability)
                    WHERE elementId(f) = $finding_id
                    RETURN elementId(v) as id, v.type as type, v.severity as severity, 
                          v.cwe_id as cwe_id, v.description as description
                    """

                    vuln_result = self.connector.run_query(
                        vuln_query, {"finding_id": finding_id}
                    )

                    for vuln in vuln_result:
                        vuln_id = vuln["id"]
                        graph_data["nodes"].append(
                            {
                                "id": f"v-{vuln_id}",
                                "label": "Vulnerability",
                                "type": "vulnerability",
                                "properties": {
                                    "type": vuln.get("type"),
                                    "severity": vuln.get("severity"),
                                    "cwe_id": vuln.get("cwe_id"),
                                    "description": vuln.get("description"),
                                },
                            }
                        )

                        # Add link from finding to vulnerability
                        graph_data["links"].append(
                            {
                                "source": f"f-{finding_id}",
                                "target": f"v-{vuln_id}",
                                "type": "IDENTIFIES",
                            }
                        )

                # Get file nodes if requested and a file path exists
                if include_files and finding.get("file_path"):
                    file_query = """
                    MATCH (f:File)
                    WHERE f.path = $file_path
                    RETURN elementId(f) as id, f.path as path, f.name as name, f.language as language
                    """

                    file_result = self.connector.run_query(
                        file_query, {"file_path": finding.get("file_path")}
                    )

                    for file in file_result:
                        file_id = file["id"]
                        graph_data["nodes"].append(
                            {
                                "id": f"file-{file_id}",
                                "label": "File",
                                "type": "file",
                                "properties": {
                                    "path": file.get("path"),
                                    "name": file.get("name"),
                                    "language": file.get("language"),
                                },
                            }
                        )

                        # Add link from finding to file
                        graph_data["links"].append(
                            {
                                "source": f"f-{finding_id}",
                                "target": f"file-{file_id}",
                                "type": "FOUND_IN",
                            }
                        )

        # Add sources and sinks if requested
        if include_sources_sinks:
            # Get source nodes
            sources_query = """
            MATCH (i:Investigation {id: $investigation_id})-[:HAS_SOURCE]->(s:Source)
            RETURN elementId(s) as id, s.name as name, s.source_type as source_type, 
                  s.description as description, s.confidence as confidence,
                  s.is_funnel_identified as is_funnel_identified
            LIMIT $max_nodes
            """

            sources_result = self.connector.run_query(
                sources_query,
                {"investigation_id": investigation_id, "max_nodes": max_nodes},
            )

            for source in sources_result:
                source_id = source["id"]
                graph_data["nodes"].append(
                    {
                        "id": f"s-{source_id}",
                        "label": source.get("name", "Source"),
                        "type": "source",
                        "is_funnel_identified": source.get(
                            "is_funnel_identified", False
                        ),
                        "properties": {
                            "name": source.get("name"),
                            "source_type": source.get("source_type"),
                            "description": source.get("description"),
                            "confidence": source.get("confidence"),
                        },
                    }
                )

                # Add link from investigation to source
                graph_data["links"].append(
                    {
                        "source": f"i-{investigation['id']}",
                        "target": f"s-{source_id}",
                        "type": "HAS_SOURCE",
                    }
                )

                # Find related method/function if available
                method_query = """
                MATCH (s:Source)-[:DEFINED_IN]->(m:Method)
                WHERE elementId(s) = $source_id
                RETURN elementId(m) as id, m.name as name, m.signature as signature
                """

                method_result = self.connector.run_query(
                    method_query, {"source_id": source_id}
                )

                for method in method_result:
                    method_id = method["id"]
                    # Check if method node already exists
                    if not any(
                        node["id"] == f"m-{method_id}" for node in graph_data["nodes"]
                    ):
                        graph_data["nodes"].append(
                            {
                                "id": f"m-{method_id}",
                                "label": method.get("name", "Method"),
                                "type": "method",
                                "is_funnel_identified": False,
                                "properties": {
                                    "name": method.get("name"),
                                    "signature": method.get("signature"),
                                },
                            }
                        )

                    # Add link from source to method
                    graph_data["links"].append(
                        {
                            "source": f"s-{source_id}",
                            "target": f"m-{method_id}",
                            "type": "DEFINED_IN",
                        }
                    )

            # Get sink nodes
            sinks_query = """
            MATCH (i:Investigation {id: $investigation_id})-[:HAS_SINK]->(s:Sink)
            RETURN elementId(s) as id, s.name as name, s.sink_type as sink_type, 
                  s.description as description, s.confidence as confidence,
                  s.is_funnel_identified as is_funnel_identified
            LIMIT $max_nodes
            """

            sinks_result = self.connector.run_query(
                sinks_query,
                {"investigation_id": investigation_id, "max_nodes": max_nodes},
            )

            for sink in sinks_result:
                sink_id = sink["id"]
                graph_data["nodes"].append(
                    {
                        "id": f"sk-{sink_id}",
                        "label": sink.get("name", "Sink"),
                        "type": "sink",
                        "is_funnel_identified": sink.get("is_funnel_identified", False),
                        "properties": {
                            "name": sink.get("name"),
                            "sink_type": sink.get("sink_type"),
                            "description": sink.get("description"),
                            "confidence": sink.get("confidence"),
                        },
                    }
                )

                # Add link from investigation to sink
                graph_data["links"].append(
                    {
                        "source": f"i-{investigation['id']}",
                        "target": f"sk-{sink_id}",
                        "type": "HAS_SINK",
                    }
                )

                # Find related method/function if available
                method_query = """
                MATCH (s:Sink)-[:DEFINED_IN]->(m:Method)
                WHERE elementId(s) = $sink_id
                RETURN elementId(m) as id, m.name as name, m.signature as signature
                """

                method_result = self.connector.run_query(
                    method_query, {"sink_id": sink_id}
                )

                for method in method_result:
                    method_id = method["id"]
                    # Check if method node already exists
                    if not any(
                        node["id"] == f"m-{method_id}" for node in graph_data["nodes"]
                    ):
                        graph_data["nodes"].append(
                            {
                                "id": f"m-{method_id}",
                                "label": method.get("name", "Method"),
                                "type": "method",
                                "is_funnel_identified": False,
                                "properties": {
                                    "name": method.get("name"),
                                    "signature": method.get("signature"),
                                },
                            }
                        )

                    # Add link from sink to method
                    graph_data["links"].append(
                        {
                            "source": f"sk-{sink_id}",
                            "target": f"m-{method_id}",
                            "type": "DEFINED_IN",
                        }
                    )

            # Get data flow paths
            dataflow_query = """
            MATCH (i:Investigation {id: $investigation_id})-[:HAS_DATA_FLOW_PATH]->(d:DataFlowPath)
            RETURN elementId(d) as id, d.label as label, d.vulnerability_type as vulnerability_type, 
                  d.impact as impact, d.description as description, d.confidence as confidence,
                  d.recommendations as recommendations, d.is_funnel_identified as is_funnel_identified
            LIMIT $max_nodes
            """

            dataflow_result = self.connector.run_query(
                dataflow_query,
                {"investigation_id": investigation_id, "max_nodes": max_nodes},
            )

            for dataflow in dataflow_result:
                dataflow_id = dataflow["id"]
                graph_data["nodes"].append(
                    {
                        "id": f"df-{dataflow_id}",
                        "label": dataflow.get("label", "Data Flow Path"),
                        "type": "dataFlowPath",
                        "is_funnel_identified": dataflow.get(
                            "is_funnel_identified", False
                        ),
                        "properties": {
                            "vulnerability_type": dataflow.get("vulnerability_type"),
                            "impact": dataflow.get("impact"),
                            "description": dataflow.get("description"),
                            "confidence": dataflow.get("confidence"),
                            "recommendations": dataflow.get("recommendations", []),
                        },
                    }
                )

                # Add link from investigation to data flow path
                graph_data["links"].append(
                    {
                        "source": f"i-{investigation['id']}",
                        "target": f"df-{dataflow_id}",
                        "type": "HAS_DATA_FLOW_PATH",
                    }
                )

                # Find related sources and sinks
                source_flow_query = """
                MATCH (s:Source)-[:FLOWS_TO]->(d:DataFlowPath)
                WHERE elementId(d) = $dataflow_id
                RETURN elementId(s) as id
                """

                source_flow_results = self.connector.run_query(
                    source_flow_query, {"dataflow_id": dataflow_id}
                )

                for source_flow in source_flow_results:
                    source_id = source_flow["id"]
                    # Add flow link from source to data flow path
                    graph_data["links"].append(
                        {
                            "source": f"s-{source_id}",
                            "target": f"df-{dataflow_id}",
                            "type": "FLOWS_TO",
                        }
                    )

                sink_flow_query = """
                MATCH (d:DataFlowPath)-[:FLOWS_TO]->(s:Sink)
                WHERE elementId(d) = $dataflow_id
                RETURN elementId(s) as id
                """

                sink_flow_results = self.connector.run_query(
                    sink_flow_query, {"dataflow_id": dataflow_id}
                )

                for sink_flow in sink_flow_results:
                    sink_id = sink_flow["id"]
                    # Add flow link from data flow path to sink
                    graph_data["links"].append(
                        {
                            "source": f"df-{dataflow_id}",
                            "target": f"sk-{sink_id}",
                            "type": "FLOWS_TO",
                        }
                    )

        return graph_data

    def export_graph_as_json(
        self, graph_data: Dict[str, Any], output_path: Optional[str] = None
    ) -> str:
        """Export graph data as JSON.

        Args:
            graph_data: Graph data with nodes and links
            output_path: Optional output file path

        Returns:
            Path to the exported file
        """
        if not output_path:
            # Create a temp file with a unique name
            timestamp = uuid.uuid4().hex[:8]
            output_path = os.path.join(
                tempfile.gettempdir(), f"graph_export_{timestamp}.json"
            )

        with open(output_path, "w") as f:
            json.dump(graph_data, f, indent=2)

        logger.info(f"Graph exported as JSON to {output_path}")
        return output_path

    def export_graph_as_html(
        self,
        graph_data: Dict[str, Any],
        output_path: Optional[str] = None,
        title: str = "Investigation Graph",
    ) -> str:
        """Export graph data as an interactive HTML visualization.

        Uses D3.js to create an interactive force-directed graph visualization.

        Args:
            graph_data: Graph data with nodes and links
            output_path: Optional output file path
            title: Title for the visualization

        Returns:
            Path to the exported HTML file
        """
        if not output_path:
            # Create a temp file with a unique name
            timestamp = uuid.uuid4().hex[:8]
            output_path = os.path.join(
                tempfile.gettempdir(), f"graph_viz_{timestamp}.html"
            )

        # Enhanced HTML template with D3.js for interactive visualization
        html_template = """
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>{title}</title>
    <script src="https://d3js.org/d3.v7.min.js"></script>
    <style>
        body {{ margin: 0; font-family: Arial, sans-serif; overflow: hidden; }}
        .container {{ display: flex; height: 100vh; flex-direction: row-reverse; }}
        .graph {{ flex: 1; }}
        .sidebar {{ width: 300px; padding: 20px; background: #f8f9fa; overflow-y: auto; }}
        .node {{ stroke: #fff; stroke-width: 1.5px; }}
        .funnel-node {{ animation: pulse 2s infinite; }}
        .link {{ stroke: #999; stroke-opacity: 0.6; }}
        h1 {{ font-size: 24px; margin-top: 0; }}
        h2 {{ font-size: 18px; margin-top: 20px; }}
        pre {{ background: #f1f1f1; padding: 10px; overflow: auto; }}
        .controls {{ margin: 20px 0; }}
        button {{ background: #4b76e8; color: white; border: none; padding: 8px 12px; margin-right: 5px; cursor: pointer; }}
        button:hover {{ background: #3a5bbf; }}
        .node-details {{ margin-top: 20px; }}
        .legend {{ margin-top: 20px; }}
        .legend-item {{ display: flex; align-items: center; margin-bottom: 5px; }}
        .legend-color {{ width: 15px; height: 15px; margin-right: 8px; }}
        .legend-funnel {{ width: 15px; height: 15px; margin-right: 8px; border: 2px solid #FFD700; }}
        .zoom-controls {{ position: absolute; top: 20px; left: 20px; background: rgba(255,255,255,0.7); padding: 10px; border-radius: 5px; }}
        .tooltip {{ position: absolute; background: white; border: 1px solid #ddd; padding: 10px; border-radius: 5px; pointer-events: none; opacity: 0; }}
        @keyframes pulse {{
            0% {{
                stroke-width: 1.5px;
                stroke-opacity: 1;
            }}
            50% {{
                stroke-width: 4px;
                stroke-opacity: 0.8;
            }}
            100% {{
                stroke-width: 1.5px;
                stroke-opacity: 1;
            }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="graph" id="graph"></div>
        <div class="sidebar">
            <h1>{title}</h1>
            <div class="controls">
                <button id="zoom-in">Zoom In</button>
                <button id="zoom-out">Zoom Out</button>
                <button id="reset">Reset</button>
            </div>
            <div class="controls">
                <h3>Filter Nodes</h3>
                <div style="margin-bottom: 5px;">
                    <input type="checkbox" id="filter-funnel" checked>
                    <label for="filter-funnel">Highlight Funnel Nodes</label>
                </div>
                <div style="margin-bottom: 5px;">
                    <input type="checkbox" id="filter-source" checked>
                    <label for="filter-source">Show Sources</label>
                </div>
                <div style="margin-bottom: 5px;">
                    <input type="checkbox" id="filter-sink" checked>
                    <label for="filter-sink">Show Sinks</label>
                </div>
                <div style="margin-bottom: 5px;">
                    <input type="checkbox" id="filter-dataflow" checked>
                    <label for="filter-dataflow">Show Data Flow Paths</label>
                </div>
                <div style="margin-bottom: 5px;">
                    <input type="checkbox" id="filter-findings" checked>
                    <label for="filter-findings">Show Findings</label>
                </div>
                <div style="margin-bottom: 5px;">
                    <input type="checkbox" id="filter-vulnerability" checked>
                    <label for="filter-vulnerability">Show Vulnerabilities</label>
                </div>
                <div style="margin-bottom: 5px;">
                    <input type="checkbox" id="filter-method" checked>
                    <label for="filter-method">Show Methods</label>
                </div>
                <div style="margin-bottom: 5px;">
                    <input type="checkbox" id="filter-files" checked>
                    <label for="filter-files">Show Files</label>
                </div>
            </div>
            <div class="legend">
                <h2>Legend</h2>
                <div class="legend-item">
                    <div class="legend-color" style="background-color: #4b76e8;"></div>
                    <div>Investigation</div>
                </div>
                <div class="legend-item">
                    <div class="legend-color" style="background-color: #f94144;"></div>
                    <div>Finding</div>
                </div>
                <div class="legend-item">
                    <div class="legend-color" style="background-color: #6610f2;"></div>
                    <div>Repository</div>
                </div>
                <div class="legend-item">
                    <div class="legend-color" style="background-color: #9b59b6;"></div>
                    <div>Vulnerability</div>
                </div>
                <div class="legend-item">
                    <div class="legend-color" style="background-color: #20c997;"></div>
                    <div>File</div>
                </div>
                <div class="legend-item">
                    <div class="legend-color" style="background-color: #02ccfa;"></div>
                    <div>Source</div>
                </div>
                <div class="legend-item">
                    <div class="legend-color" style="background-color: #fa7602;"></div>
                    <div>Sink</div>
                </div>
                <div class="legend-item">
                    <div class="legend-color" style="background-color: #fa0290;"></div>
                    <div>DataFlowPath</div>
                </div>
                <div class="legend-item">
                    <div class="legend-color" style="background-color: #9370db;"></div>
                    <div>Method</div>
                </div>
                <h3>Funnel Identified Nodes</h3>
                <div class="legend-item">
                    <div class="legend-funnel" style="background-color: #02ccfa;"></div>
                    <div>Source (Funnel Identified)</div>
                </div>
                <div class="legend-item">
                    <div class="legend-funnel" style="background-color: #fa7602;"></div>
                    <div>Sink (Funnel Identified)</div>
                </div>
                <div class="legend-item">
                    <div class="legend-funnel" style="background-color: #fa0290;"></div>
                    <div>DataFlowPath (Funnel Identified)</div>
                </div>
            </div>
            <div class="node-details">
                <h2>Node Details</h2>
                <p id="node-description">Click on a node to see details</p>
                <pre id="node-properties">{{}}</pre>
            </div>
        </div>
    </div>
    <div class="tooltip" id="tooltip"></div>
    <script>
        // Graph data
        const graphData = {data};
        
        // Process graph data to ensure proper structure
        graphData.nodes.forEach(node => {{
            // Default funnel identification to false if not specified
            if (node.is_funnel_identified === undefined) {{
                node.is_funnel_identified = false;
            }}
            
            // Assign colors based on node type
            switch(node.type) {{
                case "investigation":
                    node.color = "#4b76e8";
                    break;
                case "repository":
                    node.color = "#6610f2";
                    break;
                case "finding":
                    node.color = "#f94144";
                    break;
                case "vulnerability":
                    node.color = "#9b59b6";
                    break;
                case "file":
                    node.color = "#20c997";
                    break;
                case "source":
                    node.color = "#02ccfa";
                    break;
                case "sink":
                    node.color = "#fa7602";
                    break;
                case "dataFlowPath":
                    node.color = "#fa0290";
                    break;
                case "method":
                    node.color = "#9370db";
                    break;
                default:
                    node.color = "#999";
            }}
        }});
        
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
            .on('zoom', (event) => {{
                g.attr('transform', event.transform);
            }});
        
        // Apply zoom to SVG
        svg.call(zoom);
        
        // Create a group for the graph
        const g = svg.append('g');
        
        // Initialize the simulation with a custom force layout
        const simulation = d3.forceSimulation(graphData.nodes)
            .force('link', d3.forceLink(graphData.links).id(d => d.id).distance(150))
            .force('charge', d3.forceManyBody().strength(-500))
            .force('x', d3.forceX(width / 3).strength(0.1))  // Pull nodes toward left third
            .force('y', d3.forceY(height / 3).strength(0.1)) // Pull nodes toward top third
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
            .on('mouseover', function(event, d) {{
                tooltip.transition()
                    .duration(200)
                    .style('opacity', .9);
                
                // Create tooltip content
                let tooltipContent = `<strong>${d.label}</strong><br/>${d.type}`;
                
                // Add funnel identification badge if applicable
                if (d.is_funnel_identified) {{
                    tooltipContent += `<br/><span style="color: #FFD700; font-weight: bold;">⭐ Funnel Identified</span>`;
                    
                    // Add source or sink specific info
                    if (d.type === 'source') {{
                        tooltipContent += `<br/>Source Type: ${d.properties?.source_type || 'Unknown'}`;
                        tooltipContent += `<br/>Confidence: ${(d.properties?.confidence * 100).toFixed(0)}%`;
                    }} else if (d.type === 'sink') {{
                        tooltipContent += `<br/>Sink Type: ${d.properties?.sink_type || 'Unknown'}`;
                        tooltipContent += `<br/>Confidence: ${(d.properties?.confidence * 100).toFixed(0)}%`;
                    }} else if (d.type === 'dataFlowPath') {{
                        tooltipContent += `<br/>Vulnerability: ${d.properties?.vulnerability_type || 'Unknown'}`;
                        tooltipContent += `<br/>Impact: ${d.properties?.impact || 'Unknown'}`;
                    }}
                }}
                
                tooltip.html(tooltipContent)
                    .style('left', (event.pageX + 10) + 'px')
                    .style('top', (event.pageY - 28) + 'px');
            }})
            .on('mouseout', function() {{
                tooltip.transition()
                    .duration(500)
                    .style('opacity', 0);
            }})
            .on('click', showNodeDetails);
        
        // Simulation tick function
        function ticked() {{
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
        }}
        
        // Drag functions
        function dragstarted(event, d) {{
            if (!event.active) simulation.alphaTarget(0.3).restart();
            d.fx = d.x;
            d.fy = d.y;
        }}
        
        function dragged(event, d) {{
            d.fx = event.x;
            d.fy = event.y;
        }}
        
        function dragended(event, d) {{
            if (!event.active) simulation.alphaTarget(0);
            d.fx = null;
            d.fy = null;
        }}
        
        // Helper to determine node radius based on type
        function getNodeRadius(node) {{
            // If it's a funnel-identified node, make it slightly larger
            const funnelBonus = node.is_funnel_identified ? 2 : 0;
            
            switch(node.type) {{
                case 'investigation':
                    return 15;
                case 'finding':
                    return 10;
                case 'vulnerability':
                    return 12;
                case 'file':
                    return 8;
                case 'repository':
                    return 13;
                case 'source':
                    return 12 + funnelBonus;
                case 'sink':
                    return 12 + funnelBonus;
                case 'dataFlowPath':
                    return 10 + funnelBonus;
                case 'method':
                    return 7;
                default:
                    return 8;
            }}
        }}
        
        // Show node details in sidebar
        function showNodeDetails(event, d) {{
            document.getElementById('node-description').textContent = `${d.type}: ${d.label}`;
            document.getElementById('node-properties').textContent = JSON.stringify(d.properties || {{}}, null, 2);
        }}
        
        // Control buttons
        document.getElementById('zoom-in').addEventListener('click', () => {{
            svg.transition().duration(500).call(zoom.scaleBy, 1.5);
        }});
        
        document.getElementById('zoom-out').addEventListener('click', () => {{
            svg.transition().duration(500).call(zoom.scaleBy, 0.75);
        }});
        
        document.getElementById('reset').addEventListener('click', () => {{
            svg.transition().duration(500).call(
                zoom.transform, 
                d3.zoomIdentity.translate(width / 2, height / 2).scale(1)
            );
        }});
        
        // Filter controls
        function applyFilters() {{
            // Get filter states
            const highlightFunnel = document.getElementById('filter-funnel').checked;
            const showSources = document.getElementById('filter-source').checked;
            const showSinks = document.getElementById('filter-sink').checked;
            const showDataFlow = document.getElementById('filter-dataflow').checked;
            const showFindings = document.getElementById('filter-findings').checked;
            const showVulnerability = document.getElementById('filter-vulnerability').checked;
            const showMethod = document.getElementById('filter-method').checked;
            const showFiles = document.getElementById('filter-files').checked;
            
            // Apply node visibility
            node.style('display', d => {{
                if (d.type === 'source' && !showSources) return 'none';
                if (d.type === 'sink' && !showSinks) return 'none';
                if (d.type === 'dataFlowPath' && !showDataFlow) return 'none';
                if (d.type === 'finding' && !showFindings) return 'none';
                if (d.type === 'vulnerability' && !showVulnerability) return 'none';
                if (d.type === 'method' && !showMethod) return 'none';
                if (d.type === 'file' && !showFiles) return 'none';
                return null;
            }});
            
            // Apply node label visibility
            label.style('display', d => {{
                if (d.type === 'source' && !showSources) return 'none';
                if (d.type === 'sink' && !showSinks) return 'none';
                if (d.type === 'dataFlowPath' && !showDataFlow) return 'none';
                if (d.type === 'finding' && !showFindings) return 'none';
                if (d.type === 'vulnerability' && !showVulnerability) return 'none';
                if (d.type === 'method' && !showMethod) return 'none';
                if (d.type === 'file' && !showFiles) return 'none';
                return null;
            }});
            
            // Apply highlighting for funnel nodes
            if (highlightFunnel) {{
                node.attr('stroke', d => d.is_funnel_identified ? (d.stroke_color || '#FFD700') : '#fff')
                    .attr('stroke-width', d => d.is_funnel_identified ? (d.stroke_width || 3) : 1.5)
                    .classed('funnel-node', d => d.is_funnel_identified);
            }} else {{
                node.attr('stroke', '#fff')
                    .attr('stroke-width', 1.5)
                    .classed('funnel-node', false);
            }}
            
            // Update links based on node visibility
            link.style('display', d => {{
                // Get the source and target nodes
                const sourceNode = graphData.nodes.find(n => n.id === d.source.id);
                const targetNode = graphData.nodes.find(n => n.id === d.target.id);
                
                // Hide link if either source or target is hidden
                if (sourceNode && targetNode) {{
                    if (sourceNode.type === 'source' && !showSources) return 'none';
                    if (sourceNode.type === 'sink' && !showSinks) return 'none';
                    if (sourceNode.type === 'dataFlowPath' && !showDataFlow) return 'none';
                    if (sourceNode.type === 'finding' && !showFindings) return 'none';
                    if (sourceNode.type === 'vulnerability' && !showVulnerability) return 'none';
                    if (sourceNode.type === 'method' && !showMethod) return 'none';
                    if (sourceNode.type === 'file' && !showFiles) return 'none';
                    
                    if (targetNode.type === 'source' && !showSources) return 'none';
                    if (targetNode.type === 'sink' && !showSinks) return 'none';
                    if (targetNode.type === 'dataFlowPath' && !showDataFlow) return 'none';
                    if (targetNode.type === 'finding' && !showFindings) return 'none';
                    if (targetNode.type === 'vulnerability' && !showVulnerability) return 'none';
                    if (targetNode.type === 'method' && !showMethod) return 'none';
                    if (targetNode.type === 'file' && !showFiles) return 'none';
                }}
                
                return null;
            }});
            
            // Update link style
            link.attr('stroke', d => {{
                // Get the source and target nodes
                const sourceNode = graphData.nodes.find(n => n.id === d.source.id);
                const targetNode = graphData.nodes.find(n => n.id === d.target.id);
                
                // Highlight links between funnel-identified nodes if highlighting is enabled
                if (highlightFunnel && sourceNode && targetNode) {{
                    if (sourceNode.is_funnel_identified && targetNode.is_funnel_identified) {{
                        return '#FFD700';  // Gold for funnel links
                    }}
                }}
                
                return '#999';  // Default color
            }});
        }}
        
        // Add event listeners for filters
        document.getElementById('filter-funnel').addEventListener('change', applyFilters);
        document.getElementById('filter-source').addEventListener('change', applyFilters);
        document.getElementById('filter-sink').addEventListener('change', applyFilters);
        document.getElementById('filter-dataflow').addEventListener('change', applyFilters);
        document.getElementById('filter-findings').addEventListener('change', applyFilters);
        document.getElementById('filter-vulnerability').addEventListener('change', applyFilters);
        document.getElementById('filter-method').addEventListener('change', applyFilters);
        document.getElementById('filter-files').addEventListener('change', applyFilters);
        
        // Apply filters on initial load
        applyFilters();
        
        // Initial position to top-left with some padding
        svg.call(
            zoom.transform,
            d3.zoomIdentity.translate(100, 100).scale(0.8)
        );
    </script>
</body>
</html>
        """

        # Format the HTML with the graph data
        html_content = html_template.format(title=title, data=json.dumps(graph_data))

        # Write to file
        with open(output_path, "w") as f:
            f.write(html_content)

        logger.info(f"Graph exported as HTML visualization to {output_path}")
        return output_path

    def export_graph_as_svg(
        self,
        graph_data: Dict[str, Any],
        output_path: Optional[str] = None,
        width: int = 1200,
        height: int = 800,
    ) -> str:
        """Generate a simple SVG visualization for the graph.

        This provides a static image for documentation or reports.

        Args:
            graph_data: Graph data with nodes and links
            output_path: Optional output file path
            width: Width of the SVG image
            height: Height of the SVG image

        Returns:
            Path to the exported SVG file
        """
        # This would typically use a library like graphviz or a headless browser
        # to render the D3 visualization to SVG, but for simplicity, we'll create
        # a basic SVG manually with a specific layout.

        if not output_path:
            # Create a temp file with a unique name
            timestamp = uuid.uuid4().hex[:8]
            output_path = os.path.join(
                tempfile.gettempdir(), f"graph_viz_{timestamp}.svg"
            )

        # Basic SVG template
        svg_template = """<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<svg width="{width}" height="{height}" xmlns="http://www.w3.org/2000/svg">
    <defs>
        <marker id="arrowhead" markerWidth="10" markerHeight="7" 
            refX="27" refY="3.5" orient="auto">
            <polygon points="0 0, 10 3.5, 0 7" fill="#999" />
        </marker>
    </defs>
    <rect width="{width}" height="{height}" fill="#f9f9f9" />
    <!-- Links -->
    {links}
    <!-- Nodes -->
    {nodes}
    <!-- Labels -->
    {labels}
    <!-- Legend -->
    <g transform="translate(20, 20)">
        <text x="0" y="0" font-size="16" font-weight="bold">Legend</text>
        <circle cx="10" cy="25" r="10" fill="#3498db" />
        <text x="25" y="30" font-size="12">Investigation</text>
        <circle cx="10" cy="50" r="10" fill="#2ecc71" />
        <text x="25" y="55" font-size="12">Repository</text>
        <circle cx="10" cy="75" r="10" fill="#e74c3c" />
        <text x="25" y="80" font-size="12">Finding</text>
        <circle cx="10" cy="100" r="10" fill="#9b59b6" />
        <text x="25" y="105" font-size="12">Vulnerability</text>
        <circle cx="10" cy="125" r="10" fill="#f39c12" />
        <text x="25" y="130" font-size="12">File</text>
    </g>
</svg>
        """

        # Simple force-directed layout algorithm
        nodes = graph_data["nodes"]
        links = graph_data["links"]

        # Assign positions to nodes
        center_x = width / 2
        center_y = height / 2
        radius = min(width, height) * 0.4

        # Place investigation node at the center
        investigation_node = next(
            (n for n in nodes if n["type"] == "investigation"), None
        )
        if investigation_node:
            investigation_node["x"] = center_x
            investigation_node["y"] = center_y

        # Place repository nodes in a circle around the investigation
        repo_nodes = [n for n in nodes if n["type"] == "repository"]
        repo_angle = (2 * 3.14159) / max(1, len(repo_nodes))
        for i, node in enumerate(repo_nodes):
            angle = i * repo_angle
            node["x"] = center_x + radius * 0.4 * math.cos(angle)
            node["y"] = center_y + radius * 0.4 * math.sin(angle)

        # Place finding nodes in a larger circle
        finding_nodes = [n for n in nodes if n["type"] == "finding"]
        finding_angle = (2 * 3.14159) / max(1, len(finding_nodes))
        for i, node in enumerate(finding_nodes):
            angle = i * finding_angle
            node["x"] = center_x + radius * 0.6 * math.cos(angle)
            node["y"] = center_y + radius * 0.6 * math.sin(angle)

        # Place vulnerability and file nodes near their findings
        for node in nodes:
            if node["type"] in ["vulnerability", "file"]:
                # Find connected finding
                connected_link = next(
                    (l for l in links if l["target"] == node["id"]), None
                )
                if connected_link:
                    source_node = next(
                        (n for n in nodes if n["id"] == connected_link["source"]), None
                    )
                    if source_node and "x" in source_node:
                        angle = random.random() * 2 * 3.14159
                        distance = 30 + random.random() * 20
                        node["x"] = source_node["x"] + distance * math.cos(angle)
                        node["y"] = source_node["y"] + distance * math.sin(angle)
                    else:
                        # Fallback if source node not found
                        node["x"] = center_x + (random.random() - 0.5) * radius
                        node["y"] = center_y + (random.random() - 0.5) * radius
                else:
                    # Fallback for disconnected nodes
                    node["x"] = center_x + (random.random() - 0.5) * radius
                    node["y"] = center_y + (random.random() - 0.5) * radius

        # Generate SVG elements
        svg_links = []
        for link in links:
            source_node = next((n for n in nodes if n["id"] == link["source"]), None)
            target_node = next((n for n in nodes if n["id"] == link["target"]), None)
            if (
                source_node
                and target_node
                and "x" in source_node
                and "x" in target_node
            ):
                svg_links.append(
                    f'<line x1="{source_node["x"]}" y1="{source_node["y"]}" '
                    f'x2="{target_node["x"]}" y2="{target_node["y"]}" '
                    f'stroke="#999" stroke-width="1" marker-end="url(#arrowhead)" />'
                )

        svg_nodes = []
        for node in nodes:
            if "x" not in node:  # Skip nodes without positions
                continue

            # Node colors based on type
            fill_color = "#ccc"  # Default
            if node["type"] == "investigation":
                fill_color = "#3498db"
                radius = 15
            elif node["type"] == "repository":
                fill_color = "#2ecc71"
                radius = 12
            elif node["type"] == "finding":
                fill_color = "#e74c3c"
                radius = 8
            elif node["type"] == "vulnerability":
                fill_color = "#9b59b6"
                radius = 7
            elif node["type"] == "file":
                fill_color = "#f39c12"
                radius = 5

            svg_nodes.append(
                f'<circle cx="{node["x"]}" cy="{node["y"]}" r="{radius}" '
                f'fill="{fill_color}" stroke="white" stroke-width="1.5" />'
            )

        svg_labels = []
        for node in nodes:
            if "x" not in node:  # Skip nodes without positions
                continue

            # Get label based on node type
            label = ""
            if node["type"] == "investigation":
                label = "Investigation"
            elif (
                node["type"] == "repository"
                and "properties" in node
                and "name" in node["properties"]
            ):
                label = node["properties"]["name"]
            elif (
                node["type"] == "finding"
                and "properties" in node
                and "type" in node["properties"]
            ):
                label = node["properties"]["type"]
            elif (
                node["type"] == "vulnerability"
                and "properties" in node
                and "cwe_id" in node["properties"]
            ):
                label = node["properties"]["cwe_id"]
            elif (
                node["type"] == "file"
                and "properties" in node
                and "name" in node["properties"]
            ):
                label = node["properties"]["name"]
            else:
                label = node.get("label", "")

            if label:
                svg_labels.append(
                    f'<text x="{node["x"] + 12}" y="{node["y"]}" '
                    f'font-size="10" text-anchor="start">{label}</text>'
                )

        # Render the SVG
        svg_content = svg_template.format(
            width=width,
            height=height,
            links="\n    ".join(svg_links),
            nodes="\n    ".join(svg_nodes),
            labels="\n    ".join(svg_labels),
        )

        # Write to file
        with open(output_path, "w") as f:
            f.write(svg_content)

        logger.info(f"Graph exported as SVG to {output_path}")
        return output_path


# Add missing imports for the SVG export function
import math
import random

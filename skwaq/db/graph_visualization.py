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
        
    def get_investigation_graph(self, 
                               investigation_id: str, 
                               include_findings: bool = True,
                               include_vulnerabilities: bool = True,
                               include_files: bool = True,
                               max_nodes: int = 100) -> Dict[str, Any]:
        """Get the graph data for an investigation.
        
        Args:
            investigation_id: ID of the investigation
            include_findings: Whether to include Finding nodes
            include_vulnerabilities: Whether to include Vulnerability nodes
            include_files: Whether to include File nodes
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
        
        investigation_result = self.connector.run_query(query, {"investigation_id": investigation_id})
        
        if not investigation_result:
            logger.warning(f"Investigation {investigation_id} not found")
            return {"nodes": [], "links": []}
            
        # Initialize the graph data structure
        graph_data = {
            "nodes": [],
            "links": []
        }
        
        # Add the investigation node
        investigation = investigation_result[0]
        graph_data["nodes"].append({
            "id": f"i-{investigation['id']}",
            "label": "Investigation",
            "type": "investigation",
            "properties": {
                "id": investigation_id,
                "workflow_id": investigation.get("workflow_id"),
                "created_at": investigation.get("created_at"),
                "updated_at": investigation.get("updated_at")
            }
        })
        
        # Get the repository node
        repository_id = investigation.get("repository_id")
        if repository_id:
            repo_query = """
            MATCH (r:Repository {id: $repository_id})
            RETURN elementId(r) as id, r.name as name, r.url as url, r.description as description
            """
            
            repo_result = self.connector.run_query(repo_query, {"repository_id": repository_id})
            
            if repo_result:
                repo = repo_result[0]
                graph_data["nodes"].append({
                    "id": f"r-{repo['id']}",
                    "label": "Repository",
                    "type": "repository",
                    "properties": {
                        "name": repo.get("name"),
                        "url": repo.get("url"),
                        "description": repo.get("description")
                    }
                })
                
                # Add link from investigation to repository
                graph_data["links"].append({
                    "source": f"i-{investigation['id']}",
                    "target": f"r-{repo['id']}",
                    "type": "ANALYZES"
                })
                
        # Get findings if requested
        if include_findings:
            findings_query = """
            MATCH (i:Investigation {id: $investigation_id})-[r:HAS_FINDING]->(f:Finding)
            RETURN elementId(f) as id, f.vulnerability_type as type, f.severity as severity, 
                  f.confidence as confidence, f.description as description,
                  f.remediation as remediation, f.file_path as file_path
            LIMIT $max_nodes
            """
            
            findings_result = self.connector.run_query(findings_query, {
                "investigation_id": investigation_id,
                "max_nodes": max_nodes
            })
            
            for finding in findings_result:
                finding_id = finding['id']
                graph_data["nodes"].append({
                    "id": f"f-{finding_id}",
                    "label": "Finding",
                    "type": "finding",
                    "properties": {
                        "type": finding.get("type"),
                        "severity": finding.get("severity"),
                        "confidence": finding.get("confidence"),
                        "description": finding.get("description"),
                        "file_path": finding.get("file_path")
                    }
                })
                
                # Add link from investigation to finding
                graph_data["links"].append({
                    "source": f"i-{investigation['id']}",
                    "target": f"f-{finding_id}",
                    "type": "HAS_FINDING"
                })
                
                # Get vulnerabilities for this finding if requested
                if include_vulnerabilities:
                    vuln_query = """
                    MATCH (f:Finding)-[r:IDENTIFIES]->(v:Vulnerability)
                    WHERE elementId(f) = $finding_id
                    RETURN elementId(v) as id, v.type as type, v.severity as severity, 
                          v.cwe_id as cwe_id, v.description as description
                    """
                    
                    vuln_result = self.connector.run_query(vuln_query, {"finding_id": finding_id})
                    
                    for vuln in vuln_result:
                        vuln_id = vuln['id']
                        graph_data["nodes"].append({
                            "id": f"v-{vuln_id}",
                            "label": "Vulnerability",
                            "type": "vulnerability",
                            "properties": {
                                "type": vuln.get("type"),
                                "severity": vuln.get("severity"),
                                "cwe_id": vuln.get("cwe_id"),
                                "description": vuln.get("description")
                            }
                        })
                        
                        # Add link from finding to vulnerability
                        graph_data["links"].append({
                            "source": f"f-{finding_id}",
                            "target": f"v-{vuln_id}",
                            "type": "IDENTIFIES"
                        })
                
                # Get file nodes if requested and a file path exists
                if include_files and finding.get("file_path"):
                    file_query = """
                    MATCH (f:File)
                    WHERE f.path = $file_path
                    RETURN elementId(f) as id, f.path as path, f.name as name, f.language as language
                    """
                    
                    file_result = self.connector.run_query(file_query, {"file_path": finding.get("file_path")})
                    
                    for file in file_result:
                        file_id = file['id']
                        graph_data["nodes"].append({
                            "id": f"file-{file_id}",
                            "label": "File",
                            "type": "file",
                            "properties": {
                                "path": file.get("path"),
                                "name": file.get("name"),
                                "language": file.get("language")
                            }
                        })
                        
                        # Add link from finding to file
                        graph_data["links"].append({
                            "source": f"f-{finding_id}",
                            "target": f"file-{file_id}",
                            "type": "FOUND_IN"
                        })
        
        return graph_data
        
    def export_graph_as_json(self, graph_data: Dict[str, Any], output_path: Optional[str] = None) -> str:
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
            output_path = os.path.join(tempfile.gettempdir(), f"graph_export_{timestamp}.json")
            
        with open(output_path, 'w') as f:
            json.dump(graph_data, f, indent=2)
            
        logger.info(f"Graph exported as JSON to {output_path}")
        return output_path
        
    def export_graph_as_html(self, 
                           graph_data: Dict[str, Any], 
                           output_path: Optional[str] = None,
                           title: str = "Investigation Graph") -> str:
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
            output_path = os.path.join(tempfile.gettempdir(), f"graph_viz_{timestamp}.html")
        
        # Simplified HTML template with embedded D3.js for visualization
        html_template = """
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>{title}</title>
    <script src="https://d3js.org/d3.v7.min.js"></script>
    <style>
        body {{
            margin: 0;
            font-family: Arial, sans-serif;
            overflow: hidden;
        }}
        .links line {{
            stroke: #999;
            stroke-opacity: 0.6;
        }}
        .nodes circle {{
            stroke: #fff;
            stroke-width: 1.5px;
        }}
        .node-labels {{
            font-size: 10px;
        }}
        .investigation {{ fill: #3498db; }}
        .repository {{ fill: #2ecc71; }}
        .finding {{ fill: #e74c3c; }}
        .vulnerability {{ fill: #9b59b6; }}
        .file {{ fill: #f39c12; }}
        
        .tooltip {{
            position: absolute;
            background: #fff;
            border: 1px solid #ccc;
            border-radius: 4px;
            padding: 10px;
            font-size: 12px;
            pointer-events: none;
            opacity: 0;
            max-width: 300px;
            overflow-wrap: break-word;
        }}
        .controls {{
            position: absolute;
            top: 10px;
            left: 10px;
            background: rgba(255, 255, 255, 0.8);
            padding: 10px;
            border-radius: 4px;
            border: 1px solid #ccc;
        }}
        .title {{
            font-size: 16px;
            font-weight: bold;
            margin-bottom: 5px;
        }}
    </style>
</head>
<body>
    <div class="controls">
        <div class="title">{title}</div>
    </div>
    
    <div id="tooltip" class="tooltip"></div>
    
    <script>
        // Graph data
        const graphData = {data};
        
        // Set up the SVG
        const width = window.innerWidth;
        const height = window.innerHeight;
        
        const svg = d3.select("body")
            .append("svg")
            .attr("width", width)
            .attr("height", height);
            
        // Container for the graph
        const container = svg.append("g");
        
        // Create a force simulation
        const simulation = d3.forceSimulation(graphData.nodes)
            .force("link", d3.forceLink(graphData.links).id(d => d.id).distance(100))
            .force("charge", d3.forceManyBody().strength(-300))
            .force("center", d3.forceCenter(width / 2, height / 2))
            .force("collide", d3.forceCollide(30));
        
        // Create links
        const link = container.append("g")
            .attr("class", "links")
            .selectAll("line")
            .data(graphData.links)
            .enter()
            .append("line")
            .attr("stroke-width", 1);
        
        // Create nodes
        const node = container.append("g")
            .attr("class", "nodes")
            .selectAll("circle")
            .data(graphData.nodes)
            .enter()
            .append("circle")
            .attr("r", 8)
            .attr("class", d => d.type || "default");
        
        // Update positions on each simulation tick
        simulation.on("tick", () => {{
            link
                .attr("x1", d => d.source.x)
                .attr("y1", d => d.source.y)
                .attr("x2", d => d.target.x)
                .attr("y2", d => d.target.y);
            
            node
                .attr("cx", d => d.x)
                .attr("cy", d => d.y);
        }});
    </script>
</body>
</html>
        """
        
        # Format the HTML with the graph data
        html_content = html_template.format(
            title=title,
            data=json.dumps(graph_data)
        )
        
        # Write to file
        with open(output_path, 'w') as f:
            f.write(html_content)
            
        logger.info(f"Graph exported as HTML visualization to {output_path}")
        return output_path
        
    def export_graph_as_svg(self, 
                          graph_data: Dict[str, Any], 
                          output_path: Optional[str] = None,
                          width: int = 1200,
                          height: int = 800) -> str:
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
            output_path = os.path.join(tempfile.gettempdir(), f"graph_viz_{timestamp}.svg")
            
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
        investigation_node = next((n for n in nodes if n["type"] == "investigation"), None)
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
                connected_link = next((l for l in links if l["target"] == node["id"]), None)
                if connected_link:
                    source_node = next((n for n in nodes if n["id"] == connected_link["source"]), None)
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
            if source_node and target_node and "x" in source_node and "x" in target_node:
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
            elif node["type"] == "repository" and "properties" in node and "name" in node["properties"]:
                label = node["properties"]["name"]
            elif node["type"] == "finding" and "properties" in node and "type" in node["properties"]:
                label = node["properties"]["type"]
            elif node["type"] == "vulnerability" and "properties" in node and "cwe_id" in node["properties"]:
                label = node["properties"]["cwe_id"]
            elif node["type"] == "file" and "properties" in node and "name" in node["properties"]:
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
            labels="\n    ".join(svg_labels)
        )
        
        # Write to file
        with open(output_path, 'w') as f:
            f.write(svg_content)
            
        logger.info(f"Graph exported as SVG to {output_path}")
        return output_path


# Add missing imports for the SVG export function
import math
import random
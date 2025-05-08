#!/usr/bin/env python3
"""Create a comprehensive visualization of a repository including AST nodes, files, and summaries.

This script creates a visualization of the entire repository structure, including:
1. Repository node
2. File nodes
3. AST nodes (Functions, Classes, Methods)
4. AI Summary nodes
5. All relationships between these nodes

Usage:
    python create_comprehensive_viz.py <repository_id> <output_html>
"""

import asyncio
import json
import sys
from typing import Dict, List, Any, Optional

from skwaq.db.neo4j_connector import get_connector


async def main():
    """Generate comprehensive repository visualization."""
    if len(sys.argv) < 3:
        print("Usage: python create_comprehensive_viz.py <repository_id> <output_html>")
        return

    repo_id = sys.argv[1]
    output_html = sys.argv[2]
    
    connector = get_connector()
    
    print(f"Generating comprehensive visualization for repository {repo_id}")
    
    # Query to get all relevant nodes and relationships (limited for performance)
    query = """
    // Starting with repository node
    MATCH (repo:Repository)
    WHERE repo.ingestion_id = $repo_id OR elementId(repo) = $repo_id
    
    // Get a limited subset of files for visualization
    OPTIONAL MATCH (repo)-[:CONTAINS*]->(file:File)
    // Limit by depth to get reasonable performance
    WHERE size([(file)<-[:CONTAINS*]-(d:Directory) | d]) <= 3
    WITH repo, file
    LIMIT 1000
    
    // Get file-to-file relationships
    OPTIONAL MATCH (file)-[:CONTAINS]->(child:File)
    
    // Get file-to-AST relationships (since we only have DEFINES, not PART_OF)
    OPTIONAL MATCH (file)-[defines:DEFINES]->(ast_node)
    WHERE ast_node:Function OR ast_node:Class OR ast_node:Method
    WITH repo, file, child, ast_node
    LIMIT 2000
    
    // Return all nodes and relationships
    RETURN 
        collect(DISTINCT repo) AS repos,
        collect(DISTINCT file) AS files,
        collect(DISTINCT ast_node) AS ast_nodes,
        [] AS summaries,  // No AISummary nodes yet
        collect(DISTINCT {
            startNodeElementId: elementId(repo),
            endNodeElementId: elementId(file),
            type: "CONTAINS"
        }) AS repo_file_rels,
        collect(DISTINCT {
            startNodeElementId: elementId(file),
            endNodeElementId: elementId(child),
            type: "CONTAINS"
        }) AS file_file_rels,
        [] AS ast_file_rels,  // No PART_OF relationships
        [] AS summary_rels,   // No summary relationships
        collect(DISTINCT {
            startNodeElementId: elementId(file),
            endNodeElementId: elementId(ast_node),
            type: "DEFINES"
        }) AS file_ast_rels
    """
    
    result = connector.run_query(query, {"repo_id": repo_id})
    
    if not result or len(result) == 0:
        print(f"No data found for repository {repo_id}")
        return
    
    # Extract all nodes
    all_nodes = []
    node_map = {}  # Map node IDs to their index in the all_nodes array
    
    # Process repository nodes
    for node in result[0]["repos"]:
        if not node:
            continue
        node_id = node.get("elementId")
        node_data = {
            "id": node_id,
            "label": node.get("name", "Repository"),
            "type": "Repository",
            "properties": {k: v for k, v in node.items() if k not in ["elementId", "name"]}
        }
        node_map[node_id] = len(all_nodes)
        all_nodes.append(node_data)
    
    # Process file nodes
    for node in result[0]["files"]:
        if not node:
            continue
        node_id = node.get("elementId")
        node_data = {
            "id": node_id,
            "label": node.get("name", ""),
            "type": "File",
            "properties": {k: v for k, v in node.items() if k not in ["elementId", "name"]}
        }
        node_map[node_id] = len(all_nodes)
        all_nodes.append(node_data)
    
    # Process AST nodes
    for node in result[0]["ast_nodes"]:
        if not node:
            continue
        node_id = node.get("elementId")
        node_labels = node.get("labels", [])
        node_type = node_labels[0] if node_labels else "ASTNode"
        node_data = {
            "id": node_id,
            "label": node.get("name", ""),
            "type": node_type,
            "properties": {k: v for k, v in node.items() if k not in ["elementId", "name", "labels"]}
        }
        node_map[node_id] = len(all_nodes)
        all_nodes.append(node_data)
    
    # Process summary nodes
    for node in result[0]["summaries"]:
        if not node:
            continue
        node_id = node.get("elementId")
        node_data = {
            "id": node_id,
            "label": "Summary",
            "type": "AISummary",
            "properties": {k: v for k, v in node.items() if k not in ["elementId"]}
        }
        node_map[node_id] = len(all_nodes)
        all_nodes.append(node_data)
    
    # Process all relationships
    all_links = []
    process_relationships(result[0]["repo_file_rels"], all_links)
    process_relationships(result[0]["file_file_rels"], all_links)
    process_relationships(result[0]["ast_file_rels"], all_links)
    process_relationships(result[0]["summary_rels"], all_links)
    process_relationships(result[0]["file_ast_rels"], all_links)
    
    # Generate HTML visualization
    html = generate_html(all_nodes, all_links)
    
    # Write HTML to file
    with open(output_html, "w") as f:
        f.write(html)
    
    print(f"Visualization created at {output_html}")
    print(f"- Nodes: {len(all_nodes)} ({count_node_types(all_nodes)})")
    print(f"- Links: {len(all_links)} ({count_link_types(all_links)})")


def process_relationships(relationships, all_links):
    """Process relationships and add them to all_links."""
    # Handle path relationships (arrays of relationships)
    for rel_item in relationships:
        if not rel_item:
            continue
        
        # Check if this is a path (array) or a single relationship
        if isinstance(rel_item, list):
            # Handle path relationships (like CONTAINS*)
            for rel in rel_item:
                process_single_relationship(rel, all_links)
        else:
            # Handle single relationship
            process_single_relationship(rel_item, all_links)

def process_single_relationship(rel, all_links):
    """Process a single relationship and add it to all_links."""
    if not rel:
        return
        
    source_id = rel.get("startNodeElementId")
    target_id = rel.get("endNodeElementId")
    rel_type = rel.get("type")
    
    if not source_id or not target_id or not rel_type:
        return
    
    link_data = {
        "source": source_id,
        "target": target_id,
        "label": rel_type,
        "properties": {k: v for k, v in rel.items() if k not in ["startNodeElementId", "endNodeElementId", "type"]}
    }
    all_links.append(link_data)


def count_node_types(nodes):
    """Count the number of nodes of each type."""
    counts = {}
    for node in nodes:
        node_type = node.get("type", "Unknown")
        counts[node_type] = counts.get(node_type, 0) + 1
    
    return ", ".join([f"{count} {node_type}" for node_type, count in counts.items()])


def count_link_types(links):
    """Count the number of links of each type."""
    counts = {}
    for link in links:
        link_type = link.get("label", "Unknown")
        counts[link_type] = counts.get(link_type, 0) + 1
    
    return ", ".join([f"{count} {link_type}" for link_type, count in counts.items()])


def generate_html(nodes, links):
    """Generate HTML visualization using D3.js."""
    html = """
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="utf-8">
        <title>Comprehensive Repository Visualization</title>
        <script src="https://d3js.org/d3.v7.min.js"></script>
        <style>
            body, html {
                margin: 0;
                padding: 0;
                width: 100%;
                height: 100%;
                overflow: hidden;
                font-family: Arial, sans-serif;
            }
            
            #graph-container {
                width: 100%;
                height: 100%;
                background-color: #f9f9f9;
            }
            
            .node {
                stroke: #fff;
                stroke-width: 1.5px;
            }
            
            .link {
                stroke: #999;
                stroke-opacity: 0.6;
            }
            
            .node-label {
                font-size: 12px;
                pointer-events: none;
                text-shadow: 1px 1px 2px white, -1px -1px 2px white, 1px -1px 2px white, -1px 1px 2px white;
            }
            
            .link-label {
                font-size: 10px;
                pointer-events: none;
                fill: #666;
                text-shadow: 1px 1px 2px white, -1px -1px 2px white, 1px -1px 2px white, -1px 1px 2px white;
            }
            
            #controls {
                position: absolute;
                top: 10px;
                left: 10px;
                background-color: rgba(255, 255, 255, 0.8);
                padding: 10px;
                border-radius: 5px;
                box-shadow: 0 0 5px rgba(0, 0, 0, 0.2);
            }
            
            #search-container {
                position: absolute;
                top: 10px;
                right: 10px;
                background-color: rgba(255, 255, 255, 0.8);
                padding: 10px;
                border-radius: 5px;
                box-shadow: 0 0 5px rgba(0, 0, 0, 0.2);
            }
            
            .info-box {
                position: absolute;
                bottom: 10px;
                left: 10px;
                background-color: rgba(255, 255, 255, 0.8);
                padding: 10px;
                border-radius: 5px;
                box-shadow: 0 0 5px rgba(0, 0, 0, 0.2);
                max-width: 300px;
                max-height: 300px;
                overflow: auto;
                font-size: 12px;
            }
            
            .color-dot {
                display: inline-block;
                width: 10px;
                height: 10px;
                border-radius: 50%;
                margin-right: 5px;
            }
            
            #legend {
                position: absolute;
                bottom: 10px;
                right: 10px;
                background-color: rgba(255, 255, 255, 0.8);
                padding: 10px;
                border-radius: 5px;
                box-shadow: 0 0 5px rgba(0, 0, 0, 0.2);
            }
            
            .search-result {
                cursor: pointer;
                padding: 5px;
                border-radius: 3px;
            }
            
            .search-result:hover {
                background-color: #eee;
            }
        </style>
    </head>
    <body>
        <div id="graph-container"></div>
        
        <div id="controls">
            <h4>Visualization Controls</h4>
            <div>
                <input type="checkbox" id="show-repository" checked>
                <label for="show-repository">Repository</label>
            </div>
            <div>
                <input type="checkbox" id="show-file" checked>
                <label for="show-file">File</label>
            </div>
            <div>
                <input type="checkbox" id="show-function" checked>
                <label for="show-function">Function</label>
            </div>
            <div>
                <input type="checkbox" id="show-class" checked>
                <label for="show-class">Class</label>
            </div>
            <div>
                <input type="checkbox" id="show-method" checked>
                <label for="show-method">Method</label>
            </div>
            <div>
                <input type="checkbox" id="show-summary" checked>
                <label for="show-summary">AI Summary</label>
            </div>
            <hr>
            <div>
                <button id="expand-graph">Expand Force</button>
                <button id="collapse-graph">Collapse Force</button>
            </div>
        </div>
        
        <div id="search-container">
            <h4>Search Nodes</h4>
            <input type="text" id="search-input" placeholder="Search by name...">
            <div id="search-results"></div>
        </div>
        
        <div id="node-info" class="info-box" style="display: none;">
            <h4>Node Information</h4>
            <div id="info-content"></div>
        </div>
        
        <div id="legend">
            <h4>Legend</h4>
            <div><span class="color-dot" style="background-color: #66c2a5;"></span> Repository</div>
            <div><span class="color-dot" style="background-color: #fc8d62;"></span> File</div>
            <div><span class="color-dot" style="background-color: #8da0cb;"></span> Function</div>
            <div><span class="color-dot" style="background-color: #e78ac3;"></span> Class</div>
            <div><span class="color-dot" style="background-color: #a6d854;"></span> Method</div>
            <div><span class="color-dot" style="background-color: #ffd92f;"></span> AI Summary</div>
        </div>
        
        <script>
            // Node and link data
            const nodesData = ${nodes_json};
            const linksData = ${links_json};
            
            // Color scheme for node types
            const colorMap = {
                Repository: "#66c2a5",
                File: "#fc8d62",
                Function: "#8da0cb",
                Class: "#e78ac3",
                Method: "#a6d854",
                AISummary: "#ffd92f",
                Unknown: "#999999"
            };
            
            // Node size by type
            const sizeMap = {
                Repository: 15,
                File: 8,
                Function: 6,
                Class: 10,
                Method: 6,
                AISummary: 12,
                Unknown: 5
            };
            
            // Set up the SVG
            const width = window.innerWidth;
            const height = window.innerHeight;
            
            const svg = d3.select("#graph-container")
                .append("svg")
                .attr("width", width)
                .attr("height", height);
            
            // Container for all graph elements (for zooming)
            const container = svg.append("g");
            
            // Create the simulation
            const simulation = d3.forceSimulation()
                .force("link", d3.forceLink().id(d => d.id).distance(100))
                .force("charge", d3.forceManyBody().strength(-300))
                .force("center", d3.forceCenter(width / 2, height / 2))
                .force("collision", d3.forceCollide().radius(d => getNodeSize(d) * 2));
            
            // Helper function to get node size
            function getNodeSize(d) {
                return sizeMap[d.type] || 5;
            }
            
            // Create links
            const link = container.append("g")
                .selectAll("line")
                .data(linksData)
                .enter()
                .append("line")
                .attr("class", "link")
                .attr("stroke-width", 1.5);
            
            // Create link labels (only visible on hover)
            const linkLabel = container.append("g")
                .selectAll("text")
                .data(linksData)
                .enter()
                .append("text")
                .attr("class", "link-label")
                .attr("opacity", 0)  // Initially hidden
                .text(d => d.label);
            
            // Create nodes
            const node = container.append("g")
                .selectAll("circle")
                .data(nodesData)
                .enter()
                .append("circle")
                .attr("class", "node")
                .attr("r", getNodeSize)
                .attr("fill", d => colorMap[d.type] || "#999")
                .call(d3.drag()
                    .on("start", dragstarted)
                    .on("drag", dragged)
                    .on("end", dragended))
                .on("click", showNodeInfo)
                .on("mouseover", function(event, d) {
                    d3.select(this).attr("stroke", "#000").attr("stroke-width", 2);
                    
                    // Highlight connected links and nodes
                    const connectedLinks = linksData.filter(l => l.source.id === d.id || l.target.id === d.id);
                    const connectedNodeIds = new Set();
                    
                    connectedLinks.forEach(l => {
                        const sourceId = typeof l.source === 'object' ? l.source.id : l.source;
                        const targetId = typeof l.target === 'object' ? l.target.id : l.target;
                        
                        if (sourceId === d.id) {
                            connectedNodeIds.add(targetId);
                        } else {
                            connectedNodeIds.add(sourceId);
                        }
                        
                        // Highlight link
                        link.filter(link => link === l)
                            .attr("stroke", "#000")
                            .attr("stroke-width", 2.5);
                        
                        // Show link label
                        linkLabel.filter(link => link === l)
                            .attr("opacity", 1);
                    });
                    
                    // Highlight connected nodes
                    node.filter(n => connectedNodeIds.has(n.id))
                        .attr("stroke", "#000")
                        .attr("stroke-width", 2);
                })
                .on("mouseout", function(event, d) {
                    d3.select(this).attr("stroke", "#fff").attr("stroke-width", 1.5);
                    
                    // Reset links
                    link.attr("stroke", "#999").attr("stroke-width", 1.5);
                    
                    // Hide link labels
                    linkLabel.attr("opacity", 0);
                    
                    // Reset connected nodes
                    node.attr("stroke", "#fff").attr("stroke-width", 1.5);
                });
            
            // Create node labels (only visible when zoomed in)
            const nodeLabel = container.append("g")
                .selectAll("text")
                .data(nodesData)
                .enter()
                .append("text")
                .attr("class", "node-label")
                .attr("dy", "-10")
                .text(d => d.label || "");
            
            // Set up simulation
            simulation
                .nodes(nodesData)
                .on("tick", ticked);
            
            simulation.force("link")
                .links(linksData);
            
            // Function to update positions on tick
            function ticked() {
                link
                    .attr("x1", d => d.source.x)
                    .attr("y1", d => d.source.y)
                    .attr("x2", d => d.target.x)
                    .attr("y2", d => d.target.y);
                
                linkLabel
                    .attr("x", d => (d.source.x + d.target.x) / 2)
                    .attr("y", d => (d.source.y + d.target.y) / 2);
                
                node
                    .attr("cx", d => d.x = Math.max(getNodeSize(d), Math.min(width - getNodeSize(d), d.x)))
                    .attr("cy", d => d.y = Math.max(getNodeSize(d), Math.min(height - getNodeSize(d), d.y)));
                
                nodeLabel
                    .attr("x", d => d.x)
                    .attr("y", d => d.y);
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
            
            // Show node info when clicked
            function showNodeInfo(event, d) {
                const infoBox = document.getElementById("node-info");
                const infoContent = document.getElementById("info-content");
                
                infoBox.style.display = "block";
                
                let html = `<p><strong>ID:</strong> ${d.id}</p>`;
                html += `<p><strong>Type:</strong> ${d.type}</p>`;
                html += `<p><strong>Label:</strong> ${d.label}</p>`;
                
                if (d.properties) {
                    html += "<p><strong>Properties:</strong></p><ul>";
                    for (const [key, value] of Object.entries(d.properties)) {
                        if (value !== null && value !== undefined) {
                            if (key === "summary") {
                                // Add a collapsible section for long summaries
                                html += `<li>${key}: <details><summary>Show/Hide</summary>${value}</details></li>`;
                            } else {
                                html += `<li>${key}: ${value}</li>`;
                            }
                        }
                    }
                    html += "</ul>";
                }
                
                infoContent.innerHTML = html;
            }
            
            // Set up node type filtering
            document.getElementById("show-repository").addEventListener("change", filterGraph);
            document.getElementById("show-file").addEventListener("change", filterGraph);
            document.getElementById("show-function").addEventListener("change", filterGraph);
            document.getElementById("show-class").addEventListener("change", filterGraph);
            document.getElementById("show-method").addEventListener("change", filterGraph);
            document.getElementById("show-summary").addEventListener("change", filterGraph);
            
            function filterGraph() {
                const showRepository = document.getElementById("show-repository").checked;
                const showFile = document.getElementById("show-file").checked;
                const showFunction = document.getElementById("show-function").checked;
                const showClass = document.getElementById("show-class").checked;
                const showMethod = document.getElementById("show-method").checked;
                const showSummary = document.getElementById("show-summary").checked;
                
                // Filter nodes
                node.style("display", d => {
                    if (d.type === "Repository" && !showRepository) return "none";
                    if (d.type === "File" && !showFile) return "none";
                    if (d.type === "Function" && !showFunction) return "none";
                    if (d.type === "Class" && !showClass) return "none";
                    if (d.type === "Method" && !showMethod) return "none";
                    if (d.type === "AISummary" && !showSummary) return "none";
                    return null;
                });
                
                // Filter node labels
                nodeLabel.style("display", d => {
                    if (d.type === "Repository" && !showRepository) return "none";
                    if (d.type === "File" && !showFile) return "none";
                    if (d.type === "Function" && !showFunction) return "none";
                    if (d.type === "Class" && !showClass) return "none";
                    if (d.type === "Method" && !showMethod) return "none";
                    if (d.type === "AISummary" && !showSummary) return "none";
                    return null;
                });
                
                // Filter links based on visible nodes
                link.style("display", d => {
                    const sourceType = d.source.type;
                    const targetType = d.target.type;
                    
                    const sourceVisible = (
                        (sourceType === "Repository" && showRepository) ||
                        (sourceType === "File" && showFile) ||
                        (sourceType === "Function" && showFunction) ||
                        (sourceType === "Class" && showClass) ||
                        (sourceType === "Method" && showMethod) ||
                        (sourceType === "AISummary" && showSummary)
                    );
                    
                    const targetVisible = (
                        (targetType === "Repository" && showRepository) ||
                        (targetType === "File" && showFile) ||
                        (targetType === "Function" && showFunction) ||
                        (targetType === "Class" && showClass) ||
                        (targetType === "Method" && showMethod) ||
                        (targetType === "AISummary" && showSummary)
                    );
                    
                    return sourceVisible && targetVisible ? null : "none";
                });
                
                // Filter link labels based on link visibility
                linkLabel.style("display", function() {
                    const linkDisplay = d3.select(this.parentNode)
                        .select("line")
                        .style("display");
                    return linkDisplay === "none" ? "none" : null;
                });
            }
            
            // Add zoom functionality
            const zoom = d3.zoom()
                .scaleExtent([0.1, 10])
                .on("zoom", zoomed);
            
            svg.call(zoom);
            
            function zoomed(event) {
                container.attr("transform", event.transform);
                
                // Show node labels only when zoomed in sufficiently
                const currentScale = event.transform.k;
                nodeLabel.style("opacity", () => currentScale > 1.5 ? 0.8 : 0);
            }
            
            // Search functionality
            const searchInput = document.getElementById("search-input");
            const searchResults = document.getElementById("search-results");
            
            searchInput.addEventListener("input", performSearch);
            
            function performSearch() {
                const query = searchInput.value.toLowerCase();
                if (query.length < 2) {
                    searchResults.innerHTML = "";
                    return;
                }
                
                // Find matching nodes
                const matches = nodesData.filter(node => {
                    const label = (node.label || "").toLowerCase();
                    
                    // Check properties (like path, etc.)
                    let propertiesMatch = false;
                    if (node.properties) {
                        for (const [key, value] of Object.entries(node.properties)) {
                            if (value && String(value).toLowerCase().includes(query)) {
                                propertiesMatch = true;
                                break;
                            }
                        }
                    }
                    
                    return label.includes(query) || propertiesMatch;
                }).slice(0, 10); // Limit to 10 results
                
                // Display results
                searchResults.innerHTML = "";
                matches.forEach(node => {
                    const result = document.createElement("div");
                    result.className = "search-result";
                    result.textContent = `${node.type}: ${node.label}`;
                    result.addEventListener("click", () => {
                        // Highlight the node
                        const selectedNode = node;
                        
                        // Center view on the node
                        const scale = 2;
                        const x = width / 2 - selectedNode.x * scale;
                        const y = height / 2 - selectedNode.y * scale;
                        
                        svg.transition()
                            .duration(750)
                            .call(zoom.transform, d3.zoomIdentity.translate(x, y).scale(scale));
                        
                        // Show node info
                        showNodeInfo(null, selectedNode);
                        
                        // Highlight the node
                        node.filter(n => n === selectedNode)
                            .attr("stroke", "#000")
                            .attr("stroke-width", 3);
                    });
                    searchResults.appendChild(result);
                });
            }
            
            // Buttons to adjust force layout
            document.getElementById("expand-graph").addEventListener("click", () => {
                simulation.force("charge").strength(-1000);
                simulation.alpha(1).restart();
            });
            
            document.getElementById("collapse-graph").addEventListener("click", () => {
                simulation.force("charge").strength(-100);
                simulation.alpha(1).restart();
            });
        </script>
    </body>
    </html>
    """
    
    # Replace placeholder values with actual data
    html = html.replace("${nodes_json}", json.dumps(nodes))
    html = html.replace("${links_json}", json.dumps(links))
    
    return html


if __name__ == "__main__":
    asyncio.run(main())
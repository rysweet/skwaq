#!/usr/bin/env python3
"""Create a fixed visualization for files and AST nodes with proper relationships."""

import json
import os
import sys
from skwaq.db.neo4j_connector import get_connector
from rich.console import Console
from rich.progress import Progress

console = Console()

def visualize_investigation():
    """Create a custom visualization for the investigation."""
    # Get the most recent investigation
    connector = get_connector()
    query = """
    MATCH (i:Investigation)
    RETURN i.id as id, i.title as title
    ORDER BY i.created_at DESC
    LIMIT 1
    """
    
    results = connector.run_query(query)
    if not results:
        console.print("[bold red]No investigations found!")
        return 1
    
    investigation_id = results[0]["id"]
    investigation_title = results[0]["title"]
    console.print(f"[bold green]Found investigation: {investigation_id} - {investigation_title}")
    
    # Get the investigation node
    inv_query = """
    MATCH (i:Investigation {id: $id})
    RETURN elementId(i) as id, i.title as title, i.description as description,
           i.status as status, i.created_at as created_at
    """
    
    inv_result = connector.run_query(inv_query, {"id": investigation_id})[0]
    console.print(f"[bold blue]Found investigation node with ID: {inv_result['id']}")
    
    with Progress() as progress:
        task = progress.add_task("[cyan]Building visualization...", total=5)
        
        # Step 1: Get files included in the investigation (limited to 50 for better visualization)
        file_query = """
        MATCH (i:Investigation {id: $id})-[:INCLUDES]->(f:File)
        WHERE NOT f:Directory
        RETURN elementId(f) as id, f.name as name, f.path as path
        LIMIT 50
        """
        
        file_results = connector.run_query(file_query, {"id": investigation_id})
        console.print(f"[bold blue]Added {len(file_results)} files to visualization")
        progress.update(task, advance=1)
        
        # Step 2: Get AST nodes for these files (limited to 100 for better visualization)
        file_ids = [file["id"] for file in file_results]
        
        ast_query = """
        MATCH (file:File)-[:DEFINES]->(ast)
        WHERE elementId(file) IN $file_ids AND (ast:Function OR ast:Class OR ast:Method)
        RETURN elementId(ast) as id, ast.name as name, labels(ast)[0] as type, elementId(file) as file_id
        LIMIT 100
        """
        
        ast_results = connector.run_query(ast_query, {"file_ids": file_ids})
        console.print(f"[bold blue]Added {len(ast_results)} AST nodes to visualization")
        progress.update(task, advance=1)
        
        # Convert to graph visualization format
        nodes = []
        links = []
        
        # Step 3: Add investigation node
        nodes.append({
            "id": str(inv_result["id"]),
            "label": inv_result["title"],
            "type": "Investigation",
            "color": "#4b76e8",
            "properties": {
                "description": inv_result["description"],
                "status": inv_result["status"],
                "created_at": inv_result["created_at"]
            }
        })
        
        # Add file nodes and links to investigation
        for file in file_results:
            nodes.append({
                "id": str(file["id"]),
                "label": file["name"],
                "type": "File",
                "color": "#20c997",
                "properties": {
                    "path": file["path"]
                }
            })
            
            # Add link from investigation to file
            links.append({
                "source": str(inv_result["id"]),
                "target": str(file["id"]),
                "label": "INCLUDES"
            })
        
        progress.update(task, advance=1)
        
        # Step 4: Add AST nodes and relationships
        for ast in ast_results:
            color = "#8da0cb" if ast["type"] == "Function" else "#e78ac3" if ast["type"] == "Class" else "#a6d854"
            nodes.append({
                "id": str(ast["id"]),
                "label": ast["name"],
                "type": ast["type"],
                "color": color,
                "properties": {}
            })
            
            # Add DEFINES relationship from file to AST
            file_id = str(ast["file_id"])
            ast_id = str(ast["id"])
            
            links.append({
                "source": file_id,
                "target": ast_id,
                "label": "DEFINES"
            })
            
            # Add PART_OF relationship from AST to file
            links.append({
                "source": ast_id,
                "target": file_id,
                "label": "PART_OF"
            })
        
        progress.update(task, advance=1)
        
        # Step 5: Create visualization HTML
        output_path = f"investigation-{investigation_id}-fixed.html"
        
        html = """
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="utf-8">
            <title>Investigation Visualization</title>
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
                    max-width: 300px;
                    z-index: 10;
                }
                
                #search-box {
                    position: absolute;
                    top: 10px;
                    right: 10px;
                    background-color: rgba(255, 255, 255, 0.8);
                    padding: 10px;
                    border-radius: 5px;
                    box-shadow: 0 0 5px rgba(0, 0, 0, 0.2);
                    z-index: 10;
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
                    z-index: 10;
                }
                
                #legend {
                    position: absolute;
                    bottom: 10px;
                    right: 10px;
                    background-color: rgba(255, 255, 255, 0.8);
                    padding: 10px;
                    border-radius: 5px;
                    box-shadow: 0 0 5px rgba(0, 0, 0, 0.2);
                    z-index: 10;
                }
                
                .color-dot {
                    display: inline-block;
                    width: 10px;
                    height: 10px;
                    border-radius: 50%;
                    margin-right: 5px;
                }
                
                .search-result {
                    cursor: pointer;
                    padding: 3px;
                    margin: 2px 0;
                }
                
                .search-result:hover {
                    background-color: #eee;
                }
                
                .control-section {
                    margin-bottom: 10px;
                }
                
                .control-header {
                    font-weight: bold;
                    margin-bottom: 5px;
                }
                
                button {
                    margin-right: 5px;
                    margin-bottom: 5px;
                    padding: 5px 10px;
                    background: #4b76e8;
                    color: white;
                    border: none;
                    border-radius: 3px;
                    cursor: pointer;
                }
                
                button:hover {
                    background: #3a64d8;
                }
                
                #statistics {
                    margin-top: 10px;
                    font-size: 12px;
                }
            </style>
        </head>
        <body>
            <div id="graph-container"></div>
            
            <div id="controls">
                <h4>${investigation_title}</h4>
                
                <div class="control-section">
                    <div class="control-header">Filter Nodes</div>
                    <div>
                        <input type="checkbox" id="show-investigation" checked>
                        <label for="show-investigation">Investigation</label>
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
                </div>
                
                <div class="control-section">
                    <div class="control-header">Filter Links</div>
                    <div>
                        <input type="checkbox" id="show-includes" checked>
                        <label for="show-includes">INCLUDES</label>
                    </div>
                    <div>
                        <input type="checkbox" id="show-defines" checked>
                        <label for="show-defines">DEFINES</label>
                    </div>
                    <div>
                        <input type="checkbox" id="show-part-of" checked>
                        <label for="show-part-of">PART_OF</label>
                    </div>
                </div>
                
                <div class="control-section">
                    <div class="control-header">Layout Controls</div>
                    <button id="expand-graph">Expand</button>
                    <button id="collapse-graph">Collapse</button>
                    <button id="reset-view">Reset View</button>
                </div>
                
                <div id="statistics">
                    <div class="control-header">Statistics</div>
                    <div>Nodes: ${node_count}</div>
                    <div>Links: ${link_count}</div>
                </div>
            </div>
            
            <div id="search-box">
                <h4>Search</h4>
                <input type="text" id="search-input" placeholder="Search for nodes...">
                <div id="search-results" style="max-height: 300px; overflow-y: auto;"></div>
            </div>
            
            <div id="node-info" class="info-box" style="display: none;">
                <h4>Node Information</h4>
                <div id="info-content"></div>
            </div>
            
            <div id="legend">
                <h4>Legend</h4>
                <div><span class="color-dot" style="background-color: #4b76e8;"></span> Investigation</div>
                <div><span class="color-dot" style="background-color: #20c997;"></span> File</div>
                <div><span class="color-dot" style="background-color: #8da0cb;"></span> Function</div>
                <div><span class="color-dot" style="background-color: #e78ac3;"></span> Class</div>
                <div><span class="color-dot" style="background-color: #a6d854;"></span> Method</div>
            </div>
            
            <script>
                // Node and link data
                const nodesData = ${nodes_json};
                const linksData = ${links_json};
                
                // Node size by type
                const sizeMap = {
                    Investigation: 15,
                    File: 8,
                    Function: 6,
                    Class: 7,
                    Method: 5
                };
                
                // Link color by type
                const linkColorMap = {
                    INCLUDES: "#999",
                    DEFINES: "#2ca02c",
                    PART_OF: "#d62728"
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
                    .force("link", d3.forceLink().id(d => d.id).distance(80))
                    .force("charge", d3.forceManyBody().strength(-200))
                    .force("center", d3.forceCenter(width / 2, height / 2))
                    .force("collision", d3.forceCollide().radius(d => getNodeSize(d) * 2));
                
                // Helper function to get node size
                function getNodeSize(d) {
                    return sizeMap[d.type] || 5;
                }
                
                // Create links with directionality markers
                const linkGroup = container.append("g").attr("class", "links");
                
                // Add arrow markers for directed links
                svg.append("defs").selectAll("marker")
                    .data(["DEFINES", "PART_OF", "INCLUDES"])
                    .enter().append("marker")
                    .attr("id", d => `arrow-${d}`)
                    .attr("viewBox", "0 -5 10 10")
                    .attr("refX", 20)
                    .attr("refY", 0)
                    .attr("markerWidth", 6)
                    .attr("markerHeight", 6)
                    .attr("orient", "auto")
                    .append("path")
                    .attr("fill", d => linkColorMap[d] || "#999")
                    .attr("d", "M0,-5L10,0L0,5");
                
                // Create the links
                const link = linkGroup.selectAll("line")
                    .data(linksData)
                    .enter()
                    .append("line")
                    .attr("class", "link")
                    .attr("stroke", d => linkColorMap[d.label] || "#999")
                    .attr("stroke-width", 1.5)
                    .attr("marker-end", d => `url(#arrow-${d.label})`)
                    .attr("data-label", d => d.label);
                
                // Create link labels
                const linkLabel = container.append("g")
                    .selectAll("text")
                    .data(linksData)
                    .enter()
                    .append("text")
                    .attr("class", "link-label")
                    .attr("opacity", 0)  // Initially hidden
                    .text(d => d.label)
                    .attr("data-label", d => d.label);
                
                // Create nodes
                const node = container.append("g")
                    .selectAll("circle")
                    .data(nodesData)
                    .enter()
                    .append("circle")
                    .attr("class", "node")
                    .attr("r", getNodeSize)
                    .attr("fill", d => d.color || "#999")
                    .call(d3.drag()
                        .on("start", dragstarted)
                        .on("drag", dragged)
                        .on("end", dragended))
                    .on("click", showNodeInfo)
                    .on("mouseover", handleMouseOver)
                    .on("mouseout", handleMouseOut);
                
                // Create node labels
                const nodeLabel = container.append("g")
                    .selectAll("text")
                    .data(nodesData)
                    .enter()
                    .append("text")
                    .attr("class", "node-label")
                    .attr("dy", "-10")
                    .text(d => d.label || "")
                    .attr("opacity", 0);  // Initially hidden
                
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
                
                // Handle mouseover to highlight connections
                function handleMouseOver(event, d) {
                    // Highlight the node
                    d3.select(this).attr("stroke", "#000").attr("stroke-width", 2);
                    
                    // Find connected links and nodes
                    const connectedLinks = linksData.filter(l => 
                        (l.source.id === d.id || l.source === d.id) || 
                        (l.target.id === d.id || l.target === d.id)
                    );
                    
                    const connectedNodeIds = new Set();
                    
                    connectedLinks.forEach(l => {
                        // Get source and target IDs
                        const sourceId = typeof l.source === 'object' ? l.source.id : l.source;
                        const targetId = typeof l.target === 'object' ? l.target.id : l.target;
                        
                        // Add connected node IDs
                        if (sourceId === d.id) {
                            connectedNodeIds.add(targetId);
                        } else {
                            connectedNodeIds.add(sourceId);
                        }
                        
                        // Highlight link
                        link.filter(link => link === l)
                            .attr("stroke", "#000")
                            .attr("stroke-width", 2);
                        
                        // Show link label
                        linkLabel.filter(link => link === l)
                            .attr("opacity", 1);
                    });
                    
                    // Highlight connected nodes
                    node.filter(n => connectedNodeIds.has(n.id))
                        .attr("stroke", "#000")
                        .attr("stroke-width", 2);
                    
                    // Show labels for this node and connected nodes
                    nodeLabel.filter(n => n.id === d.id || connectedNodeIds.has(n.id))
                        .attr("opacity", 1);
                }
                
                // Handle mouseout to reset highlights
                function handleMouseOut() {
                    node.attr("stroke", "#fff").attr("stroke-width", 1.5);
                    
                    link.attr("stroke", d => linkColorMap[d.label] || "#999")
                        .attr("stroke-width", 1.5);
                        
                    linkLabel.attr("opacity", 0);
                    
                    // Only show labels when zoomed in
                    const currentZoom = d3.zoomTransform(svg.node()).k;
                    nodeLabel.attr("opacity", currentZoom > 1.5 ? 0.8 : 0);
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
                                html += `<li>${key}: ${value}</li>`;
                            }
                        }
                        html += "</ul>";
                    }
                    
                    infoContent.innerHTML = html;
                }
                
                // Set up node type filtering
                document.getElementById("show-investigation").addEventListener("change", filterGraph);
                document.getElementById("show-file").addEventListener("change", filterGraph);
                document.getElementById("show-function").addEventListener("change", filterGraph);
                document.getElementById("show-class").addEventListener("change", filterGraph);
                document.getElementById("show-method").addEventListener("change", filterGraph);
                document.getElementById("show-includes").addEventListener("change", filterGraph);
                document.getElementById("show-defines").addEventListener("change", filterGraph);
                document.getElementById("show-part-of").addEventListener("change", filterGraph);
                
                function filterGraph() {
                    const showInvestigation = document.getElementById("show-investigation").checked;
                    const showFile = document.getElementById("show-file").checked;
                    const showFunction = document.getElementById("show-function").checked;
                    const showClass = document.getElementById("show-class").checked;
                    const showMethod = document.getElementById("show-method").checked;
                    const showIncludes = document.getElementById("show-includes").checked;
                    const showDefines = document.getElementById("show-defines").checked;
                    const showPartOf = document.getElementById("show-part-of").checked;
                    
                    // Filter nodes
                    node.style("display", d => {
                        if (d.type === "Investigation" && !showInvestigation) return "none";
                        if (d.type === "File" && !showFile) return "none";
                        if (d.type === "Function" && !showFunction) return "none";
                        if (d.type === "Class" && !showClass) return "none";
                        if (d.type === "Method" && !showMethod) return "none";
                        return null;
                    });
                    
                    // Filter node labels
                    nodeLabel.style("display", d => {
                        if (d.type === "Investigation" && !showInvestigation) return "none";
                        if (d.type === "File" && !showFile) return "none";
                        if (d.type === "Function" && !showFunction) return "none";
                        if (d.type === "Class" && !showClass) return "none";
                        if (d.type === "Method" && !showMethod) return "none";
                        return null;
                    });
                    
                    // Filter links based on relationship type
                    link.style("display", d => {
                        if (d.label === "INCLUDES" && !showIncludes) return "none";
                        if (d.label === "DEFINES" && !showDefines) return "none";
                        if (d.label === "PART_OF" && !showPartOf) return "none";
                        
                        // Also consider node visibility
                        const sourceType = d.source.type;
                        const targetType = d.target.type;
                        
                        const sourceVisible = (
                            (sourceType === "Investigation" && showInvestigation) ||
                            (sourceType === "File" && showFile) ||
                            (sourceType === "Function" && showFunction) ||
                            (sourceType === "Class" && showClass) ||
                            (sourceType === "Method" && showMethod)
                        );
                        
                        const targetVisible = (
                            (targetType === "Investigation" && showInvestigation) ||
                            (targetType === "File" && showFile) ||
                            (targetType === "Function" && showFunction) ||
                            (targetType === "Class" && showClass) ||
                            (targetType === "Method" && showMethod)
                        );
                        
                        return sourceVisible && targetVisible ? null : "none";
                    });
                    
                    // Filter link labels with same logic
                    linkLabel.style("display", d => {
                        if (d.label === "INCLUDES" && !showIncludes) return "none";
                        if (d.label === "DEFINES" && !showDefines) return "none";
                        if (d.label === "PART_OF" && !showPartOf) return "none";
                        
                        const sourceType = d.source.type;
                        const targetType = d.target.type;
                        
                        const sourceVisible = (
                            (sourceType === "Investigation" && showInvestigation) ||
                            (sourceType === "File" && showFile) ||
                            (sourceType === "Function" && showFunction) ||
                            (sourceType === "Class" && showClass) ||
                            (sourceType === "Method" && showMethod)
                        );
                        
                        const targetVisible = (
                            (targetType === "Investigation" && showInvestigation) ||
                            (targetType === "File" && showFile) ||
                            (targetType === "Function" && showFunction) ||
                            (targetType === "Class" && showClass) ||
                            (targetType === "Method" && showMethod)
                        );
                        
                        return sourceVisible && targetVisible ? null : "none";
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
                
                // Buttons to adjust force layout
                document.getElementById("expand-graph").addEventListener("click", () => {
                    simulation.force("charge").strength(-500);
                    simulation.alpha(1).restart();
                });
                
                document.getElementById("collapse-graph").addEventListener("click", () => {
                    simulation.force("charge").strength(-100);
                    simulation.alpha(1).restart();
                });
                
                document.getElementById("reset-view").addEventListener("click", () => {
                    svg.transition().duration(750).call(
                        zoom.transform,
                        d3.zoomIdentity.translate(width / 2, height / 2).scale(1)
                    );
                });
                
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
                        
                        // Check properties
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
                    }).slice(0, 20); // Limit to 20 results
                    
                    // Display results
                    searchResults.innerHTML = "";
                    if (matches.length === 0) {
                        searchResults.innerHTML = "<div>No matches found</div>";
                    } else {
                        matches.forEach(node => {
                            const result = document.createElement("div");
                            result.className = "search-result";
                            result.innerHTML = `<span class="color-dot" style="background-color: ${node.color};"></span> ${node.type}: ${node.label}`;
                            
                            result.addEventListener("click", () => {
                                // Center and highlight the node
                                const transform = d3.zoomIdentity
                                    .translate(width/2 - node.x, height/2 - node.y)
                                    .scale(2);
                                    
                                svg.transition()
                                    .duration(750)
                                    .call(zoom.transform, transform);
                                    
                                // Simulate click to show info
                                showNodeInfo({}, node);
                                
                                // Simulate mouseover to highlight connections
                                d3.selectAll(".node").each(function(d) {
                                    if (d.id === node.id) {
                                        handleMouseOver({}, d);
                                    }
                                });
                            });
                            
                            searchResults.appendChild(result);
                        });
                    }
                }
                
                // Initial reset to center the graph
                svg.call(
                    zoom.transform,
                    d3.zoomIdentity.translate(width / 2, height / 2).scale(1)
                );
            </script>
        </body>
        </html>
        """
        
        # Replace placeholders with actual data
        html = html.replace("${investigation_title}", investigation_title)
        html = html.replace("${nodes_json}", json.dumps(nodes))
        html = html.replace("${links_json}", json.dumps(links))
        html = html.replace("${node_count}", str(len(nodes)))
        html = html.replace("${link_count}", str(len(links)))
        
        # Write to file
        with open(output_path, "w") as f:
            f.write(html)
        
        console.print(f"[bold green]Visualization created at {output_path}")
        console.print(f"[bold blue]Nodes: {len(nodes)} ({sum(1 for n in nodes if n['type'] == 'Investigation')} investigations, "
              f"{sum(1 for n in nodes if n['type'] == 'File')} files, "
              f"{sum(1 for n in nodes if n['type'] in ['Function', 'Class', 'Method'])} AST nodes)")
        console.print(f"[bold blue]Links: {len(links)} (Investigation→File: {sum(1 for l in links if l['label'] == 'INCLUDES')}, "
              f"File→AST: {sum(1 for l in links if l['label'] == 'DEFINES')}, "
              f"AST→File: {sum(1 for l in links if l['label'] == 'PART_OF')})")
        
        progress.update(task, advance=1)
    
    return 0

if __name__ == "__main__":
    sys.exit(visualize_investigation())
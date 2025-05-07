#!/usr/bin/env python3
"""Create a direct visualization of files and AST nodes."""

import json
from skwaq.db.neo4j_connector import get_connector

def main():
    """Generate a visualization directly querying files and AST nodes."""
    connector = get_connector()
    
    # Get a limited number of files
    files_query = """
    MATCH (f:File)
    WHERE NOT (f:Directory)
    RETURN f.name as name, f.path as path, elementId(f) as id
    LIMIT 100
    """
    
    files = connector.run_query(files_query)
    print(f"Found {len(files)} files")
    
    # Get AST nodes for all files
    ast_query = """
    MATCH (file:File)-[:DEFINES]->(ast)
    WHERE elementId(file) IN $file_ids AND (ast:Function OR ast:Class)
    RETURN file.name as file_name, elementId(file) as file_id, 
           ast.name as ast_name, elementId(ast) as ast_id, labels(ast) as ast_labels
    LIMIT 1000
    """
    
    file_ids = [file["id"] for file in files]
    ast_results = connector.run_query(ast_query, {"file_ids": file_ids})
    print(f"Found {len(ast_results)} AST nodes")
    
    # Build visualization data
    nodes = []
    links = []
    node_ids = set()
    
    # Add file nodes
    for file in files:
        file_id = file["id"]
        if file_id not in node_ids:
            node_ids.add(file_id)
            nodes.append({
                "id": file_id,
                "label": file["name"],
                "type": "File",
                "properties": {"path": file["path"]}
            })
    
    # Add AST nodes and relationships
    for ast in ast_results:
        file_id = ast["file_id"]
        ast_id = ast["ast_id"]
        
        # Add AST node if not already added
        if ast_id not in node_ids:
            node_ids.add(ast_id)
            node_type = ast["ast_labels"][0] if ast["ast_labels"] else "Unknown"
            nodes.append({
                "id": ast_id,
                "label": ast["ast_name"],
                "type": node_type,
                "properties": {"file": ast["file_name"]}
            })
        
        # Add relationship
        links.append({
            "source": file_id,
            "target": ast_id,
            "label": "DEFINES"
        })
    
    # Create HTML visualization
    html = """
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="utf-8">
        <title>Files and AST Nodes Visualization</title>
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
            
            #search-box {
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
            
            #legend {
                position: absolute;
                bottom: 10px;
                right: 10px;
                background-color: rgba(255, 255, 255, 0.8);
                padding: 10px;
                border-radius: 5px;
                box-shadow: 0 0 5px rgba(0, 0, 0, 0.2);
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
        </style>
    </head>
    <body>
        <div id="graph-container"></div>
        
        <div id="controls">
            <h4>Visualization Controls</h4>
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
            <hr>
            <div>
                <button id="expand-graph">Expand Force</button>
                <button id="collapse-graph">Collapse Force</button>
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
            <div><span class="color-dot" style="background-color: #fc8d62;"></span> File</div>
            <div><span class="color-dot" style="background-color: #8da0cb;"></span> Function</div>
            <div><span class="color-dot" style="background-color: #e78ac3;"></span> Class</div>
        </div>
        
        <script>
            // Node and link data
            const nodesData = ${nodes_json};
            const linksData = ${links_json};
            
            // Color scheme for node types
            const colorMap = {
                File: "#fc8d62",
                Function: "#8da0cb",
                Class: "#e78ac3",
                Method: "#a6d854",
                Unknown: "#999999"
            };
            
            // Node size by type
            const sizeMap = {
                File: 8,
                Function: 5,
                Class: 7,
                Method: 5,
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
                .force("link", d3.forceLink().id(d => d.id).distance(70))
                .force("charge", d3.forceManyBody().strength(-200))
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
                .attr("stroke-width", 1);
            
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
                .on("mouseover", handleMouseOver)
                .on("mouseout", handleMouseOut);
            
            // Create node labels (only visible when zoomed in)
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
                link.attr("stroke", "#999").attr("stroke-width", 1);
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
            document.getElementById("show-file").addEventListener("change", filterGraph);
            document.getElementById("show-function").addEventListener("change", filterGraph);
            document.getElementById("show-class").addEventListener("change", filterGraph);
            
            function filterGraph() {
                const showFile = document.getElementById("show-file").checked;
                const showFunction = document.getElementById("show-function").checked;
                const showClass = document.getElementById("show-class").checked;
                
                // Filter nodes
                node.style("display", d => {
                    if (d.type === "File" && !showFile) return "none";
                    if (d.type === "Function" && !showFunction) return "none";
                    if (d.type === "Class" && !showClass) return "none";
                    return null;
                });
                
                // Filter node labels
                nodeLabel.style("display", d => {
                    if (d.type === "File" && !showFile) return "none";
                    if (d.type === "Function" && !showFunction) return "none";
                    if (d.type === "Class" && !showClass) return "none";
                    return null;
                });
                
                // Filter links based on visible nodes
                link.style("display", d => {
                    const sourceType = d.source.type;
                    const targetType = d.target.type;
                    
                    const sourceVisible = (
                        (sourceType === "File" && showFile) ||
                        (sourceType === "Function" && showFunction) ||
                        (sourceType === "Class" && showClass)
                    );
                    
                    const targetVisible = (
                        (targetType === "File" && showFile) ||
                        (targetType === "Function" && showFunction) ||
                        (targetType === "Class" && showClass)
                    );
                    
                    return sourceVisible && targetVisible ? null : "none";
                });
                
                // Filter link labels
                linkLabel.style("display", d => {
                    const sourceType = d.source.type;
                    const targetType = d.target.type;
                    
                    const sourceVisible = (
                        (sourceType === "File" && showFile) ||
                        (sourceType === "Function" && showFunction) ||
                        (sourceType === "Class" && showClass)
                    );
                    
                    const targetVisible = (
                        (targetType === "File" && showFile) ||
                        (targetType === "Function" && showFunction) ||
                        (targetType === "Class" && showClass)
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
                        result.innerHTML = `<span class="color-dot" style="background-color: ${colorMap[node.type]};"></span> ${node.type}: ${node.label}`;
                        
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
                            node.forEach(n => {
                                if (n.id === node.id) {
                                    handleMouseOver({}, n);
                                }
                            });
                        });
                        
                        searchResults.appendChild(result);
                    });
                }
            }
        </script>
    </body>
    </html>
    """
    
    # Replace placeholders with actual data
    html = html.replace("${nodes_json}", json.dumps(nodes))
    html = html.replace("${links_json}", json.dumps(links))
    
    # Write to file
    output_path = "/tmp/attackbot_final.html"
    with open(output_path, "w") as f:
        f.write(html)
    
    print(f"Visualization created at {output_path}")
    print(f"Nodes: {len(nodes)} ({sum(1 for n in nodes if n['type'] == 'File')} files, "
          f"{sum(1 for n in nodes if n['type'] in ['Function', 'Class', 'Method'])} AST nodes)")
    print(f"Links: {len(links)}")

if __name__ == "__main__":
    main()
#!/usr/bin/env python3
"""Create visualization for AST to file node relationships."""

import asyncio
import json
from skwaq.db.neo4j_connector import get_connector

async def main():
    """Generate visualization HTML file."""
    connector = get_connector()
    
    # Query to get all nodes and relationships for visualization
    query = """
    // Get all nodes
    MATCH (n)
    WHERE n:Repository OR n:File OR n:Function OR n:Class OR n:Method
    
    // Get all relationships
    OPTIONAL MATCH (n)-[r]->(m)
    WHERE (n:Repository AND m:File) OR
          (n:File AND (m:File OR m:Function OR m:Class OR m:Method)) OR
          ((n:Function OR n:Class OR n:Method) AND m:File)
    
    RETURN collect(distinct n) as nodes, 
           collect(distinct r) as relationships
    """
    
    result = connector.run_query(query)
    
    if not result or len(result) == 0:
        print("No data found.")
        return
    
    # Extract nodes and relationships
    nodes = result[0]["nodes"]
    relationships = result[0]["relationships"]
    
    # Process nodes
    nodes_data = []
    for node in nodes:
        node_id = node.get("elementId")
        labels = node.get("labels", [])
        
        # Determine node type from labels
        node_type = labels[0] if labels else "Unknown"
        
        # Create node data
        node_data = {
            "id": node_id,
            "label": node.get("name", ""),
            "type": node_type,
            "properties": {k: v for k, v in node.items() if k not in ["elementId", "labels", "name"]}
        }
        nodes_data.append(node_data)
    
    # Process relationships
    links_data = []
    for rel in relationships:
        if not rel:
            continue
            
        source_id = rel.get("startNodeElementId")
        target_id = rel.get("endNodeElementId")
        rel_type = rel.get("type")
        
        # Create relationship data
        link_data = {
            "source": source_id,
            "target": target_id,
            "label": rel_type,
            "properties": {k: v for k, v in rel.items() if k not in ["startNodeElementId", "endNodeElementId", "type"]}
        }
        links_data.append(link_data)
    
    # Create D3.js visualization
    html = """
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="utf-8">
        <title>Test Repository Visualization</title>
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
            
            .info-box {
                position: absolute;
                bottom: 10px;
                left: 10px;
                background-color: rgba(255, 255, 255, 0.8);
                padding: 10px;
                border-radius: 5px;
                box-shadow: 0 0 5px rgba(0, 0, 0, 0.2);
                max-width: 300px;
                max-height: 200px;
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
        </div>
        
        <div id="node-info" class="info-box" style="display: none;">
            <h4>Node Information</h4>
            <div id="info-content"></div>
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
                Unknown: "#999999"
            };
            
            // Node size by type
            const sizeMap = {
                Repository: 15,
                File: 10,
                Function: 8,
                Class: 12,
                Method: 8,
                Unknown: 6
            };
            
            // Set up the SVG
            const width = window.innerWidth;
            const height = window.innerHeight;
            
            const svg = d3.select("#graph-container")
                .append("svg")
                .attr("width", width)
                .attr("height", height);
            
            // Create the simulation
            const simulation = d3.forceSimulation()
                .force("link", d3.forceLink().id(d => d.id).distance(100))
                .force("charge", d3.forceManyBody().strength(-300))
                .force("center", d3.forceCenter(width / 2, height / 2))
                .force("collision", d3.forceCollide().radius(d => sizeMap[d.type] * 2));
            
            // Create links
            const link = svg.append("g")
                .selectAll("line")
                .data(linksData)
                .enter()
                .append("line")
                .attr("class", "link")
                .attr("stroke-width", 2);
            
            // Create link labels
            const linkLabel = svg.append("g")
                .selectAll("text")
                .data(linksData)
                .enter()
                .append("text")
                .attr("class", "link-label")
                .text(d => d.label);
            
            // Create nodes
            const node = svg.append("g")
                .selectAll("circle")
                .data(nodesData)
                .enter()
                .append("circle")
                .attr("class", "node")
                .attr("r", d => sizeMap[d.type] || 5)
                .attr("fill", d => colorMap[d.type] || "#999")
                .call(d3.drag()
                    .on("start", dragstarted)
                    .on("drag", dragged)
                    .on("end", dragended))
                .on("click", showNodeInfo)
                .on("mouseover", function() {
                    d3.select(this).attr("stroke", "#000").attr("stroke-width", 2);
                })
                .on("mouseout", function() {
                    d3.select(this).attr("stroke", "#fff").attr("stroke-width", 1.5);
                });
            
            // Create node labels
            const nodeLabel = svg.append("g")
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
                    .attr("cx", d => d.x = Math.max(sizeMap[d.type], Math.min(width - sizeMap[d.type], d.x)))
                    .attr("cy", d => d.y = Math.max(sizeMap[d.type], Math.min(height - sizeMap[d.type], d.y)));
                
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
                            html += `<li>${key}: ${value}</li>`;
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
            
            function filterGraph() {
                const showRepository = document.getElementById("show-repository").checked;
                const showFile = document.getElementById("show-file").checked;
                const showFunction = document.getElementById("show-function").checked;
                const showClass = document.getElementById("show-class").checked;
                const showMethod = document.getElementById("show-method").checked;
                
                // Filter nodes
                node.style("display", d => {
                    if (d.type === "Repository" && !showRepository) return "none";
                    if (d.type === "File" && !showFile) return "none";
                    if (d.type === "Function" && !showFunction) return "none";
                    if (d.type === "Class" && !showClass) return "none";
                    if (d.type === "Method" && !showMethod) return "none";
                    return null;
                });
                
                // Filter node labels
                nodeLabel.style("display", d => {
                    if (d.type === "Repository" && !showRepository) return "none";
                    if (d.type === "File" && !showFile) return "none";
                    if (d.type === "Function" && !showFunction) return "none";
                    if (d.type === "Class" && !showClass) return "none";
                    if (d.type === "Method" && !showMethod) return "none";
                    return null;
                });
                
                // Filter links based on visible nodes
                link.style("display", d => {
                    const sourceVisible = (
                        (d.source.type === "Repository" && showRepository) ||
                        (d.source.type === "File" && showFile) ||
                        (d.source.type === "Function" && showFunction) ||
                        (d.source.type === "Class" && showClass) ||
                        (d.source.type === "Method" && showMethod)
                    );
                    
                    const targetVisible = (
                        (d.target.type === "Repository" && showRepository) ||
                        (d.target.type === "File" && showFile) ||
                        (d.target.type === "Function" && showFunction) ||
                        (d.target.type === "Class" && showClass) ||
                        (d.target.type === "Method" && showMethod)
                    );
                    
                    return sourceVisible && targetVisible ? null : "none";
                });
                
                // Filter link labels
                linkLabel.style("display", d => {
                    const sourceVisible = (
                        (d.source.type === "Repository" && showRepository) ||
                        (d.source.type === "File" && showFile) ||
                        (d.source.type === "Function" && showFunction) ||
                        (d.source.type === "Class" && showClass) ||
                        (d.source.type === "Method" && showMethod)
                    );
                    
                    const targetVisible = (
                        (d.target.type === "Repository" && showRepository) ||
                        (d.target.type === "File" && showFile) ||
                        (d.target.type === "Function" && showFunction) ||
                        (d.target.type === "Class" && showClass) ||
                        (d.target.type === "Method" && showMethod)
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
                svg.selectAll("g").attr("transform", event.transform);
            }
        </script>
    </body>
    </html>
    """
    
    # Replace placeholders with actual data
    html = html.replace("${nodes_json}", json.dumps(nodes_data))
    html = html.replace("${links_json}", json.dumps(links_data))
    
    # Write to file
    with open("/tmp/test_repo_visualization.html", "w") as f:
        f.write(html)
    
    print(f"Visualization created at /tmp/test_repo_visualization.html")

if __name__ == "__main__":
    asyncio.run(main())
#!/usr/bin/env python3

"""
Visualize AST nodes with their AI summaries in a Neo4j browser with both PART_OF and DESCRIBES relationships.
"""

import asyncio
import os
import json
import webbrowser
from typing import Dict, List, Any

async def create_ast_visualization():
    """Create a graph visualization of AST nodes with AI summaries."""
    print("Creating AST visualization with AI summaries...")
    
    # Import necessary modules
    from skwaq.db.neo4j_connector import get_connector
    
    # Initialize the graph connector
    connector = get_connector()
    
    # Query for AST nodes and their summaries
    query = """
    MATCH (ast)-[:PART_OF]->(file:File)
    WHERE (ast:Function OR ast:Class OR ast:Method) AND ast.code IS NOT NULL
    OPTIONAL MATCH (summary:CodeSummary)-[:DESCRIBES]->(ast)
    RETURN 
        elementId(ast) as ast_id,
        ast.name as ast_name,
        labels(ast) as ast_labels,
        ast.start_line as start_line,
        ast.end_line as end_line,
        elementId(file) as file_id,
        file.name as file_name,
        file.path as file_path,
        elementId(summary) as summary_id,
        summary.summary as summary_text
    LIMIT 100
    """
    
    results = connector.run_query(query)
    print(f"Found {len(results)} AST nodes")
    
    # Prepare graph data
    graph_data = {
        "nodes": [],
        "links": []
    }
    
    node_ids = set()
    
    # Add investigation node
    investigation_id = "investigation-root"
    graph_data["nodes"].append({
        "id": investigation_id,
        "label": "AttackBot AST Analysis",
        "type": "Investigation",
        "color": "#ff7f0e",
        "properties": {
            "description": "Analysis of AttackBot AST nodes with AI summaries"
        }
    })
    node_ids.add(investigation_id)
    
    # Process results
    for result in results:
        ast_id = str(result["ast_id"])
        file_id = str(result["file_id"]) if result["file_id"] else None
        summary_id = str(result["summary_id"]) if result["summary_id"] else None
        
        # Add AST node if not already added
        if ast_id not in node_ids:
            node_ids.add(ast_id)
            node_type = result["ast_labels"][0] if result["ast_labels"] else "ASTNode"
            
            graph_data["nodes"].append({
                "id": ast_id,
                "label": result["ast_name"] or "Unnamed AST Node",
                "type": node_type,
                "properties": {
                    "start_line": result["start_line"],
                    "end_line": result["end_line"]
                },
                "color": "#8da0cb" if node_type == "Function" else 
                         "#e78ac3" if node_type == "Class" else
                         "#a6d854" if node_type == "Method" else "#999999"
            })
            
            # Link to investigation
            graph_data["links"].append({
                "source": investigation_id,
                "target": ast_id,
                "type": "HAS_AST_NODE"
            })
        
        # Add file node if not already added
        if file_id and file_id not in node_ids:
            node_ids.add(file_id)
            graph_data["nodes"].append({
                "id": file_id,
                "label": result["file_name"] or os.path.basename(result["file_path"] or "Unknown"),
                "type": "File",
                "properties": {
                    "path": result["file_path"]
                },
                "color": "#66c2a5"
            })
            
            # Link to investigation
            graph_data["links"].append({
                "source": investigation_id,
                "target": file_id,
                "type": "HAS_FILE"
            })
        
        # Add summary node if not already added
        if summary_id and summary_id not in node_ids:
            node_ids.add(summary_id)
            summary_text = result["summary_text"] or "No summary available"
            short_summary = summary_text[:50] + "..." if len(summary_text) > 50 else summary_text
            
            graph_data["nodes"].append({
                "id": summary_id,
                "label": f"Summary: {short_summary}",
                "type": "CodeSummary",
                "properties": {
                    "summary": summary_text
                },
                "color": "#ffd92f"
            })
            
            # Link to investigation
            graph_data["links"].append({
                "source": investigation_id,
                "target": summary_id,
                "type": "HAS_SUMMARY"
            })
        
        # Add relationships
        if file_id:
            # AST to File relationship (PART_OF)
            graph_data["links"].append({
                "source": ast_id,
                "target": file_id,
                "type": "PART_OF"
            })
            
            # File to AST relationship (DEFINES)
            graph_data["links"].append({
                "source": file_id,
                "target": ast_id,
                "type": "DEFINES"
            })
        
        if summary_id:
            # Summary to AST relationship (DESCRIBES)
            graph_data["links"].append({
                "source": summary_id,
                "target": ast_id,
                "type": "DESCRIBES"
            })
    
    # Create the HTML visualization
    html_file = "ast_summaries_visualization.html"
    await create_html_visualization(graph_data, html_file)
    
    print(f"Visualization created: {html_file}")
    
    # Open the visualization in a browser
    webbrowser.open(f"file://{os.path.abspath(html_file)}")
    
    return html_file

async def create_html_visualization(graph_data: Dict[str, List[Any]], output_file: str):
    """Create an HTML file with D3.js visualization."""
    html_template = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>AST Nodes with AI Summaries Visualization</title>
        <script src="https://d3js.org/d3.v7.min.js"></script>
        <script src="https://unpkg.com/d3-force-3d@3.0.3/dist/d3-force-3d.min.js"></script>
        <style>
            body {
                font-family: Arial, sans-serif;
                margin: 0;
                padding: 0;
                overflow: hidden;
            }
            
            #graph-container {
                width: 100vw;
                height: 100vh;
                background-color: #f5f5f5;
            }
            
            .node {
                stroke: #fff;
                stroke-width: 1.5px;
            }
            
            .link {
                stroke-opacity: 0.6;
            }
            
            .node-label {
                pointer-events: none;
                font-size: 10px;
            }
            
            #tooltip {
                position: absolute;
                background-color: white;
                border: 1px solid #ddd;
                border-radius: 4px;
                padding: 10px;
                max-width: 300px;
                max-height: 200px;
                overflow: auto;
                display: none;
                z-index: 1000;
                font-size: 12px;
                box-shadow: 0 2px 5px rgba(0, 0, 0, 0.2);
            }
            
            .tooltip-property {
                margin-bottom: 5px;
            }
            
            .tooltip-property span:first-child {
                font-weight: bold;
            }
            
            #controls {
                position: absolute;
                top: 10px;
                left: 10px;
                background-color: rgba(255, 255, 255, 0.8);
                padding: 10px;
                border-radius: 4px;
                box-shadow: 0 2px 5px rgba(0, 0, 0, 0.2);
                z-index: 1000;
            }
            
            #search {
                margin-bottom: 10px;
            }
            
            .legend {
                position: absolute;
                bottom: 10px;
                left: 10px;
                background-color: rgba(255, 255, 255, 0.8);
                padding: 10px;
                border-radius: 4px;
                box-shadow: 0 2px 5px rgba(0, 0, 0, 0.2);
                z-index: 1000;
            }
            
            .legend-item {
                display: flex;
                align-items: center;
                margin-bottom: 5px;
            }
            
            .legend-color {
                width: 15px;
                height: 15px;
                margin-right: 5px;
                border-radius: 50%;
            }
        </style>
    </head>
    <body>
        <div id="graph-container"></div>
        <div id="tooltip"></div>
        
        <div id="controls">
            <div id="search">
                <input type="text" id="search-input" placeholder="Search nodes..." style="width: 200px;">
            </div>
            <div>
                <label>
                    <input type="checkbox" id="toggle-physics" checked>
                    Enable Physics
                </label>
            </div>
            <div>
                <label>
                    <input type="range" id="charge-strength" min="-2000" max="-10" value="-500" step="10">
                    Charge Strength
                </label>
            </div>
            <div>
                <label>
                    <input type="range" id="link-distance" min="10" max="300" value="100" step="5">
                    Link Distance
                </label>
            </div>
            <div>
                <button id="export-image">Export as PNG</button>
            </div>
        </div>
        
        <div class="legend">
            <h3 style="margin-top: 0;">Legend</h3>
            <div class="legend-item">
                <div class="legend-color" style="background-color: #ff7f0e;"></div>
                <span>Investigation</span>
            </div>
            <div class="legend-item">
                <div class="legend-color" style="background-color: #8da0cb;"></div>
                <span>Function</span>
            </div>
            <div class="legend-item">
                <div class="legend-color" style="background-color: #e78ac3;"></div>
                <span>Class</span>
            </div>
            <div class="legend-item">
                <div class="legend-color" style="background-color: #a6d854;"></div>
                <span>Method</span>
            </div>
            <div class="legend-item">
                <div class="legend-color" style="background-color: #66c2a5;"></div>
                <span>File</span>
            </div>
            <div class="legend-item">
                <div class="legend-color" style="background-color: #ffd92f;"></div>
                <span>CodeSummary</span>
            </div>
        </div>
        
        <script>
            // Graph data
            const graphData = GRAPH_DATA_PLACEHOLDER;
            
            // Set up the SVG container
            const width = window.innerWidth;
            const height = window.innerHeight;
            
            const svg = d3.select('#graph-container')
                .append('svg')
                .attr('width', width)
                .attr('height', height);
            
            // Create force simulation
            const simulation = d3.forceSimulation()
                .force('link', d3.forceLink().id(d => d.id).distance(100))
                .force('charge', d3.forceManyBody().strength(-500))
                .force('center', d3.forceCenter(width / 2, height / 2))
                .force('collide', d3.forceCollide().radius(d => 20));
            
            // Create arrow marker definitions
            svg.append('defs').selectAll('marker')
                .data(['arrowhead'])
                .enter().append('marker')
                .attr('id', d => d)
                .attr('viewBox', '0 -5 10 10')
                .attr('refX', 20)
                .attr('refY', 0)
                .attr('markerWidth', 6)
                .attr('markerHeight', 6)
                .attr('orient', 'auto')
                .append('path')
                .attr('d', 'M0,-5L10,0L0,5');
            
            // Add links to the SVG
            const link = svg.append('g')
                .selectAll('line')
                .data(graphData.links)
                .enter().append('line')
                .attr('class', 'link')
                .attr('stroke', '#999')
                .attr('stroke-width', 1)
                .attr('marker-end', 'url(#arrowhead)');
            
            // Add link text to show relationship type
            const linkText = svg.append('g')
                .selectAll('text')
                .data(graphData.links)
                .enter().append('text')
                .attr('font-size', 8)
                .attr('text-anchor', 'middle')
                .text(d => d.type);
            
            // Add nodes to the SVG
            const node = svg.append('g')
                .selectAll('circle')
                .data(graphData.nodes)
                .enter().append('circle')
                .attr('class', 'node')
                .attr('r', d => d.type === 'Investigation' ? 20 : 10)
                .attr('fill', d => d.color || '#69b3a2')
                .call(d3.drag()
                    .on('start', dragstarted)
                    .on('drag', dragged)
                    .on('end', dragended));
            
            // Add node labels
            const nodeLabel = svg.append('g')
                .selectAll('text')
                .data(graphData.nodes)
                .enter().append('text')
                .attr('class', 'node-label')
                .attr('text-anchor', 'middle')
                .attr('dy', d => d.type === 'Investigation' ? 30 : 20)
                .text(d => d.label)
                .attr('font-size', d => d.type === 'Investigation' ? 12 : 8)
                .each(function(d) {
                    // Wrap long labels
                    const text = d3.select(this);
                    const words = d.label.split(/\\s+/);
                    if (words.length > 2) {
                        text.text(words.slice(0, 2).join(' ') + '...');
                    }
                });
            
            // Initialize simulation with nodes and links
            simulation.nodes(graphData.nodes).on('tick', ticked);
            simulation.force('link').links(graphData.links);
            
            // Set up tooltip for node hover
            const tooltip = d3.select('#tooltip');
            
            node.on('mouseover', function(event, d) {
                const tooltipContent = getTooltipContent(d);
                tooltip.html(tooltipContent)
                    .style('left', (event.pageX + 10) + 'px')
                    .style('top', (event.pageY + 10) + 'px')
                    .style('display', 'block');
                
                // Highlight connected nodes and links
                const connected = getConnectedNodes(d.id);
                node.attr('opacity', n => connected.has(n.id) || n.id === d.id ? 1 : 0.2);
                link.attr('opacity', l => l.source.id === d.id || l.target.id === d.id ? 1 : 0.1);
                nodeLabel.attr('opacity', n => connected.has(n.id) || n.id === d.id ? 1 : 0.2);
                linkText.attr('opacity', l => l.source.id === d.id || l.target.id === d.id ? 1 : 0.1);
            })
            .on('mouseout', function() {
                tooltip.style('display', 'none');
                node.attr('opacity', 1);
                link.attr('opacity', 0.6);
                nodeLabel.attr('opacity', 1);
                linkText.attr('opacity', 1);
            })
            .on('click', function(event, d) {
                // Zoom in on click
                event.stopPropagation();
                const scale = 2;
                const translate = [width / 2 - scale * d.x, height / 2 - scale * d.y];
                
                svg.transition()
                    .duration(750)
                    .call(d3.zoom().transform, d3.zoomIdentity.translate(translate[0], translate[1]).scale(scale));
            });
            
            // Set up search functionality
            const searchInput = document.getElementById('search-input');
            searchInput.addEventListener('input', function() {
                const searchTerm = this.value.toLowerCase();
                
                if (searchTerm === '') {
                    node.attr('opacity', 1);
                    link.attr('opacity', 0.6);
                    nodeLabel.attr('opacity', 1);
                    return;
                }
                
                const matchingNodes = new Set();
                graphData.nodes.forEach(n => {
                    if (n.label.toLowerCase().includes(searchTerm) || 
                        n.type.toLowerCase().includes(searchTerm)) {
                        matchingNodes.add(n.id);
                    }
                });
                
                node.attr('opacity', n => matchingNodes.has(n.id) ? 1 : 0.2);
                nodeLabel.attr('opacity', n => matchingNodes.has(n.id) ? 1 : 0.2);
                
                const relatedLinks = new Set();
                graphData.links.forEach(l => {
                    if (matchingNodes.has(l.source.id) || matchingNodes.has(l.target.id)) {
                        relatedLinks.add(l);
                    }
                });
                
                link.attr('opacity', l => relatedLinks.has(l) ? 0.6 : 0.1);
            });
            
            // Set up physics toggle
            const physicsToggle = document.getElementById('toggle-physics');
            physicsToggle.addEventListener('change', function() {
                if (this.checked) {
                    simulation.alpha(0.3).restart();
                } else {
                    simulation.stop();
                }
            });
            
            // Set up charge strength slider
            const chargeSlider = document.getElementById('charge-strength');
            chargeSlider.addEventListener('input', function() {
                simulation.force('charge').strength(parseFloat(this.value));
                simulation.alpha(0.3).restart();
            });
            
            // Set up link distance slider
            const linkDistanceSlider = document.getElementById('link-distance');
            linkDistanceSlider.addEventListener('input', function() {
                simulation.force('link').distance(parseFloat(this.value));
                simulation.alpha(0.3).restart();
            });
            
            // Set up export as PNG
            document.getElementById('export-image').addEventListener('click', function() {
                const svgNode = document.querySelector('svg');
                const svgData = new XMLSerializer().serializeToString(svgNode);
                const canvas = document.createElement('canvas');
                canvas.width = width;
                canvas.height = height;
                
                const ctx = canvas.getContext('2d');
                ctx.fillStyle = '#f5f5f5';
                ctx.fillRect(0, 0, width, height);
                
                const img = new Image();
                img.onload = function() {
                    ctx.drawImage(img, 0, 0);
                    const pngData = canvas.toDataURL('image/png');
                    const link = document.createElement('a');
                    link.download = 'ast_visualization.png';
                    link.href = pngData;
                    link.click();
                };
                
                img.src = 'data:image/svg+xml;base64,' + btoa(unescape(encodeURIComponent(svgData)));
            });
            
            // Set up zoom behavior
            const zoom = d3.zoom()
                .scaleExtent([0.1, 10])
                .on('zoom', zoomed);
            
            svg.call(zoom);
            
            function zoomed(event) {
                const g = svg.selectAll('g');
                g.attr('transform', event.transform);
            }
            
            function ticked() {
                link
                    .attr('x1', d => d.source.x)
                    .attr('y1', d => d.source.y)
                    .attr('x2', d => d.target.x)
                    .attr('y2', d => d.target.y);
                
                linkText
                    .attr('x', d => (d.source.x + d.target.x) / 2)
                    .attr('y', d => (d.source.y + d.target.y) / 2);
                
                node
                    .attr('cx', d => d.x = Math.max(20, Math.min(width - 20, d.x)))
                    .attr('cy', d => d.y = Math.max(20, Math.min(height - 20, d.y)));
                
                nodeLabel
                    .attr('x', d => d.x)
                    .attr('y', d => d.y);
            }
            
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
                if (!physicsToggle.checked) {
                    d.fx = event.x;
                    d.fy = event.y;
                } else {
                    d.fx = null;
                    d.fy = null;
                }
            }
            
            function getTooltipContent(d) {
                let content = `<div><strong>${d.label}</strong> (${d.type})</div>`;
                
                if (d.properties) {
                    content += '<div style="margin-top: 10px;">';
                    
                    for (const [key, value] of Object.entries(d.properties)) {
                        if (key === 'summary' && value) {
                            content += `<div class="tooltip-property"><span>Summary:</span><br>${value}</div>`;
                        } else if (value) {
                            content += `<div class="tooltip-property"><span>${key}:</span> ${value}</div>`;
                        }
                    }
                    
                    content += '</div>';
                }
                
                return content;
            }
            
            function getConnectedNodes(nodeId) {
                const connected = new Set();
                
                graphData.links.forEach(link => {
                    if (link.source.id === nodeId) {
                        connected.add(link.target.id);
                    } else if (link.target.id === nodeId) {
                        connected.add(link.source.id);
                    }
                });
                
                return connected;
            }
            
            // Fit the graph to the viewport
            function fitGraphToViewport() {
                const bounds = svg.node().getBBox();
                const dx = bounds.width;
                const dy = bounds.height;
                const x = bounds.x + dx / 2;
                const y = bounds.y + dy / 2;
                
                const scale = 0.9 / Math.max(dx / width, dy / height);
                const translate = [width / 2 - scale * x, height / 2 - scale * y];
                
                svg.transition()
                    .duration(750)
                    .call(zoom.transform, d3.zoomIdentity.translate(translate[0], translate[1]).scale(scale));
            }
            
            // Call fitGraphToViewport after a short delay to ensure the graph has stabilized
            setTimeout(fitGraphToViewport, 1000);
        </script>
    </body>
    </html>
    """
    
    # Replace placeholder with actual graph data
    html_content = html_template.replace("GRAPH_DATA_PLACEHOLDER", json.dumps(graph_data))
    
    # Write HTML to file
    with open(output_file, "w") as f:
        f.write(html_content)

if __name__ == "__main__":
    asyncio.run(create_ast_visualization())
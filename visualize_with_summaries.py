"""
Create a visualization that includes AI summaries for code nodes.
"""

import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

from skwaq.db.neo4j_connector import get_connector
from skwaq.utils.logging import get_logger

logger = get_logger(__name__)

def visualize_with_summaries(investigation_id: Optional[str] = None, output_file: Optional[str] = None):
    """Create a visualization that includes AI summaries for code nodes.
    
    Args:
        investigation_id: Optional ID of the investigation to visualize
        output_file: Optional output file path for the visualization
    """
    try:
        connector = get_connector()
        print(f"Connected to Neo4j database")
        
        # Determine what to visualize
        if investigation_id:
            print(f"Visualizing investigation with ID: {investigation_id}")
            
            # Check if investigation exists
            inv_query = """
            MATCH (i:Investigation)
            WHERE i.id = $id
            RETURN i.name as name
            """
            
            inv = connector.run_query(inv_query, {"id": investigation_id})
            if not inv:
                print(f"Error: Investigation {investigation_id} not found")
                return None
            
            print(f"Found investigation: {inv[0]['name']}")
            
            # Get files in the investigation
            files_query = """
            MATCH (i:Investigation)-[:INCLUDES]->(f:File)
            WHERE i.id = $id
            RETURN elementId(f) as id, f.path as path, f.name as name
            """
            
            files = connector.run_query(files_query, {"id": investigation_id})
            print(f"Found {len(files)} files in the investigation")
            
            # Get file IDs
            file_ids = [file["id"] for file in files]
            
            if not file_ids:
                print("No files found in the investigation")
                return None
            
            # Get relationships for visualization
            query = """
            // Get AST nodes connected to investigation files
            MATCH (f:File)<-[:PART_OF]-(ast)
            WHERE elementId(f) IN $file_ids AND (ast:Function OR ast:Class OR ast:Method)
            
            // Get AI summaries connected to AST nodes
            OPTIONAL MATCH (ast)<-[:DESCRIBES]-(summary:CodeSummary)
            
            // Get other relationships between AST nodes
            OPTIONAL MATCH (ast)-[r:CALLS|EXTENDS|IMPLEMENTS|CONTAINS]->(other)
            WHERE other:Function OR other:Class OR other:Method
            
            // Return all components
            RETURN 
                elementId(f) as file_id,
                f.path as file_path,
                f.name as file_name,
                elementId(ast) as ast_id,
                ast.name as ast_name,
                labels(ast) as ast_labels,
                elementId(summary) as summary_id,
                summary.summary as summary_text,
                TYPE(r) as rel_type,
                elementId(other) as other_id,
                other.name as other_name,
                labels(other) as other_labels
            """
            
            results = connector.run_query(query, {"file_ids": file_ids})
            print(f"Found {len(results)} relationships for visualization")
            
        else:
            # Visualize the entire repository
            print("Visualizing the entire repository")
            
            # Get repository node
            repo_query = """
            MATCH (r:Repository)
            RETURN elementId(r) as id, r.name as name
            LIMIT 1
            """
            
            repos = connector.run_query(repo_query)
            if not repos:
                print("No repository found in the database")
                return None
            
            repo_id = repos[0]["id"]
            repo_name = repos[0]["name"]
            print(f"Found repository: {repo_name}")
            
            # Get all the relationships for visualization
            query = """
            // Get files in the repository
            MATCH (r:Repository)-[:CONTAINS*]->(f:File)
            WHERE elementId(r) = $repo_id
            
            // Get AST nodes connected to files
            MATCH (f)<-[:PART_OF]-(ast)
            WHERE ast:Function OR ast:Class OR ast:Method
            
            // Get AI summaries connected to AST nodes
            OPTIONAL MATCH (ast)<-[:DESCRIBES]-(summary:CodeSummary)
            
            // Get other relationships between AST nodes
            OPTIONAL MATCH (ast)-[r:CALLS|EXTENDS|IMPLEMENTS|CONTAINS]->(other)
            WHERE other:Function OR other:Class OR other:Method
            
            // Return all components
            RETURN 
                elementId(f) as file_id,
                f.path as file_path,
                f.name as file_name,
                elementId(ast) as ast_id,
                ast.name as ast_name,
                labels(ast) as ast_labels,
                elementId(summary) as summary_id,
                summary.summary as summary_text,
                TYPE(r) as rel_type,
                elementId(other) as other_id,
                other.name as other_name,
                labels(other) as other_labels
            LIMIT 1000
            """
            
            results = connector.run_query(query, {"repo_id": repo_id})
            print(f"Found {len(results)} relationships for visualization (limited to 1000)")
            
        # Process results into graph data
        nodes = {}
        links = []
        
        # Process each relationship
        for result in results:
            # Add file node if not already added
            file_id = result["file_id"]
            if file_id not in nodes:
                nodes[file_id] = {
                    "id": file_id,
                    "name": result["file_name"],
                    "path": result["file_path"],
                    "type": "File",
                    "group": 1
                }
            
            # Add AST node if not already added
            ast_id = result["ast_id"]
            if ast_id not in nodes:
                ast_labels = result["ast_labels"]
                ast_type = ast_labels[0] if ast_labels else "Unknown"
                nodes[ast_id] = {
                    "id": ast_id,
                    "name": result["ast_name"],
                    "type": ast_type,
                    "group": 2
                }
            
            # Add link between file and AST node
            links.append({
                "source": ast_id,
                "target": file_id,
                "type": "PART_OF"
            })
            
            # Add summary node if available
            if result["summary_id"] is not None:
                summary_id = result["summary_id"]
                if summary_id not in nodes:
                    nodes[summary_id] = {
                        "id": summary_id,
                        "name": "Summary",
                        "summary": result["summary_text"],
                        "type": "CodeSummary",
                        "group": 3
                    }
                
                # Add link between AST node and summary node
                links.append({
                    "source": summary_id,
                    "target": ast_id,
                    "type": "DESCRIBES"
                })
            
            # Add other AST node and relationship if available
            if result["other_id"] is not None:
                other_id = result["other_id"]
                if other_id not in nodes:
                    other_labels = result["other_labels"]
                    other_type = other_labels[0] if other_labels else "Unknown"
                    nodes[other_id] = {
                        "id": other_id,
                        "name": result["other_name"],
                        "type": other_type,
                        "group": 2
                    }
                
                # Add link between AST nodes
                links.append({
                    "source": ast_id,
                    "target": other_id,
                    "type": result["rel_type"]
                })
        
        # Create graph data
        graph_data = {
            "nodes": list(nodes.values()),
            "links": links
        }
        
        print(f"Created graph with {len(graph_data['nodes'])} nodes and {len(graph_data['links'])} links")
        
        # Create HTML visualization
        html = create_html_visualization(graph_data, investigation_id)
        
        # Determine output file
        if not output_file:
            # Create a default filename
            if investigation_id:
                output_file = f"investigation-{investigation_id}-with-summaries.html"
            else:
                output_file = "repository-with-summaries.html"
        
        # Write to file
        with open(output_file, "w") as f:
            f.write(html)
        
        print(f"Visualization saved to: {output_file}")
        return output_file
        
    except Exception as e:
        print(f"Error creating visualization: {e}")
        import traceback
        traceback.print_exc()
        return None

def create_html_visualization(graph_data: Dict[str, List[Dict[str, Any]]], title: Optional[str] = None) -> str:
    """Create an HTML visualization from graph data.
    
    Args:
        graph_data: Dictionary with nodes and links
        title: Optional title for the visualization
    
    Returns:
        HTML string for the visualization
    """
    # Create a title for the visualization
    if not title:
        title = "Code Visualization with AI Summaries"
    
    # Convert graph data to JSON
    graph_json = json.dumps(graph_data)
    
    # Create HTML
    html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>{title}</title>
    <style>
        body {{
            margin: 0;
            font-family: Arial, sans-serif;
            overflow: hidden;
        }}
        #controls {{
            position: absolute;
            top: 10px;
            left: 10px;
            background: rgba(255, 255, 255, 0.8);
            padding: 10px;
            border-radius: 5px;
            z-index: 1;
        }}
        #node-info {{
            position: absolute;
            bottom: 10px;
            left: 10px;
            background: rgba(255, 255, 255, 0.8);
            padding: 10px;
            border-radius: 5px;
            max-width: 500px;
            max-height: 300px;
            overflow: auto;
            z-index: 1;
        }}
        #search-container {{
            position: absolute;
            top: 10px;
            right: 10px;
            background: rgba(255, 255, 255, 0.8);
            padding: 10px;
            border-radius: 5px;
            z-index: 1;
        }}
        .search-results {{
            max-height: 300px;
            overflow-y: auto;
        }}
        .search-result {{
            padding: 5px;
            cursor: pointer;
        }}
        .search-result:hover {{
            background-color: #f0f0f0;
        }}
        .node-file {{
            fill: #7cb9e8;
            stroke: #0066cc;
            stroke-width: 1.5px;
        }}
        .node-function, .node-class, .node-method {{
            fill: #c9e265;
            stroke: #5c8a00;
            stroke-width: 1.5px;
        }}
        .node-codesummary {{
            fill: #ff9966;
            stroke: #cc5500;
            stroke-width: 1.5px;
        }}
        .link {{
            stroke: #999;
            stroke-opacity: 0.6;
        }}
        .link-part_of {{
            stroke: #0066cc;
            stroke-opacity: 0.6;
        }}
        .link-defines {{
            stroke: #cc5500;
            stroke-opacity: 0.6;
        }}
        .link-calls {{
            stroke: #5c8a00;
            stroke-opacity: 0.8;
            stroke-dasharray: 5;
        }}
        .link-describes {{
            stroke: #ff5500;
            stroke-opacity: 0.8;
        }}
    </style>
    <script src="https://d3js.org/d3.v7.min.js"></script>
</head>
<body>
    <div id="controls">
        <h2>{title}</h2>
        <div>
            <label>
                <input type="checkbox" id="toggle-files" checked> Show File Nodes
            </label>
        </div>
        <div>
            <label>
                <input type="checkbox" id="toggle-ast" checked> Show AST Nodes
            </label>
        </div>
        <div>
            <label>
                <input type="checkbox" id="toggle-summaries" checked> Show Summaries
            </label>
        </div>
        <div>
            <label>Link Distance:</label>
            <input type="range" id="link-distance" min="50" max="500" value="200">
        </div>
        <div>
            <label>Charge Strength:</label>
            <input type="range" id="charge-strength" min="-1000" max="-10" value="-300">
        </div>
        <div>
            <button id="reset-zoom">Reset Zoom</button>
        </div>
    </div>
    
    <div id="search-container">
        <div>
            <input type="text" id="search-input" placeholder="Search nodes...">
            <button id="search-button">Search</button>
        </div>
        <div id="search-results" class="search-results"></div>
    </div>
    
    <div id="node-info"></div>
    
    <script>
        // Graph data
        const data = {graph_json};
        
        // Set up SVG and visualization
        const width = window.innerWidth;
        const height = window.innerHeight;
        
        const svg = d3.select("body").append("svg")
            .attr("width", width)
            .attr("height", height);
        
        // Create zoom behavior
        const zoom = d3.zoom()
            .scaleExtent([0.1, 10])
            .on("zoom", (event) => {
                container.attr("transform", event.transform);
            });
        
        svg.call(zoom);
        
        // Create a container for the graph
        const container = svg.append("g");
        
        // Reset zoom function
        function resetZoom() {
            svg.transition().duration(750).call(
                zoom.transform,
                d3.zoomIdentity
            );
        }
        
        // Initialize force simulation
        let linkDistance = 200;
        let chargeStrength = -300;
        
        const simulation = d3.forceSimulation()
            .force("link", d3.forceLink().id(d => d.id).distance(linkDistance))
            .force("charge", d3.forceManyBody().strength(chargeStrength))
            .force("center", d3.forceCenter(width / 2, height / 2))
            .force("collision", d3.forceCollide().radius(30));
        
        // Update simulation parameters
        function updateSimulation() {
            simulation.force("link").distance(linkDistance);
            simulation.force("charge").strength(chargeStrength);
            simulation.alpha(0.3).restart();
        }
        
        // Create links
        const link = container.append("g")
            .selectAll("line")
            .data(data.links)
            .join("line")
            .attr("class", d => `link link-\${d.type.toLowerCase()}`);
        
        // Create nodes
        const node = container.append("g")
            .selectAll("circle")
            .data(data.nodes)
            .join("circle")
            .attr("r", d => {
                if (d.type === "File") return 8;
                if (d.type === "CodeSummary") return 6;
                return 5;
            })
            .attr("class", d => `node node-\${d.type.toLowerCase()}`)
            .each(d => {
                // Store original data
                d.originalX = d.x;
                d.originalY = d.y;
            })
            .call(drag(simulation));
        
        // Add title to nodes (for tooltips)
        node.append("title")
            .text(d => `\${d.name} (\${d.type})`);
            
        // Add node labels
        const label = container.append("g")
            .selectAll("text")
            .data(data.nodes)
            .join("text")
            .attr("dx", 12)
            .attr("dy", ".35em")
            .text(d => d.name)
            .style("font-size", "8px")
            .style("pointer-events", "none");
        
        // Set simulation nodes and links
        simulation.nodes(data.nodes).on("tick", ticked);
        simulation.force("link").links(data.links);
        
        // Tick function for the simulation
        function ticked() {
            link
                .attr("x1", d => d.source.x)
                .attr("y1", d => d.source.y)
                .attr("x2", d => d.target.x)
                .attr("y2", d => d.target.y);
            
            node
                .attr("cx", d => d.x)
                .attr("cy", d => d.y);
            
            label
                .attr("x", d => d.x)
                .attr("y", d => d.y);
        }
        
        // Drag function for nodes
        function drag(simulation) {
            function dragstarted(event) {
                if (!event.active) simulation.alphaTarget(0.3).restart();
                event.subject.fx = event.subject.x;
                event.subject.fy = event.subject.y;
            }
            
            function dragged(event) {
                event.subject.fx = event.x;
                event.subject.fy = event.y;
            }
            
            function dragended(event) {
                if (!event.active) simulation.alphaTarget(0);
                event.subject.fx = null;
                event.subject.fy = null;
            }
            
            return d3.drag()
                .on("start", dragstarted)
                .on("drag", dragged)
                .on("end", dragended);
        }
        
        // Node info panel
        node.on("click", (event, d) => {
            const nodeInfo = document.getElementById("node-info");
            let html = `<h3>\${d.name} (\${d.type})</h3>`;
            
            if (d.type === "File") {
                html += `<p>Path: \${d.path}</p>`;
            } else if (d.type === "CodeSummary") {
                html += `<p><strong>AI Summary:</strong></p>`;
                html += `<p>\${d.summary}</p>`;
            } else {
                // Show inbound and outbound links
                const inbound = data.links.filter(l => l.target.id === d.id);
                const outbound = data.links.filter(l => l.source.id === d.id);
                
                if (inbound.length > 0) {
                    html += `<p><strong>Inbound Relationships:</strong></p>`;
                    html += `<ul>`;
                    inbound.forEach(l => {
                        const source = data.nodes.find(n => n.id === l.source.id);
                        html += `<li>\${source.name} (\${source.type}) -[\${l.type}]-> \${d.name}</li>`;
                    });
                    html += `</ul>`;
                }
                
                if (outbound.length > 0) {
                    html += `<p><strong>Outbound Relationships:</strong></p>`;
                    html += `<ul>`;
                    outbound.forEach(l => {
                        const target = data.nodes.find(n => n.id === l.target.id);
                        html += `<li>\${d.name} -[\${l.type}]-> \${target.name} (\${target.type})</li>`;
                    });
                    html += `</ul>`;
                }
                
                // Show AI Summary if connected
                const summaryNode = data.nodes.find(n => {
                    return n.type === "CodeSummary" && data.links.some(l => 
                        l.type === "DESCRIBES" && l.source.id === n.id && l.target.id === d.id
                    );
                });
                
                if (summaryNode) {
                    html += `<p><strong>AI Summary:</strong></p>`;
                    html += `<p>\${summaryNode.summary}</p>`;
                }
            }
            
            nodeInfo.innerHTML = html;
        });
        
        // Search functionality
        document.getElementById("search-button").addEventListener("click", performSearch);
        document.getElementById("search-input").addEventListener("keyup", event => {
            if (event.key === "Enter") performSearch();
        });
        
        function performSearch() {
            const query = document.getElementById("search-input").value.toLowerCase();
            const results = data.nodes.filter(node => 
                node.name.toLowerCase().includes(query) || 
                (node.path && node.path.toLowerCase().includes(query))
            );
            
            const resultsContainer = document.getElementById("search-results");
            resultsContainer.innerHTML = "";
            
            if (results.length === 0) {
                resultsContainer.innerHTML = "<p>No results found</p>";
                return;
            }
            
            results.slice(0, 20).forEach(result => {
                const div = document.createElement("div");
                div.className = "search-result";
                div.textContent = `\${result.name} (\${result.type})`;
                div.addEventListener("click", () => {
                    // Highlight the node
                    node.attr("r", d => {
                        if (d.id === result.id) return 15;
                        if (d.type === "File") return 8;
                        if (d.type === "CodeSummary") return 6;
                        return 5;
                    });
                    
                    // Center on the node
                    const transform = d3.zoomIdentity
                        .translate(width/2, height/2)
                        .scale(1)
                        .translate(-result.x, -result.y);
                    
                    svg.transition().duration(750).call(zoom.transform, transform);
                    
                    // Show node info
                    const nodeInfo = document.getElementById("node-info");
                    let html = `<h3>\${result.name} (\${result.type})</h3>`;
                    
                    if (result.type === "File") {
                        html += `<p>Path: \${result.path}</p>`;
                    } else if (result.type === "CodeSummary") {
                        html += `<p><strong>AI Summary:</strong></p>`;
                        html += `<p>\${result.summary}</p>`;
                    }
                    
                    nodeInfo.innerHTML = html;
                });
                resultsContainer.appendChild(div);
            });
            
            if (results.length > 20) {
                const div = document.createElement("div");
                div.textContent = `...and \${results.length - 20} more results`;
                resultsContainer.appendChild(div);
            }
        }
        
        // Filter nodes
        document.getElementById("toggle-files").addEventListener("change", filterNodes);
        document.getElementById("toggle-ast").addEventListener("change", filterNodes);
        document.getElementById("toggle-summaries").addEventListener("change", filterNodes);
        
        function filterNodes() {
            const showFiles = document.getElementById("toggle-files").checked;
            const showAST = document.getElementById("toggle-ast").checked;
            const showSummaries = document.getElementById("toggle-summaries").checked;
            
            // Filter nodes
            node.style("display", d => {
                if (d.type === "File" && !showFiles) return "none";
                if ((d.type === "Function" || d.type === "Class" || d.type === "Method") && !showAST) return "none";
                if (d.type === "CodeSummary" && !showSummaries) return "none";
                return null;
            });
            
            // Filter labels
            label.style("display", d => {
                if (d.type === "File" && !showFiles) return "none";
                if ((d.type === "Function" || d.type === "Class" || d.type === "Method") && !showAST) return "none";
                if (d.type === "CodeSummary" && !showSummaries) return "none";
                return null;
            });
            
            // Filter links
            link.style("display", d => {
                const sourceType = d.source.type;
                const targetType = d.source.type;
                
                if ((sourceType === "File" || targetType === "File") && !showFiles) return "none";
                if (((sourceType === "Function" || sourceType === "Class" || sourceType === "Method") ||
                     (targetType === "Function" || targetType === "Class" || targetType === "Method")) && !showAST) return "none";
                if ((sourceType === "CodeSummary" || targetType === "CodeSummary") && !showSummaries) return "none";
                return null;
            });
        }
        
        // Update simulation parameters
        document.getElementById("link-distance").addEventListener("input", function() {
            linkDistance = +this.value;
            updateSimulation();
        });
        
        document.getElementById("charge-strength").addEventListener("input", function() {
            chargeStrength = +this.value;
            updateSimulation();
        });
        
        // Reset zoom
        document.getElementById("reset-zoom").addEventListener("click", resetZoom);
        
        // Initial reset to center the graph
        setTimeout(resetZoom, 100);
    </script>
</body>
</html>"""
    
    return html

def main():
    if len(sys.argv) > 1 and sys.argv[1] == "--help":
        print("Usage: python visualize_with_summaries.py [investigation_id] [output_file]")
        print("  investigation_id: Optional ID of the investigation to visualize")
        print("  output_file: Optional output file path for the visualization")
        return
    
    investigation_id = sys.argv[1] if len(sys.argv) > 1 else None
    output_file = sys.argv[2] if len(sys.argv) > 2 else None
    
    print(f"Creating visualization{'for investigation '+investigation_id if investigation_id else ''}")
    
    output = visualize_with_summaries(investigation_id, output_file)
    
    if output:
        print(f"Visualization created successfully: {output}")
    else:
        print("Failed to create visualization")

if __name__ == "__main__":
    main()
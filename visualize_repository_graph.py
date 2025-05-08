#!/usr/bin/env python3
"""Generate a visualization of the graph for an ingested repository."""

import sys
import json
import os
from typing import Dict, Any, List, Tuple

from skwaq.db.neo4j_connector import get_connector

def count_node_types(repo_id: str) -> Dict[str, int]:
    """Count different node types in the repository.
    
    Args:
        repo_id: Repository ingestion ID
        
    Returns:
        Dictionary of node types and counts
    """
    connector = get_connector()
    
    # Get all node types in the graph connected to this repository
    query = """
    MATCH (r:Repository)-[:CONTAINS*]->(n)
    WHERE r.ingestion_id = $id
    WITH DISTINCT labels(n) AS types, COUNT(n) AS count
    RETURN types, count
    ORDER BY count DESC
    """
    
    results = connector.run_query(query, {"id": repo_id})
    
    # Process results
    type_counts = {}
    for result in results:
        node_type = result["types"][0] if result["types"] else "Unknown"
        type_counts[node_type] = result["count"]
    
    return type_counts

def find_repository_structure(repo_id: str, limit: int = 1000) -> Tuple[List[Dict], List[Dict]]:
    """Find the repository structure in the graph.
    
    Args:
        repo_id: Repository ingestion ID
        limit: Maximum number of nodes to retrieve
        
    Returns:
        Tuple of (nodes, relationships)
    """
    connector = get_connector()
    
    # Get repository node
    repo_query = """
    MATCH (r:Repository)
    WHERE r.ingestion_id = $id
    RETURN elementId(r) AS id, r.name AS name
    """
    
    repo_result = connector.run_query(repo_query, {"id": repo_id})
    if not repo_result:
        return [], []
    
    repo_node_id = repo_result[0]["id"]
    repo_name = repo_result[0]["name"]
    
    # Get structure with directory and file nodes (limited)
    structure_query = """
    MATCH path = (r:Repository)-[:CONTAINS*1..3]->(n)
    WHERE elementId(r) = $repo_id
    WITH path, n, r
    LIMIT $limit
    RETURN path
    """
    
    structure_results = connector.run_query(
        structure_query, {"repo_id": repo_node_id, "limit": limit}
    )
    
    # Process results into nodes and relationships
    nodes = []
    relationships = []
    node_ids = set()  # To track unique nodes
    
    # Add repository node
    nodes.append({
        "id": f"n{repo_node_id}",
        "label": repo_name,
        "type": "Repository",
        "properties": {"ingestion_id": repo_id}
    })
    node_ids.add(repo_node_id)
    
    # Process paths from results
    for result in structure_results:
        path = result["path"]
        
        # Process nodes in the path
        for node in path.nodes:
            node_id = node.id
            
            # Skip if already processed
            if node_id in node_ids:
                continue
            
            # Add to nodes list
            node_type = list(node.labels)[0] if node.labels else "Unknown"
            node_data = {
                "id": f"n{node_id}",
                "label": node.get("name", node_type),
                "type": node_type,
                "properties": {}
            }
            
            # Add properties
            for key, value in node.items():
                if key != "name":  # Already used as label
                    node_data["properties"][key] = value
            
            nodes.append(node_data)
            node_ids.add(node_id)
        
        # Process relationships in the path
        for rel in path.relationships:
            relationships.append({
                "source": f"n{rel.start_node.id}",
                "target": f"n{rel.end_node.id}",
                "type": rel.type
            })
    
    return nodes, relationships

def create_html_visualization(nodes: List[Dict], relationships: List[Dict], title: str) -> str:
    """Create HTML visualization of the graph.
    
    Args:
        nodes: List of node objects
        relationships: List of relationship objects
        title: Visualization title
        
    Returns:
        HTML content
    """
    # Count node types
    node_types = {}
    for node in nodes:
        node_type = node["type"]
        if node_type not in node_types:
            node_types[node_type] = 0
        node_types[node_type] += 1
    
    # Create HTML
    html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <title>{title}</title>
        <script src="https://d3js.org/d3.v7.min.js"></script>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 0; padding: 0; display: flex; height: 100vh; }}
            #info {{ width: 300px; padding: 20px; border-right: 1px solid #ccc; overflow-y: auto; }}
            #graph {{ flex-grow: 1; }}
            h1 {{ font-size: 20px; margin-top: 0; }}
            h2 {{ font-size: 16px; margin-top: 20px; }}
            .stats {{ margin-bottom: 20px; }}
            .stat {{ display: flex; justify-content: space-between; margin-bottom: 5px; }}
            .controls {{ margin: 20px 0; }}
            button {{ padding: 5px 10px; margin-right: 5px; }}
            #search {{ width: 100%; padding: 5px; margin-bottom: 10px; }}
            #details {{ margin-top: 20px; }}
            pre {{ background: #f5f5f5; padding: 10px; overflow: auto; max-height: 300px; font-size: 12px; }}
            .node {{ cursor: pointer; }}
            .link {{ stroke: #999; stroke-opacity: 0.6; }}
            .node-Repository {{ fill: #4285F4; }}
            .node-Directory {{ fill: #34A853; }}
            .node-File {{ fill: #FBBC05; }}
            .node-Method {{ fill: #EA4335; }}
            .node-Class {{ fill: #9C27B0; }}
            .node-Function {{ fill: #00BCD4; }}
            .node-Unknown {{ fill: #9E9E9E; }}
            .legend {{ display: flex; flex-wrap: wrap; margin-top: 20px; }}
            .legend-item {{ display: flex; align-items: center; margin-right: 15px; margin-bottom: 5px; }}
            .legend-color {{ width: 12px; height: 12px; margin-right: 5px; }}
        </style>
    </head>
    <body>
        <div id="info">
            <h1>{title}</h1>
            
            <div class="stats">
                <h2>Statistics</h2>
                <div class="stat">
                    <span>Nodes:</span>
                    <span>{len(nodes)}</span>
                </div>
                <div class="stat">
                    <span>Relationships:</span>
                    <span>{len(relationships)}</span>
                </div>
            </div>
            
            <div class="stats">
                <h2>Node Types</h2>
    """
    
    # Add node type counts
    for node_type, count in sorted(node_types.items(), key=lambda x: x[1], reverse=True):
        html += f"""
                <div class="stat">
                    <span>{node_type}:</span>
                    <span>{count}</span>
                </div>
        """
    
    html += """
            </div>
            
            <div class="controls">
                <h2>Controls</h2>
                <input id="search" type="text" placeholder="Search nodes...">
                <button id="zoom-in">Zoom In</button>
                <button id="zoom-out">Zoom Out</button>
                <button id="reset">Reset</button>
            </div>
            
            <div class="legend">
                <h2>Legend</h2>
    """
    
    # Add legend items
    legend_colors = {
        "Repository": "#4285F4",
        "Directory": "#34A853",
        "File": "#FBBC05",
        "Method": "#EA4335",
        "Class": "#9C27B0",
        "Function": "#00BCD4"
    }
    
    for node_type, color in legend_colors.items():
        if node_type in node_types:
            html += f"""
                <div class="legend-item">
                    <div class="legend-color" style="background-color: {color}"></div>
                    <span>{node_type}</span>
                </div>
            """
    
    html += """
            </div>
            
            <div id="details">
                <h2>Node Details</h2>
                <div id="node-info">Click a node to see details</div>
                <pre id="node-properties"></pre>
            </div>
        </div>
        
        <div id="graph"></div>
        
        <script>
            // Graph data
            const nodes = """ + json.dumps(nodes) + """;
            const links = """ + json.dumps(relationships) + """;
            
            // Set up visualization
            const width = document.getElementById('graph').clientWidth;
            const height = document.getElementById('graph').clientHeight;
            
            // Create SVG
            const svg = d3.select('#graph')
                .append('svg')
                .attr('width', width)
                .attr('height', height);
            
            // Add zoom functionality
            const g = svg.append('g');
            const zoom = d3.zoom()
                .scaleExtent([0.1, 5])
                .on('zoom', (event) => {
                    g.attr('transform', event.transform);
                });
            
            svg.call(zoom);
            
            // Create simulation
            const simulation = d3.forceSimulation(nodes)
                .force('link', d3.forceLink(links).id(d => d.id).distance(100))
                .force('charge', d3.forceManyBody().strength(-300))
                .force('center', d3.forceCenter(width / 2, height / 2))
                .on('tick', ticked);
            
            // Create links
            const link = g.append('g')
                .selectAll('line')
                .data(links)
                .enter().append('line')
                .attr('class', 'link');
            
            // Create nodes
            const node = g.append('g')
                .selectAll('circle')
                .data(nodes)
                .enter().append('circle')
                .attr('class', d => `node node-${d.type}`)
                .attr('r', d => {
                    switch (d.type) {
                        case 'Repository': return 15;
                        case 'Directory': return 8;
                        case 'File': return 5;
                        default: return 4;
                    }
                })
                .call(d3.drag()
                    .on('start', dragstarted)
                    .on('drag', dragged)
                    .on('end', dragended));
            
            // Add node tooltips
            node.append('title')
                .text(d => `${d.type}: ${d.label}`);
            
            // Add node labels (only for important nodes)
            const label = g.append('g')
                .selectAll('text')
                .data(nodes.filter(d => d.type === 'Repository' || d.type === 'Directory'))
                .enter().append('text')
                .attr('dx', 12)
                .attr('dy', 4)
                .text(d => d.label);
            
            // Handle node clicks
            node.on('click', (event, d) => {
                d3.select('#node-info').html(`<strong>${d.type}:</strong> ${d.label}`);
                d3.select('#node-properties').text(JSON.stringify(d.properties, null, 2));
            });
            
            // Search functionality
            d3.select('#search').on('input', function() {
                const term = this.value.toLowerCase();
                
                // Highlight matching nodes
                node.attr('r', d => {
                    const isMatch = d.label.toLowerCase().includes(term) || 
                                   d.type.toLowerCase().includes(term) ||
                                   JSON.stringify(d.properties).toLowerCase().includes(term);
                    
                    if (term && isMatch) {
                        switch (d.type) {
                            case 'Repository': return 20;
                            case 'Directory': return 12;
                            case 'File': return 8;
                            default: return 6;
                        }
                    } else {
                        switch (d.type) {
                            case 'Repository': return 15;
                            case 'Directory': return 8;
                            case 'File': return 5;
                            default: return 4;
                        }
                    }
                });
            });
            
            // Handle zoom controls
            d3.select('#zoom-in').on('click', () => {
                svg.transition().duration(500).call(zoom.scaleBy, 1.5);
            });
            
            d3.select('#zoom-out').on('click', () => {
                svg.transition().duration(500).call(zoom.scaleBy, 0.75);
            });
            
            d3.select('#reset').on('click', () => {
                svg.transition().duration(500).call(
                    zoom.transform, 
                    d3.zoomIdentity.translate(width / 2, height / 2).scale(1)
                );
            });
            
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
            
            // Initial zoom to fit graph
            svg.call(zoom.transform, d3.zoomIdentity.scale(0.8));
        </script>
    </body>
    </html>
    """
    
    return html

def main():
    """Main function."""
    if len(sys.argv) < 2:
        print("Usage: python visualize_repository_graph.py <repository_id> [output_file]")
        sys.exit(1)
    
    repo_id = sys.argv[1]
    output_file = sys.argv[2] if len(sys.argv) > 2 else f"repository_graph_{repo_id}.html"
    
    # Get node type counts
    print(f"Analyzing repository: {repo_id}")
    type_counts = count_node_types(repo_id)
    
    print("\nNode Types:")
    for node_type, count in sorted(type_counts.items(), key=lambda x: x[1], reverse=True):
        print(f"  {node_type}: {count}")
    
    # Find repository structure
    print("\nFinding repository structure...")
    nodes, relationships = find_repository_structure(repo_id)
    
    print(f"Found {len(nodes)} nodes and {len(relationships)} relationships")
    
    # Create HTML visualization
    print("Creating visualization...")
    html = create_html_visualization(nodes, relationships, f"Repository Graph: {repo_id}")
    
    # Write to file
    with open(output_file, "w") as f:
        f.write(html)
    
    print(f"\nVisualization saved to: {output_file}")

if __name__ == "__main__":
    main()
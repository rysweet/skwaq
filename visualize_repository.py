#!/usr/bin/env python3
"""Script to visualize repository structure from Neo4j database"""

import json
import sys
import os
import time
from typing import Dict, Any, List, Tuple, Optional

from skwaq.db.neo4j_connector import get_connector
from skwaq.utils.logging import get_logger

logger = get_logger(__name__)

def generate_repository_graph(repo_id: str, max_nodes: int = 300) -> Dict[str, Any]:
    """Generate a graph visualization of the repository structure.
    
    Args:
        repo_id: Repository ID to visualize
        max_nodes: Maximum number of nodes to include
        
    Returns:
        Dictionary with nodes and links for visualization
    """
    connector = get_connector()
    
    # Get repository info
    repo_query = """
    MATCH (r:Repository {ingestion_id: $id})
    RETURN r
    """
    
    results = connector.run_query(repo_query, {"id": repo_id})
    if not results:
        logger.error(f"Repository with ID {repo_id} not found")
        return {"nodes": [], "links": []}
    
    repo_node = results[0]["r"]
    repo_name = repo_node.get("name", "Unknown Repository")
    
    # Get file structure
    file_query = """
    MATCH (r:Repository {ingestion_id: $id})-[:CONTAINS*]->(f:File)
    RETURN elementId(f) as id, f.path as path, f.name as name, labels(f) as labels,
           f.type as type, f.language as language
    LIMIT $max_nodes
    """
    
    file_results = connector.run_query(
        file_query, {"id": repo_id, "max_nodes": max_nodes}
    )
    
    # Get AST nodes
    ast_query = """
    MATCH (r:Repository {ingestion_id: $id})-[:CONTAINS*]->(f:File)<-[:PART_OF]-(n)
    WHERE (n:Function OR n:Method OR n:Class)
    RETURN elementId(n) as id, n.name as name, labels(n) as labels,
           elementId(f) as file_id, n.type as type
    LIMIT $max_nodes
    """
    
    ast_results = connector.run_query(
        ast_query, {"id": repo_id, "max_nodes": max_nodes}
    )
    
    # Get relationships
    rel_query = """
    MATCH (a)-[r]->(b)
    WHERE (a:File OR a:Function OR a:Method OR a:Class) AND
          (b:File OR b:Function OR b:Method OR b:Class) 
    RETURN elementId(a) as source, elementId(b) as target, type(r) as type
    LIMIT $max_links
    """
    
    rel_results = connector.run_query(
        rel_query, {"max_links": max_nodes * 5}
    )
    
    # Build nodes and links
    nodes = []
    links = []
    node_ids = set()
    
    # Add repository node
    repo_node_id = "repo_" + repo_id
    nodes.append({
        "id": repo_node_id,
        "name": repo_name,
        "group": "Repository",
        "val": 30  # Size
    })
    node_ids.add(repo_node_id)
    
    # Add file nodes
    for file_result in file_results:
        file_id = str(file_result["id"])
        if file_id in node_ids:
            continue
            
        node_type = "Directory" if "Directory" in file_result["labels"] else "File"
        node_name = file_result["name"] if file_result["name"] else os.path.basename(file_result["path"])
        language = file_result.get("language", "")
        
        nodes.append({
            "id": file_id,
            "name": node_name,
            "group": node_type,
            "val": 10 if node_type == "Directory" else 5,
            "path": file_result["path"],
            "language": language
        })
        node_ids.add(file_id)
        
        # Add link to repository
        links.append({
            "source": repo_node_id,
            "target": file_id,
            "value": 1,
            "type": "CONTAINS"
        })
    
    # Add AST nodes
    for ast_result in ast_results:
        ast_id = str(ast_result["id"])
        if ast_id in node_ids:
            continue
            
        node_type = ast_result["labels"][0] if ast_result["labels"] else "Unknown"
        node_name = ast_result["name"] if ast_result["name"] else "Unnamed " + node_type
        
        nodes.append({
            "id": ast_id,
            "name": node_name,
            "group": node_type,
            "val": 3
        })
        node_ids.add(ast_id)
        
        # Add link to file
        file_id = str(ast_result["file_id"])
        if file_id in node_ids:
            links.append({
                "source": ast_id,
                "target": file_id,
                "value": 1,
                "type": "PART_OF"
            })
    
    # Add other relationships
    for rel_result in rel_results:
        source_id = str(rel_result["source"])
        target_id = str(rel_result["target"])
        rel_type = rel_result["type"]
        
        if source_id in node_ids and target_id in node_ids:
            links.append({
                "source": source_id,
                "target": target_id,
                "value": 1,
                "type": rel_type
            })
    
    return {
        "nodes": nodes,
        "links": links
    }

def generate_html(graph_data: Dict[str, Any], title: str) -> str:
    """Generate HTML visualization for the graph data.
    
    Args:
        graph_data: Dictionary with nodes and links
        title: Title for the visualization
        
    Returns:
        HTML string for visualization
    """
    # Basic HTML template with D3.js for visualization
    html = [
        "<!DOCTYPE html>",
        "<html>",
        "<head>",
        f"    <title>{title}</title>",
        "    <script src='https://d3js.org/d3.v7.min.js'></script>",
        "    <style>",
        "        body { margin: 0; font-family: Arial, sans-serif; }",
        "        #visualization { width: 100vw; height: 100vh; }",
        "        .tooltip {",
        "            position: absolute;",
        "            text-align: center;",
        "            padding: 8px;",
        "            font: 12px sans-serif;",
        "            background: white;",
        "            border: 1px solid #ddd;",
        "            border-radius: 3px;",
        "            pointer-events: none;",
        "            z-index: 100;",
        "        }",
        "        .controls {",
        "            position: absolute;",
        "            top: 20px;",
        "            right: 20px;",
        "            padding: 10px;",
        "            background: rgba(255,255,255,0.8);",
        "            border-radius: 5px;",
        "        }",
        "    </style>",
        "</head>",
        "<body>",
        f"    <h1 style='position:absolute;top:10px;left:20px;z-index:1'>{title}</h1>",
        "    <div class='controls'>",
        "        <button id='zoom-in'>+</button>",
        "        <button id='zoom-out'>-</button>",
        "        <button id='center'>Center</button>",
        "    </div>",
        "    <div id='visualization'></div>",
        "    <div class='tooltip' style='opacity: 0;'></div>",
        "    <script>",
        f"        const data = {json.dumps(graph_data)};",
        """
        // Create a force simulation for the graph
        const svg = d3.select('#visualization')
            .append('svg')
            .attr('width', '100%')
            .attr('height', '100%');
            
        const width = window.innerWidth;
        const height = window.innerHeight;
        const color = d3.scaleOrdinal(d3.schemeCategory10);
        
        // Create a tooltip
        const tooltip = d3.select('.tooltip');
        
        // Add zoom behavior
        const zoom = d3.zoom()
            .scaleExtent([0.1, 10])
            .on('zoom', (event) => {
                container.attr('transform', event.transform);
            });
            
        svg.call(zoom);
        
        // Create container for graph
        const container = svg.append('g');
        
        // Create a force simulation
        const simulation = d3.forceSimulation(data.nodes)
            .force('link', d3.forceLink(data.links).id(d => d.id).distance(100))
            .force('charge', d3.forceManyBody().strength(-300))
            .force('center', d3.forceCenter(width / 2, height / 2))
            .force('collision', d3.forceCollide().radius(d => Math.sqrt(d.val || 5) * 4));
        
        // Create links
        const link = container.append('g')
            .selectAll('line')
            .data(data.links)
            .enter().append('line')
            .attr('stroke', d => {
                switch(d.type) {
                    case 'CONTAINS': return '#999';
                    case 'PART_OF': return '#3388cc';
                    case 'DEFINES': return '#dd8800';
                    default: return '#666';
                }
            })
            .attr('stroke-width', d => Math.sqrt(d.value || 1) * 1.5)
            .attr('stroke-opacity', 0.6);
        
        // Create nodes
        const node = container.append('g')
            .selectAll('circle')
            .data(data.nodes)
            .enter().append('circle')
            .attr('r', d => Math.sqrt(d.val || 5) * 1.5)
            .attr('fill', d => {
                switch(d.group) {
                    case 'Repository': return '#ff6347';  // tomato
                    case 'Directory': return '#4682b4';   // steelblue
                    case 'File': return '#2e8b57';        // seagreen
                    case 'Function': return '#9370db';    // mediumpurple
                    case 'Method': return '#ba55d3';      // mediumorchid
                    case 'Class': return '#ff8c00';       // darkorange
                    default: return '#777';
                }
            })
            .call(d3.drag()
                .on('start', dragStarted)
                .on('drag', dragged)
                .on('end', dragEnded))
            .on('mouseover', (event, d) => {
                tooltip.transition()
                    .duration(200)
                    .style('opacity', .9);
                    
                let tooltipContent = `<strong>${d.name}</strong><br/>Type: ${d.group}`;
                if (d.path) tooltipContent += `<br/>Path: ${d.path}`;
                if (d.language) tooltipContent += `<br/>Language: ${d.language}`;
                
                tooltip.html(tooltipContent)
                    .style('left', (event.pageX + 10) + 'px')
                    .style('top', (event.pageY - 28) + 'px');
            })
            .on('mouseout', () => {
                tooltip.transition()
                    .duration(500)
                    .style('opacity', 0);
            });
        
        // Add node labels
        const label = container.append('g')
            .selectAll('text')
            .data(data.nodes)
            .enter().append('text')
            .attr('text-anchor', 'middle')
            .attr('dy', '.35em')
            .text(d => d.name)
            .style('font-size', d => {
                if (d.group === 'Repository') return '16px';
                if (d.group === 'Directory') return '12px';
                return '10px';
            })
            .style('fill', '#333')
            .style('pointer-events', 'none')
            .style('opacity', d => {
                if (d.group === 'Repository') return 1;
                if (d.group === 'Directory') return 0.8;
                return 0.2;
            });
        
        // Add simulation ticks
        simulation.on('tick', () => {
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
        });
        
        // Drag functions
        function dragStarted(event, d) {
            if (!event.active) simulation.alphaTarget(0.3).restart();
            d.fx = d.x;
            d.fy = d.y;
        }
        
        function dragged(event, d) {
            d.fx = event.x;
            d.fy = event.y;
        }
        
        function dragEnded(event, d) {
            if (!event.active) simulation.alphaTarget(0);
            d.fx = null;
            d.fy = null;
        }
        
        // Controls
        d3.select('#zoom-in').on('click', () => {
            zoom.scaleBy(svg.transition().duration(750), 1.2);
        });
        
        d3.select('#zoom-out').on('click', () => {
            zoom.scaleBy(svg.transition().duration(750), 0.8);
        });
        
        d3.select('#center').on('click', () => {
            svg.transition().duration(750).call(
                zoom.transform,
                d3.zoomIdentity.translate(width / 2, height / 2).scale(1)
            );
        });
        
        // Fix nodes to improve layout
        data.nodes.forEach(node => {
            if (node.group === 'Repository') {
                node.fx = width / 2;
                node.fy = height / 2;
            }
        });
        """,
        "    </script>",
        "</body>",
        "</html>"
    ]
    
    return "\n".join(html)

def main():
    """Main function."""
    if len(sys.argv) < 2:
        print("Usage: python visualize_repository.py <repository_id> [max_nodes]")
        
        # List repositories
        connector = get_connector()
        query = """
        MATCH (r:Repository)
        RETURN r.ingestion_id as id, r.name as name
        """
        
        repo_results = connector.run_query(query)
        
        if repo_results:
            print("\nAvailable repositories:")
            for result in repo_results:
                print(f"  {result.get('name', 'Unknown')}: {result['id']}")
        
        sys.exit(1)
    
    repo_id = sys.argv[1]
    max_nodes = int(sys.argv[2]) if len(sys.argv) > 2 else 300
    
    # Generate the graph data
    graph_data = generate_repository_graph(repo_id, max_nodes)
    
    if not graph_data["nodes"]:
        print(f"No visualization data found for repository {repo_id}")
        sys.exit(1)
    
    # Generate HTML
    html = generate_html(graph_data, f"Repository Visualization: {repo_id}")
    
    # Save to file
    output_file = f"repository_{repo_id}_visualization.html"
    with open(output_file, "w") as f:
        f.write(html)
    
    print(f"Visualization saved to {output_file}")

if __name__ == "__main__":
    main()
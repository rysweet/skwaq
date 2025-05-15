#!/usr/bin/env python3
"""Script to ingest a repository with code summaries and visualize the graph."""

import asyncio
import os
import sys
import time
import json
from pathlib import Path
from typing import Dict, Any, List, Optional

from skwaq.core.openai_client import get_openai_client
from skwaq.db.neo4j_connector import get_connector
from skwaq.ingestion import Ingestion
from skwaq.utils.logging import get_logger
from datetime import datetime

logger = get_logger(__name__)

async def ingest_repository(repo_path: str, max_files: int = 20) -> str:
    """Ingest a repository with code summaries.
    
    Args:
        repo_path: Path to the repository
        max_files: Maximum number of files to summarize (for testing)
        
    Returns:
        Ingestion ID
    """
    print(f"Starting ingestion of {repo_path}")
    print("Initializing OpenAI client...")
    
    # Initialize OpenAI client
    model_client = get_openai_client(async_mode=True)
    
    # Create ingestion
    print("Creating ingestion instance...")
    ingestion = Ingestion(
        local_path=repo_path,
        model_client=model_client,
        parse_only=False,
        max_parallel=3
    )
    
    # Start ingestion process
    print("Starting ingestion process...")
    ingestion_id = await ingestion.ingest()
    print(f"Ingestion started with ID: {ingestion_id}")
    
    # Poll for status
    completed = False
    start_time = time.time()
    summarization_started = False
    
    print("Monitoring ingestion progress...")
    while not completed:
        # Get current status
        status = await ingestion.get_status(ingestion_id)
        
        # Print progress with a timestamp
        current_time = time.time()
        elapsed = current_time - start_time
        timestamp = datetime.now().strftime("%H:%M:%S")
        
        # Check if summarization has started
        if "summarization_stats" in status.to_dict() and status.summarization_stats and not summarization_started:
            summarization_started = True
            print(f"[{timestamp}] Summarization started after {elapsed:.2f} seconds")
        
        # Print status
        if status.total_files > 0:
            progress = (status.files_processed / status.total_files) * 100
            print(f"[{timestamp}] Progress: {progress:.2f}% ({status.files_processed}/{status.total_files}), State: {status.state}, Message: {status.message}")
        else:
            print(f"[{timestamp}] Progress: {status.progress:.2f}%, State: {status.state}, Message: {status.message}")
        
        # Check if we need to limit files for testing
        if summarization_started and max_files > 0 and status.summarization_stats.get("files_processed", 0) >= max_files:
            print(f"[{timestamp}] Reached maximum files limit ({max_files}), stopping summarization")
            break
        
        # Check if completed or failed
        if status.state in ["completed", "failed"]:
            completed = True
            if status.state == "completed":
                print(f"[{timestamp}] Completed in {elapsed:.2f} seconds")
            else:
                print(f"[{timestamp}] Failed: {status.error}")
        
        # Wait before polling again
        await asyncio.sleep(5)
    
    return ingestion_id

def create_graph_visualization(repo_id: str, output_path: str) -> None:
    """Create a visualization of the graph for a repository.
    
    Args:
        repo_id: Repository ingestion ID
        output_path: Path to save the visualization
    """
    connector = get_connector()
    
    print(f"Creating visualization for repository {repo_id}")
    
    # Gather statistics about node types
    query = """
    MATCH (r:Repository {ingestion_id: $id})
    OPTIONAL MATCH (r)-[:CONTAINS*]->(f)
    WITH r, collect(distinct labels(f)) as node_types
    UNWIND node_types as type
    RETURN type, count(*) as count
    """
    
    type_results = connector.run_query(query, {"id": repo_id})
    
    # Process node types
    type_counts = {}
    for result in type_results:
        node_type = result["type"][0] if result["type"] else "Unknown"
        type_counts[node_type] = result["count"]
    
    print("\nNode types in the repository:")
    for node_type, count in sorted(type_counts.items(), key=lambda x: x[1], reverse=True):
        print(f"  {node_type}: {count}")
    
    # Check for code summaries
    summary_query = """
    MATCH (r:Repository {ingestion_id: $id})
    OPTIONAL MATCH (n)-[:HAS_SUMMARY]->(s:CodeSummary)
    RETURN count(s) as summary_count
    """
    
    summary_results = connector.run_query(summary_query, {"id": repo_id})
    summary_count = summary_results[0]["summary_count"] if summary_results else 0
    
    print(f"\nFound {summary_count} code summaries")
    
    if summary_count > 0:
        # Get some sample summaries
        sample_query = """
        MATCH (r:Repository {ingestion_id: $id})
        MATCH (n)-[:HAS_SUMMARY]->(s:CodeSummary)
        RETURN labels(n) as node_type, n.name as name, s.summary as summary
        LIMIT 5
        """
        
        sample_results = connector.run_query(sample_query, {"id": repo_id})
        
        print("\nSample summaries:")
        for result in sample_results:
            node_type = result["node_type"][0] if result["node_type"] else "Unknown"
            name = result["name"] or "Unnamed"
            summary = result["summary"] or "No summary"
            print(f"  {node_type} '{name}': {summary[:100]}...")
    
    # Get repository structure (limit the number of nodes to avoid large visualizations)
    query = """
    MATCH (r:Repository {ingestion_id: $id})
    OPTIONAL MATCH path = (r)-[:CONTAINS*1..2]->(d)
    WITH r, collect(path) as paths
    
    // Get a limited number of CodeSummary nodes
    OPTIONAL MATCH (n)-[:HAS_SUMMARY]->(s:CodeSummary)
    WITH r, paths, n, s
    LIMIT 100
    
    RETURN r, paths, collect(n) as nodes, collect(s) as summaries
    """
    
    results = connector.run_query(query, {"id": repo_id})
    
    # Create visualization data
    if not results:
        print("No repository found with ID:", repo_id)
        return
    
    nodes = []
    links = []
    
    # Add repository node
    repo = results[0]["r"]
    repo_id_str = f"n{repo.element_id}"
    nodes.append({
        "id": repo_id_str,
        "label": repo.get("name", "Repository"),
        "type": "Repository",
        "properties": {k: v for k, v in repo.items()}
    })
    
    # Process paths (directories and files)
    for path in results[0]["paths"]:
        for node in path.nodes:
            if node.element_id == repo.element_id:
                continue  # Skip repository node (already added)
            
            node_id_str = f"n{node.element_id}"
            
            # Check if node already exists
            if not any(n["id"] == node_id_str for n in nodes):
                node_type = list(node.labels)[0] if node.labels else "Unknown"
                nodes.append({
                    "id": node_id_str,
                    "label": node.get("name", node_type),
                    "type": node_type,
                    "properties": {k: v for k, v in node.items()}
                })
        
        for rel in path.relationships:
            source_id = f"n{rel.start_node.element_id}"
            target_id = f"n{rel.end_node.element_id}"
            
            # Add link if both nodes exist and link doesn't already exist
            if (any(n["id"] == source_id for n in nodes) and 
                any(n["id"] == target_id for n in nodes) and
                not any(l["source"] == source_id and l["target"] == target_id for l in links)):
                
                links.append({
                    "source": source_id,
                    "target": target_id,
                    "type": rel.type
                })
    
    # Process code nodes with summaries
    for node in results[0]["nodes"]:
        node_id_str = f"n{node.element_id}"
        
        # Skip if already added
        if any(n["id"] == node_id_str for n in nodes):
            continue
        
        node_type = list(node.labels)[0] if node.labels else "Unknown"
        nodes.append({
            "id": node_id_str,
            "label": node.get("name", node_type),
            "type": node_type,
            "properties": {k: v for k, v in node.items()}
        })
    
    # Process summary nodes
    for summary in results[0]["summaries"]:
        summary_id_str = f"s{summary.element_id}"
        
        # Add summary node
        nodes.append({
            "id": summary_id_str,
            "label": "Summary",
            "type": "CodeSummary",
            "properties": {
                "summary": summary.get("summary", "")
            }
        })
        
        # Find the node this summary is attached to
        summary_query = """
        MATCH (n)-[:HAS_SUMMARY]->(s:CodeSummary)
        WHERE elementId(s) = $summary_id
        RETURN elementId(n) as node_id
        """
        
        summary_results = connector.run_query(summary_query, {"summary_id": summary.element_id})
        
        # Add link from code node to summary
        if summary_results:
            node_id = summary_results[0]["node_id"]
            node_id_str = f"n{node_id}"
            
            # Only add the link if both nodes exist
            if any(n["id"] == node_id_str for n in nodes):
                links.append({
                    "source": node_id_str,
                    "target": summary_id_str,
                    "type": "HAS_SUMMARY"
                })
    
    # Create graph data
    graph_data = {
        "nodes": nodes,
        "links": links
    }
    
    # Create HTML visualization
    html = create_html_visualization(graph_data, f"Repository Graph: {repo_id}")
    
    # Write to file
    with open(output_path, "w") as f:
        f.write(html)
    
    print(f"\nVisualization saved to: {output_path}")
    print(f"Included {len(nodes)} nodes and {len(links)} links in the visualization")

def create_html_visualization(graph_data: Dict[str, Any], title: str) -> str:
    """Create HTML visualization of the graph.
    
    Args:
        graph_data: Dictionary with nodes and links
        title: Visualization title
        
    Returns:
        HTML content
    """
    # Count node types
    node_types = {}
    for node in graph_data["nodes"]:
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
            .node-CodeSummary {{ fill: #FF9800; }}
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
                    <span>{len(graph_data["nodes"])}</span>
                </div>
                <div class="stat">
                    <span>Relationships:</span>
                    <span>{len(graph_data["links"])}</span>
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
        "Function": "#00BCD4",
        "CodeSummary": "#FF9800"
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
            const nodes = """ + json.dumps(graph_data["nodes"]) + """;
            const links = """ + json.dumps(graph_data["links"]) + """;
            
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
                        case 'CodeSummary': return 8;
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
                .data(nodes.filter(d => d.type === 'Repository' || d.type === 'Directory' || d.type === 'CodeSummary'))
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
                            case 'CodeSummary': return 12;
                            default: return 6;
                        }
                    } else {
                        switch (d.type) {
                            case 'Repository': return 15;
                            case 'Directory': return 8;
                            case 'File': return 5;
                            case 'CodeSummary': return 8;
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
                    .attr('y2', d => d.source.y + (d.target.y - d.source.y) * 0.8);  // Curved links
                
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

async def main():
    """Main function."""
    repo_path = sys.argv[1] if len(sys.argv) > 1 else "/Users/ryan/src/msec/red/AttackBot"
    max_files = int(sys.argv[2]) if len(sys.argv) > 2 else 20
    
    # Run ingestion with a limited number of files for testing
    ingestion_id = await ingest_repository(repo_path, max_files=max_files)
    
    # Create visualization
    output_path = f"full_graph_{ingestion_id}.html"
    create_graph_visualization(ingestion_id, output_path)

if __name__ == "__main__":
    asyncio.run(main())
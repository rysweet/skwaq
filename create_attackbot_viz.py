#!/usr/bin/env python3
"""Script to create a comprehensive visualization of the AttackBot repository with investigation."""

import json
import sys
from pathlib import Path

from skwaq.db.neo4j_connector import get_connector
from skwaq.utils.logging import get_logger

logger = get_logger(__name__)

def create_comprehensive_visualization(
    repo_id: str,
    investigation_id: str,
    output_path: str,
    max_nodes: int = 1000
):
    """Create a comprehensive visualization of repository and investigation.
    
    Args:
        repo_id: Repository ID to visualize
        investigation_id: Investigation ID to visualize
        output_path: Output path for the HTML file
        max_nodes: Maximum number of nodes to include
    """
    connector = get_connector()
    
    # Create initial data structure
    data = {
        "nodes": [],
        "links": []
    }
    
    node_ids = set()
    
    # Get investigation info
    investigation_query = """
    MATCH (i:Investigation {id: $id})
    RETURN i
    """
    investigation_results = connector.run_query(investigation_query, {"id": investigation_id})
    
    if not investigation_results:
        logger.error(f"Investigation with ID {investigation_id} not found")
        return
    
    investigation = investigation_results[0]["i"]
    investigation_id_str = investigation_id
    
    # Add investigation node
    data["nodes"].append({
        "id": investigation_id_str,
        "label": investigation.get("title", "Investigation"),
        "type": "Investigation",
        "color": "#4b76e8",
        "group": 1,
        "is_funnel_identified": False,
        "properties": {k: v for k, v in investigation.items()}
    })
    node_ids.add(investigation_id_str)
    
    # Get repository info
    repo_query = """
    MATCH (r:Repository {ingestion_id: $id})
    RETURN r
    """
    
    repo_results = connector.run_query(repo_query, {"id": repo_id})
    if not repo_results:
        logger.error(f"Repository with ID {repo_id} not found")
        return
    
    repo = repo_results[0]["r"]
    repo_id_str = "repo_" + repo_id
    
    # Add repository node
    data["nodes"].append({
        "id": repo_id_str,
        "label": repo.get("name", "Repository"),
        "type": "Repository",
        "color": "#6610f2",
        "group": 5,
        "is_funnel_identified": False,
        "properties": {k: v for k, v in repo.items()}
    })
    node_ids.add(repo_id_str)
    
    # Create direct link between investigation and repository
    data["links"].append({
        "source": investigation_id_str,
        "target": repo_id_str,
        "type": "ANALYZES"
    })
    
    # Get the top-level directories and files
    structure_query = """
    MATCH (r:Repository {ingestion_id: $id})-[:CONTAINS]->(n)
    WHERE (n:File OR n:Directory)
    RETURN elementId(n) as id, labels(n) as labels, n.name as name, n.path as path
    LIMIT $limit
    """
    
    structure_results = connector.run_query(
        structure_query, {"id": repo_id, "limit": max_nodes // 5}
    )
    
    # Add file/directory nodes
    for item in structure_results:
        item_id = str(item["id"])
        if item_id in node_ids:
            continue
            
        node_type = "File" if "File" in item["labels"] else "Directory"
        name = item["name"]
        
        node_data = {
            "id": item_id,
            "label": name,
            "type": node_type,
            "color": "#20c997" if node_type == "File" else "#34A853",
            "group": 4 if node_type == "File" else 3,
            "is_funnel_identified": False,
            "properties": {
                "name": name,
                "path": item["path"]
            }
        }
        
        data["nodes"].append(node_data)
        node_ids.add(item_id)
        
        # Link to repository
        data["links"].append({
            "source": repo_id_str,
            "target": item_id,
            "type": "CONTAINS"
        })
    
    # Get important classes, methods, and functions
    code_query = """
    MATCH (r:Repository {ingestion_id: $id})-[:CONTAINS*]->(f:File)<-[:PART_OF]-(n)
    WHERE (n:Class OR n:Method OR n:Function)
    RETURN elementId(n) as id, labels(n) as labels, n.name as name, 
           elementId(f) as file_id, n.start_line as start_line
    LIMIT $limit
    """
    
    code_results = connector.run_query(
        code_query, {"id": repo_id, "limit": max_nodes // 5}
    )
    
    # Add code entity nodes
    for entity in code_results:
        entity_id = str(entity["id"])
        if entity_id in node_ids:
            continue
            
        node_type = entity["labels"][0] if entity["labels"] else "Unknown"
        name = entity["name"]
        
        node_color = {
            "Class": "#ff8c00",
            "Method": "#ba55d3",
            "Function": "#9370db",
        }.get(node_type, "#777")
        
        node_group = {
            "Class": 6,
            "Method": 7,
            "Function": 8,
        }.get(node_type, 9)
        
        node_data = {
            "id": entity_id,
            "label": name,
            "type": node_type,
            "color": node_color,
            "group": node_group,
            "is_funnel_identified": False,
            "properties": {
                "name": name,
                "start_line": entity["start_line"]
            }
        }
        
        data["nodes"].append(node_data)
        node_ids.add(entity_id)
        
        # Link to file
        file_id = str(entity["file_id"])
        if file_id in node_ids:
            data["links"].append({
                "source": entity_id,
                "target": file_id,
                "type": "PART_OF"
            })
    
    # Note: We were trying to get AST nodes, but our database check showed that there are no AST nodes
    # beyond the classified ones (Function, Class, Method) that we already handled above.
    # If in the future AST nodes are present, this code could be uncommented.
    """
    # Get AST nodes from Blarify
    ast_query = '''
    MATCH (r:Repository {ingestion_id: $id})-[:CONTAINS*]->(f:File)
    MATCH (ast_node)-[:PART_OF]->(f)
    WHERE NOT (ast_node:Function OR ast_node:Class OR ast_node:Method)
    RETURN elementId(ast_node) as id, labels(ast_node) as labels, 
           ast_node.name as name, ast_node.type as node_type,
           elementId(f) as file_id
    LIMIT $limit
    '''
    
    ast_results = connector.run_query(
        ast_query, {"id": repo_id, "limit": max_nodes // 5}
    )
    
    # Add AST nodes
    for ast_node in ast_results:
        ast_id = str(ast_node["id"])
        if ast_id in node_ids:
            continue
            
        node_type = "AST_" + (ast_node["node_type"] or "Node")
        name = ast_node["name"] or node_type
        
        # For AST nodes, use a specific color
        node_data = {
            "id": ast_id,
            "label": name,
            "type": node_type,
            "color": "#1E88E5",  # Blue for AST nodes
            "group": 10,
            "is_funnel_identified": False,
            "properties": {
                "name": name,
                "type": ast_node["node_type"],
                "labels": ast_node["labels"]
            }
        }
        
        data["nodes"].append(node_data)
        node_ids.add(ast_id)
        
        # Link to file
        file_id = str(ast_node["file_id"])
        if file_id in node_ids:
            data["links"].append({
                "source": ast_id,
                "target": file_id,
                "type": "PART_OF"
            })
    """
    
    # Get AI-generated summaries
    summary_query = """
    MATCH (n)-[:HAS_SUMMARY]->(s:CodeSummary)
    OPTIONAL MATCH (n)-[:PART_OF]->(f:File)
    OPTIONAL MATCH (f)-[:PART_OF]->(r:Repository {ingestion_id: $id})
    RETURN elementId(n) as node_id, elementId(s) as summary_id, 
           s.summary as summary, labels(n) as node_labels,
           n.name as node_name
    LIMIT $limit
    """
    
    summary_results = connector.run_query(
        summary_query, {"id": repo_id, "limit": max_nodes // 5}
    )
    
    # Add summary nodes
    for summary in summary_results:
        summary_id = str(summary["summary_id"])
        if summary_id in node_ids:
            continue
            
        node_id = str(summary["node_id"])
        summary_text = summary["summary"] or "No summary available"
        
        # Truncate long summaries for display
        label = summary_text[:30] + "..." if len(summary_text) > 30 else summary_text
        
        node_data = {
            "id": summary_id,
            "label": label,
            "type": "CodeSummary",
            "color": "#FFC107",  # Amber for summaries
            "group": 11,
            "is_funnel_identified": False,
            "properties": {
                "summary": summary_text,
                "entity_name": summary["node_name"],
                "entity_type": summary["node_labels"][0] if summary["node_labels"] else "Unknown"
            }
        }
        
        data["nodes"].append(node_data)
        node_ids.add(summary_id)
        
        # Link to the node it summarizes
        if node_id in node_ids:
            data["links"].append({
                "source": node_id,
                "target": summary_id,
                "type": "HAS_SUMMARY"
            })
    
    # Get findings and vulnerabilities (if they exist)
    findings_query = """
    MATCH (i:Investigation {id: $id})-[:HAS_FINDING]->(f:Finding)
    OPTIONAL MATCH (f)-[:IDENTIFIES]->(v:Vulnerability)
    OPTIONAL MATCH (f)-[:FOUND_IN]->(file:File)
    RETURN f, v, file
    LIMIT $limit
    """
    
    findings_results = connector.run_query(
        findings_query, {"id": investigation_id, "limit": max_nodes // 5}
    )
    
    # Add finding nodes
    for result in findings_results:
        finding = result.get("f")
        vulnerability = result.get("v")
        file = result.get("file")
        
        if finding:
            finding_id = str(id(finding))
            if finding_id not in node_ids:
                node_data = {
                    "id": finding_id,
                    "label": finding.get("title", "Finding"),
                    "type": "Finding",
                    "color": "#f94144",
                    "group": 2,
                    "is_funnel_identified": False,
                    "properties": {k: v for k, v in finding.items()}
                }
                data["nodes"].append(node_data)
                node_ids.add(finding_id)
                
                # Link to investigation
                data["links"].append({
                    "source": investigation_id_str,
                    "target": finding_id,
                    "type": "HAS_FINDING"
                })
        
        if vulnerability:
            vuln_id = str(id(vulnerability))
            if vuln_id not in node_ids:
                node_data = {
                    "id": vuln_id,
                    "label": vulnerability.get("name", "Vulnerability"),
                    "type": "Vulnerability",
                    "color": "#e83e8c",
                    "group": 3,
                    "is_funnel_identified": False,
                    "properties": {k: v for k, v in vulnerability.items()}
                }
                data["nodes"].append(node_data)
                node_ids.add(vuln_id)
                
                # Link to finding
                if finding:
                    data["links"].append({
                        "source": finding_id,
                        "target": vuln_id,
                        "type": "IDENTIFIES"
                    })
        
        if file:
            file_id = str(id(file))
            if file_id not in node_ids:
                node_data = {
                    "id": file_id,
                    "label": file.get("name", "File"),
                    "type": "File",
                    "color": "#20c997",
                    "group": 4,
                    "is_funnel_identified": False,
                    "properties": {k: v for k, v in file.items()}
                }
                data["nodes"].append(node_data)
                node_ids.add(file_id)
                
                # Link to finding
                if finding:
                    data["links"].append({
                        "source": finding_id,
                        "target": file_id,
                        "type": "FOUND_IN"
                    })
    
    # Generate HTML
    create_html_visualization(data, f"AttackBot Analysis: {investigation_id}", output_path)
    print(f"Visualization saved to: {output_path}")
    print(f"Included {len(data['nodes'])} nodes and {len(data['links'])} links")

def create_html_visualization(data, title, output_path):
    """Create an HTML visualization of the graph data.
    
    Args:
        data: Graph data with nodes and links
        title: Title for the visualization
        output_path: Path to save the HTML file
    """
    html_template = f"""<!DOCTYPE html>
<html>
<head>
<meta charset='utf-8'>
<title>{title}</title>
<script src='https://d3js.org/d3.v7.min.js'></script>
<style>
    body {{ margin: 0; font-family: Arial, sans-serif; overflow: hidden; }}
    .container {{ display: flex; height: 100vh; }}
    .graph {{ flex: 1; }}
    .sidebar {{ width: 300px; padding: 20px; background: #f8f9fa; overflow-y: auto; }}
    .node {{ stroke: #fff; stroke-width: 1.5px; }}
    .funnel-node {{ animation: pulse 2s infinite; }}
    .link {{ stroke: #999; stroke-opacity: 0.6; }}
    h1 {{ font-size: 24px; margin-top: 0; }}
    h2 {{ font-size: 18px; margin-top: 20px; }}
    pre {{ background: #f1f1f1; padding: 10px; overflow: auto; }}
    .controls {{ margin: 20px 0; }}
    button {{ background: #4b76e8; color: white; border: none; padding: 8px 12px; margin-right: 5px; cursor: pointer; }}
    button:hover {{ background: #3a5bbf; }}
    .node-details {{ margin-top: 20px; }}
    .legend {{ margin-top: 20px; }}
    .legend-item {{ display: flex; align-items: center; margin-bottom: 5px; }}
    .legend-color {{ width: 15px; height: 15px; margin-right: 8px; }}
    .legend-funnel {{ width: 15px; height: 15px; margin-right: 8px; border: 2px solid #FFD700; }}
    .zoom-controls {{ position: absolute; top: 20px; left: 20px; background: rgba(255,255,255,0.7); padding: 10px; border-radius: 5px; }}
    .tooltip {{ position: absolute; background: white; border: 1px solid #ddd; padding: 10px; border-radius: 5px; pointer-events: none; opacity: 0; }}
    .search-container {{ margin-top: 10px; margin-bottom: 20px; }}
    #search {{ width: 100%; padding: 8px; border: 1px solid #ddd; border-radius: 4px; }}
    
    @keyframes pulse {{
        0% {{
            stroke-width: 1.5px;
            stroke-opacity: 1;
        }}
        50% {{
            stroke-width: 4px;
            stroke-opacity: 0.8;
        }}
        100% {{
            stroke-width: 1.5px;
            stroke-opacity: 1;
        }}
    }}
</style>
</head>
<body>
<div class='container'>
<div class='graph' id='graph'></div>
<div class='sidebar'>
<h1>{title}</h1>

<div class='search-container'>
    <input type='text' id='search' placeholder='Search nodes...' />
</div>

<div class='controls'>
    <button id='zoom-in'>Zoom In</button>
    <button id='zoom-out'>Zoom Out</button>
    <button id='reset'>Reset</button>
</div>

<div class='controls'>
    <h3>Filter Nodes</h3>
    <div style='margin-bottom: 5px;'>
        <input type='checkbox' id='filter-repo' checked>
        <label for='filter-repo'>Show Repository</label>
    </div>
    <div style='margin-bottom: 5px;'>
        <input type='checkbox' id='filter-files' checked>
        <label for='filter-files'>Show Files</label>
    </div>
    <div style='margin-bottom: 5px;'>
        <input type='checkbox' id='filter-code' checked>
        <label for='filter-code'>Show Code Entities</label>
    </div>
    <div style='margin-bottom: 5px;'>
        <input type='checkbox' id='filter-ast' checked>
        <label for='filter-ast'>Show AST Nodes</label>
    </div>
    <div style='margin-bottom: 5px;'>
        <input type='checkbox' id='filter-summaries' checked>
        <label for='filter-summaries'>Show AI Summaries</label>
    </div>
    <div style='margin-bottom: 5px;'>
        <input type='checkbox' id='filter-findings' checked>
        <label for='filter-findings'>Show Findings</label>
    </div>
</div>

<div class='legend'>
    <h2>Legend</h2>
    <div class='legend-item'>
        <div class='legend-color' style='background-color: #4b76e8;'></div>
        <div>Investigation</div>
    </div>
    <div class='legend-item'>
        <div class='legend-color' style='background-color: #6610f2;'></div>
        <div>Repository</div>
    </div>
    <div class='legend-item'>
        <div class='legend-color' style='background-color: #34A853;'></div>
        <div>Directory</div>
    </div>
    <div class='legend-item'>
        <div class='legend-color' style='background-color: #20c997;'></div>
        <div>File</div>
    </div>
    <div class='legend-item'>
        <div class='legend-color' style='background-color: #ff8c00;'></div>
        <div>Class</div>
    </div>
    <div class='legend-item'>
        <div class='legend-color' style='background-color: #ba55d3;'></div>
        <div>Method</div>
    </div>
    <div class='legend-item'>
        <div class='legend-color' style='background-color: #9370db;'></div>
        <div>Function</div>
    </div>
    <div class='legend-item'>
        <div class='legend-color' style='background-color: #1E88E5;'></div>
        <div>AST Node</div>
    </div>
    <div class='legend-item'>
        <div class='legend-color' style='background-color: #FFC107;'></div>
        <div>AI Summary</div>
    </div>
    <div class='legend-item'>
        <div class='legend-color' style='background-color: #f94144;'></div>
        <div>Finding</div>
    </div>
    <div class='legend-item'>
        <div class='legend-color' style='background-color: #e83e8c;'></div>
        <div>Vulnerability</div>
    </div>
</div>

<div class='node-details'>
    <h2>Node Details</h2>
    <p id='node-description'>Click on a node to see details</p>
    <pre id='node-properties'></pre>
</div>
</div>
</div>
<div class='tooltip' id='tooltip'></div>
<script>
    // Graph data
    const graphData = {json.dumps(data)};
    
    // Set up the simulation
    const width = document.getElementById('graph').clientWidth;
    const height = document.getElementById('graph').clientHeight;
    
    const svg = d3.select('#graph')
        .append('svg')
        .attr('width', width)
        .attr('height', height);
    
    // Create zoom behavior
    const zoom = d3.zoom()
        .scaleExtent([0.1, 5])
        .on('zoom', (event) => {{
            g.attr('transform', event.transform);
        }});
    
    // Apply zoom to SVG
    svg.call(zoom);
    
    // Create a group for the graph
    const g = svg.append('g');
    
    // Initialize the simulation
    const simulation = d3.forceSimulation(graphData.nodes)
        .force('link', d3.forceLink(graphData.links).id(d => d.id).distance(100))
        .force('charge', d3.forceManyBody().strength(-300))
        .force('center', d3.forceCenter(width / 2, height / 2))
        .force('collide', d3.forceCollide().radius(d => getNodeRadius(d) * 1.5))
        .on('tick', ticked);
    
    // Create links
    const link = g.append('g')
        .attr('class', 'links')
        .selectAll('line')
        .data(graphData.links)
        .enter().append('line')
        .attr('class', 'link')
        .attr('stroke-width', 1)
        .attr('stroke', d => linkColor(d));
    
    // Create nodes
    const node = g.append('g')
        .attr('class', 'nodes')
        .selectAll('circle')
        .data(graphData.nodes)
        .enter().append('circle')
        .attr('class', d => d.is_funnel_identified ? 'node funnel-node' : 'node')
        .attr('r', d => getNodeRadius(d))
        .attr('fill', d => d.color || '#999')
        .attr('stroke', d => d.is_funnel_identified ? (d.stroke_color || '#FFD700') : '#fff')
        .attr('stroke-width', d => d.is_funnel_identified ? (d.stroke_width || 3) : 1.5)
        .call(d3.drag()
            .on('start', dragstarted)
            .on('drag', dragged)
            .on('end', dragended));
    
    // Add labels to nodes
    const label = g.append('g')
        .attr('class', 'labels')
        .selectAll('text')
        .data(graphData.nodes)
        .enter().append('text')
        .text(d => d.label)
        .attr('font-size', d => labelSize(d))
        .attr('dx', d => labelOffset(d))
        .attr('dy', 4)
        .attr('opacity', d => labelOpacity(d));
    
    // Add tooltips
    const tooltip = d3.select('#tooltip');
    
    node
        .on('mouseover', function(event, d) {{
            // Highlight node
            d3.select(this)
                .attr('stroke', '#FFA500')
                .attr('stroke-width', 3);
                
            // Show tooltip
            tooltip.transition()
                .duration(200)
                .style('opacity', .9);
            
            // Create tooltip content
            let tooltipContent = `<strong>${{d.label}}</strong><br/>${{d.type}}`;
            
            // Add file path if available
            if (d.properties && d.properties.path) {{
                tooltipContent += `<br/>Path: ${{d.properties.path}}`;
            }}
            
            tooltip.html(tooltipContent)
                .style('left', (event.pageX + 10) + 'px')
                .style('top', (event.pageY - 28) + 'px');
        }})
        .on('mouseout', function() {{
            // Restore original appearance
            d3.select(this)
                .attr('stroke', d => d.is_funnel_identified ? (d.stroke_color || '#FFD700') : '#fff')
                .attr('stroke-width', d => d.is_funnel_identified ? (d.stroke_width || 3) : 1.5);
                
            // Hide tooltip
            tooltip.transition()
                .duration(500)
                .style('opacity', 0);
        }})
        .on('click', showNodeDetails);
    
    // Simulation tick function
    function ticked() {{
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
    }}
    
    // Drag functions
    function dragstarted(event, d) {{
        if (!event.active) simulation.alphaTarget(0.3).restart();
        d.fx = d.x;
        d.fy = d.y;
    }}
    
    function dragged(event, d) {{
        d.fx = event.x;
        d.fy = event.y;
    }}
    
    function dragended(event, d) {{
        if (!event.active) simulation.alphaTarget(0);
        d.fx = null;
        d.fy = null;
    }}
    
    // Helper to determine node radius based on type
    function getNodeRadius(node) {{
        switch(node.type) {{
            case 'Investigation':
                return 20;
            case 'Repository':
                return 18;
            case 'Directory':
                return 12;
            case 'File':
                return 8;
            case 'Class':
                return 10;
            case 'Method':
            case 'Function':
                return 6;
            case 'Finding':
                return 10;
            case 'Vulnerability':
                return 12;
            default:
                return 7;
        }}
    }}
    
    // Helper to determine label size
    function labelSize(node) {{
        switch(node.type) {{
            case 'Investigation':
            case 'Repository':
                return '14px';
            case 'Directory':
                return '12px';
            case 'File':
            case 'Class':
                return '10px';
            default:
                return '8px';
        }}
    }}
    
    // Helper to determine label offset
    function labelOffset(node) {{
        return getNodeRadius(node) + 5;
    }}
    
    // Helper to determine label opacity
    function labelOpacity(node) {{
        switch(node.type) {{
            case 'Investigation':
            case 'Repository':
            case 'Directory':
                return 1;
            case 'File':
            case 'Class':
                return 0.8;
            default:
                return 0.6;
        }}
    }}
    
    // Helper to determine link color
    function linkColor(link) {{
        switch(link.type) {{
            case 'ANALYZES':
                return '#4b76e8';
            case 'CONTAINS':
                return '#34A853';
            case 'PART_OF':
                return '#9370db';
            case 'HAS_FINDING':
                return '#f94144';
            case 'IDENTIFIES':
                return '#e83e8c';
            case 'FOUND_IN':
                return '#20c997';
            default:
                return '#999';
        }}
    }}
    
    // Show node details in sidebar
    function showNodeDetails(event, d) {{
        document.getElementById('node-description').textContent = `${{d.type}}: ${{d.label}}`;
        document.getElementById('node-properties').textContent = JSON.stringify(d.properties, null, 2);
    }}
    
    // Control buttons
    document.getElementById('zoom-in').addEventListener('click', () => {{
        svg.transition().duration(500).call(zoom.scaleBy, 1.5);
    }});
    
    document.getElementById('zoom-out').addEventListener('click', () => {{
        svg.transition().duration(500).call(zoom.scaleBy, 0.75);
    }});
    
    document.getElementById('reset').addEventListener('click', () => {{
        svg.transition().duration(500).call(
            zoom.transform, 
            d3.zoomIdentity.translate(width / 2, height / 2).scale(0.8)
        );
    }});
    
    // Filter controls
    function applyFilters() {{
        // Get filter states
        const showRepo = document.getElementById('filter-repo').checked;
        const showFiles = document.getElementById('filter-files').checked;
        const showCode = document.getElementById('filter-code').checked;
        const showAst = document.getElementById('filter-ast').checked;
        const showSummaries = document.getElementById('filter-summaries').checked;
        const showFindings = document.getElementById('filter-findings').checked;
        
        // Apply node visibility
        node.style('display', d => {{
            // Always show Investigation
            if (d.type === 'Investigation') return null;
            
            // Repository filter
            if ((d.type === 'Repository') && !showRepo) return 'none';
            
            // Files filter (includes Directory)
            if ((d.type === 'File' || d.type === 'Directory') && !showFiles) return 'none';
            
            // Code entities filter
            if ((d.type === 'Class' || d.type === 'Method' || d.type === 'Function') && !showCode) return 'none';
            
            // AST nodes filter - check if type starts with AST_
            if (d.type && d.type.startsWith('AST_') && !showAst) return 'none';
            
            // AI Summaries filter
            if (d.type === 'CodeSummary' && !showSummaries) return 'none';
            
            // Findings filter (includes Vulnerability)
            if ((d.type === 'Finding' || d.type === 'Vulnerability') && !showFindings) return 'none';
            
            return null;
        }});
        
        // Update links based on node visibility
        link.style('display', d => {{
            // Get the source and target nodes
            const sourceNode = graphData.nodes.find(n => n.id === d.source.id);
            const targetNode = graphData.nodes.find(n => n.id === d.target.id);
            
            // Skip if nodes not found
            if (!sourceNode || !targetNode) return null;
            
            // Repository filter
            if ((sourceNode.type === 'Repository' || targetNode.type === 'Repository') && !showRepo) return 'none';
            
            // Files filter
            if (((sourceNode.type === 'File' || sourceNode.type === 'Directory') || 
                 (targetNode.type === 'File' || targetNode.type === 'Directory')) && !showFiles) return 'none';
            
            // Code entities filter
            if (((sourceNode.type === 'Class' || sourceNode.type === 'Method' || sourceNode.type === 'Function') || 
                 (targetNode.type === 'Class' || targetNode.type === 'Method' || targetNode.type === 'Function')) && !showCode) return 'none';
            
            // AST nodes filter
            if ((sourceNode.type && sourceNode.type.startsWith('AST_') || 
                 targetNode.type && targetNode.type.startsWith('AST_')) && !showAst) return 'none';
            
            // AI Summaries filter
            if ((sourceNode.type === 'CodeSummary' || targetNode.type === 'CodeSummary') && !showSummaries) return 'none';
            
            // Findings filter
            if (((sourceNode.type === 'Finding' || sourceNode.type === 'Vulnerability') || 
                 (targetNode.type === 'Finding' || targetNode.type === 'Vulnerability')) && !showFindings) return 'none';
            
            return null;
        }});
        
        // Also update labels
        label.style('display', d => {{
            // Match the same logic as nodes
            if (d.type === 'Investigation') return null;
            if ((d.type === 'Repository') && !showRepo) return 'none';
            if ((d.type === 'File' || d.type === 'Directory') && !showFiles) return 'none';
            if ((d.type === 'Class' || d.type === 'Method' || d.type === 'Function') && !showCode) return 'none';
            if ((d.type && d.type.startsWith('AST_')) && !showAst) return 'none';
            if (d.type === 'CodeSummary' && !showSummaries) return 'none';
            if ((d.type === 'Finding' || d.type === 'Vulnerability') && !showFindings) return 'none';
            return null;
        }});
    }}
    
    // Search functionality
    document.getElementById('search').addEventListener('input', function() {{
        const searchTerm = this.value.toLowerCase();
        
        if (!searchTerm) {{
            // Reset when search is cleared
            node.attr('stroke', d => d.is_funnel_identified ? (d.stroke_color || '#FFD700') : '#fff')
                .attr('stroke-width', d => d.is_funnel_identified ? (d.stroke_width || 3) : 1.5)
                .attr('r', d => getNodeRadius(d));
                
            label.attr('font-size', d => labelSize(d))
                 .attr('opacity', d => labelOpacity(d));
                 
            return;
        }}
        
        // Highlight matching nodes
        node.each(function(d) {{
            const element = d3.select(this);
            const labelElement = label.filter(l => l.id === d.id);
            
            const matchesSearch = 
                d.label.toLowerCase().includes(searchTerm) || 
                d.type.toLowerCase().includes(searchTerm) ||
                (d.properties && d.properties.path && 
                 d.properties.path.toLowerCase().includes(searchTerm));
            
            if (matchesSearch) {{
                // Highlight
                element.attr('stroke', '#FFA500')
                       .attr('stroke-width', 3)
                       .attr('r', getNodeRadius(d) * 1.3);
                       
                labelElement.attr('font-size', d => {{
                                const baseSize = parseInt(labelSize(d));
                                return (baseSize + 2) + 'px';
                            }})
                            .attr('opacity', 1);
            }} else {{
                // Normal
                element.attr('stroke', d => d.is_funnel_identified ? (d.stroke_color || '#FFD700') : '#fff')
                       .attr('stroke-width', d => d.is_funnel_identified ? (d.stroke_width || 3) : 1.5)
                       .attr('r', d => getNodeRadius(d));
                       
                labelElement.attr('font-size', d => labelSize(d))
                           .attr('opacity', d => labelOpacity(d));
            }}
        }});
    }});
    
    // Add event listeners for filters
    document.getElementById('filter-repo').addEventListener('change', applyFilters);
    document.getElementById('filter-files').addEventListener('change', applyFilters);
    document.getElementById('filter-code').addEventListener('change', applyFilters);
    document.getElementById('filter-ast').addEventListener('change', applyFilters);
    document.getElementById('filter-summaries').addEventListener('change', applyFilters);
    document.getElementById('filter-findings').addEventListener('change', applyFilters);
    
    // Apply filters on initial load
    applyFilters();
    
    // Initial reset to center the graph
    svg.call(
        zoom.transform,
        d3.zoomIdentity.translate(width / 2, height / 2).scale(0.8)
    );
    
    // Pin repository and investigation in position
    graphData.nodes.forEach(node => {{
        if (node.type === 'Investigation') {{
            node.fx = width * 0.3;
            node.fy = height * 0.5;
        }}
        
        if (node.type === 'Repository') {{
            node.fx = width * 0.7;
            node.fy = height * 0.5;
        }}
    }});
</script>
</body>
</html>
"""
    
    with open(output_path, "w") as f:
        f.write(html_template)

def main():
    if len(sys.argv) < 3:
        print("Usage: python create_attackbot_viz.py <repo_id> <investigation_id> [output_path]")
        print("\nExample: python create_attackbot_viz.py 16bd2b91-3ac7-49ad-8479-c51a179a9120 inv-7398d013 attackbot_visualization.html")
        sys.exit(1)
    
    repo_id = sys.argv[1]
    investigation_id = sys.argv[2]
    output_path = sys.argv[3] if len(sys.argv) > 3 else "attackbot_comprehensive.html"
    
    create_comprehensive_visualization(repo_id, investigation_id, output_path)

if __name__ == "__main__":
    main()
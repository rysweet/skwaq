#!/usr/bin/env python3
"""Direct visualization of investigations using the GraphVisualizer."""

import os
import sys
import argparse
import json
import datetime
import neo4j.time

# Add the project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from skwaq.visualization.graph_visualizer import GraphVisualizer
from skwaq.db.neo4j_connector import get_connector

# Custom JSON encoder for Neo4j DateTime objects
class CustomJSONEncoder(json.JSONEncoder):
    """Custom JSON encoder to handle Neo4j data types."""
    
    def default(self, obj):
        if isinstance(obj, neo4j.time.DateTime):
            return obj.to_native().isoformat()
        if isinstance(obj, datetime.datetime):
            return obj.isoformat()
        return super().default(obj)

def main():
    """Main function to visualize an investigation."""
    parser = argparse.ArgumentParser(description="Visualize an investigation")
    parser.add_argument("investigation_id", help="ID of the investigation to visualize")
    parser.add_argument("--format", choices=["html", "json", "svg"], default="html", 
                        help="Output format")
    parser.add_argument("--output", help="Output file path")
    
    args = parser.parse_args()
    
    # Set default output path if not provided
    if not args.output:
        args.output = f"investigation-{args.investigation_id}.{args.format}"
    
    try:
        # Initialize the graph visualizer
        visualizer = GraphVisualizer()
        
        # Get the investigation graph data
        graph_data = visualizer.get_investigation_graph(
            investigation_id=args.investigation_id,
            include_findings=True,
            include_vulnerabilities=True,
            include_files=True,
            include_sources_sinks=True,
            max_nodes=100
        )
        
        # Handle JSON serialization
        # First convert DateTime objects
        for node in graph_data['nodes']:
            for key, value in node.get('properties', {}).items():
                if isinstance(value, (neo4j.time.DateTime, datetime.datetime)):
                    node['properties'][key] = value.isoformat() if hasattr(value, 'isoformat') else str(value)
        
        # Export the graph based on the format
        if args.format == "html":
            # Modify the GraphVisualizer's _generate_html_template method to use our custom encoder
            original_method = visualizer._generate_html_template
            
            def custom_template_method(graph_data, title):
                # Use our custom encoder
                graph_data_json = json.dumps(graph_data, cls=CustomJSONEncoder)
                
                # Get the rest of the template from the original function
                html_template = original_method.__code__
                css_styles = html_template.co_consts[1]
                
                # Build the HTML with our serialized data
                html = [
                    "<!DOCTYPE html>",
                    "<html>",
                    "<head>",
                    "<meta charset='utf-8'>",
                    f"<title>{title}</title>",
                    "<script src='https://d3js.org/d3.v7.min.js'></script>",
                    "<style>",
                    css_styles,
                    "</style>",
                    "</head>",
                    "<body>",
                    "<div class='container'>",
                    "<div class='graph' id='graph'></div>",
                    "<div class='sidebar'>",
                    f"<h1>{title}</h1>",
                    "<div class='controls'>",
                    "<button id='zoom-in'>Zoom In</button>",
                    "<button id='zoom-out'>Zoom Out</button>",
                    "<button id='reset'>Reset</button>",
                    "</div>",
                    "<div class='controls'>",
                    "<h3>Filter Nodes</h3>",
                    "<div style='margin-bottom: 5px;'>",
                    "<input type='checkbox' id='filter-funnel' checked>",
                    "<label for='filter-funnel'>Highlight Funnel Nodes</label>",
                    "</div>",
                    "<div style='margin-bottom: 5px;'>",
                    "<input type='checkbox' id='filter-source' checked>",
                    "<label for='filter-source'>Show Sources</label>",
                    "</div>",
                    "<div style='margin-bottom: 5px;'>",
                    "<input type='checkbox' id='filter-sink' checked>",
                    "<label for='filter-sink'>Show Sinks</label>",
                    "</div>",
                    "<div style='margin-bottom: 5px;'>",
                    "<input type='checkbox' id='filter-dataflow' checked>",
                    "<label for='filter-dataflow'>Show Data Flow Paths</label>",
                    "</div>",
                    "<div style='margin-bottom: 5px;'>",
                    "<input type='checkbox' id='filter-findings' checked>",
                    "<label for='filter-findings'>Show Findings</label>",
                    "</div>",
                    "</div>",
                    "<div class='legend'>",
                    "<h2>Legend</h2>",
                    "<div class='legend-item'>",
                    "<div class='legend-color' style='background-color: #4b76e8;'></div>",
                    "<div>Investigation</div>",
                    "</div>",
                    "<div class='legend-item'>",
                    "<div class='legend-color' style='background-color: #f94144;'></div>",
                    "<div>Finding</div>",
                    "</div>",
                    "<div class='legend-item'>",
                    "<div class='legend-color' style='background-color: #e83e8c;'></div>",
                    "<div>Vulnerability</div>",
                    "</div>",
                    "<div class='legend-item'>",
                    "<div class='legend-color' style='background-color: #20c997;'></div>",
                    "<div>File</div>",
                    "</div>",
                    "<div class='legend-item'>",
                    "<div class='legend-color' style='background-color: #6610f2;'></div>",
                    "<div>Repository</div>",
                    "</div>",
                    "<div class='legend-item'>",
                    "<div class='legend-color' style='background-color: #02ccfa;'></div>",
                    "<div>Source</div>",
                    "</div>",
                    "<div class='legend-item'>",
                    "<div class='legend-color' style='background-color: #fa7602;'></div>",
                    "<div>Sink</div>",
                    "</div>",
                    "<div class='legend-item'>",
                    "<div class='legend-color' style='background-color: #fa0290;'></div>",
                    "<div>DataFlowPath</div>",
                    "</div>",
                    "<h3>Funnel Identified Nodes</h3>",
                    "<div class='legend-item'>",
                    "<div class='legend-funnel' style='background-color: #02ccfa;'></div>",
                    "<div>Source (Funnel Identified)</div>",
                    "</div>",
                    "<div class='legend-item'>",
                    "<div class='legend-funnel' style='background-color: #fa7602;'></div>",
                    "<div>Sink (Funnel Identified)</div>",
                    "</div>",
                    "</div>",
                    "<div class='node-details'>",
                    "<h2>Node Details</h2>",
                    "<p id='node-description'>Click on a node to see details</p>",
                    "<pre id='node-properties'></pre>",
                    "</div>",
                    "</div>",
                    "</div>",
                    "<div class='tooltip' id='tooltip'></div>",
                    "<script>",
                    f"// Graph data\nconst graphData = {graph_data_json};\n",
                    """
                    // Set up the SVG
                    const width = document.getElementById('graph').clientWidth;
                    const height = document.getElementById('graph').clientHeight;
                    
                    const svg = d3.select('#graph')
                        .append('svg')
                        .attr('width', width)
                        .attr('height', height);
                    
                    // Create zoom behavior
                    const zoom = d3.zoom()
                        .scaleExtent([0.1, 5])
                        .on('zoom', (event) => {
                            g.attr('transform', event.transform);
                        });
                    
                    // Apply zoom to SVG
                    svg.call(zoom);
                    
                    // Create a group for the graph
                    const g = svg.append('g');
                    
                    // Initialize the simulation
                    const simulation = d3.forceSimulation(graphData.nodes)
                        .force('link', d3.forceLink(graphData.links).id(d => d.id).distance(100))
                        .force('charge', d3.forceManyBody().strength(-300))
                        .force('center', d3.forceCenter(width / 2, height / 2))
                        .on('tick', ticked);
                    
                    // Create links
                    const link = g.append('g')
                        .attr('class', 'links')
                        .selectAll('line')
                        .data(graphData.links)
                        .enter().append('line')
                        .attr('class', 'link')
                        .attr('stroke-width', 1);
                    
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
                        .attr('font-size', '10px')
                        .attr('dx', 12)
                        .attr('dy', 4);
                    
                    // Add tooltips
                    const tooltip = d3.select('#tooltip');
                    
                    node
                        .on('mouseover', function(event, d) {
                            tooltip.transition()
                                .duration(200)
                                .style('opacity', .9);
                            
                            // Create tooltip content
                            let tooltipContent = `<strong>${d.label}</strong><br/>${d.type}`;
                            
                            // Add funnel identification badge if applicable
                            if (d.is_funnel_identified) {
                                tooltipContent += `<br/><span style="color: #FFD700; font-weight: bold;">⭐ Funnel Identified</span>`;
                                
                                // Add source or sink specific info
                                if (d.type === 'Source') {
                                    tooltipContent += `<br/>Source Type: ${d.properties.source_type || 'Unknown'}`;
                                    tooltipContent += `<br/>Confidence: ${(d.properties.confidence * 100).toFixed(0)}%`;
                                } else if (d.type === 'Sink') {
                                    tooltipContent += `<br/>Sink Type: ${d.properties.sink_type || 'Unknown'}`;
                                    tooltipContent += `<br/>Confidence: ${(d.properties.confidence * 100).toFixed(0)}%`;
                                } else if (d.type === 'DataFlowPath') {
                                    tooltipContent += `<br/>Vulnerability: ${d.properties.vulnerability_type || 'Unknown'}`;
                                    tooltipContent += `<br/>Impact: ${d.properties.impact || 'Unknown'}`;
                                }
                            }
                            
                            tooltip.html(tooltipContent)
                                .style('left', (event.pageX + 10) + 'px')
                                .style('top', (event.pageY - 28) + 'px');
                        })
                        .on('mouseout', function() {
                            tooltip.transition()
                                .duration(500)
                                .style('opacity', 0);
                        })
                        .on('click', showNodeDetails);
                    
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
                    
                    // Helper to determine node radius based on type
                    function getNodeRadius(node) {
                        // If it's a funnel-identified node, make it slightly larger
                        const funnelBonus = node.is_funnel_identified ? 2 : 0;
                        
                        switch(node.type) {
                            case 'Investigation':
                                return 15;
                            case 'Finding':
                                return 10;
                            case 'Vulnerability':
                                return 12;
                            case 'File':
                                return 8;
                            case 'Repository':
                                return 13;
                            case 'Source':
                                return 12 + funnelBonus;
                            case 'Sink':
                                return 12 + funnelBonus;
                            case 'DataFlowPath':
                                return 10 + funnelBonus;
                            default:
                                return 8;
                        }
                    }
                    
                    // Show node details in sidebar
                    function showNodeDetails(event, d) {
                        document.getElementById('node-description').textContent = `${d.type}: ${d.label}`;
                        document.getElementById('node-properties').textContent = JSON.stringify(d.properties, null, 2);
                    }
                    
                    // Control buttons
                    document.getElementById('zoom-in').addEventListener('click', () => {
                        svg.transition().duration(500).call(zoom.scaleBy, 1.5);
                    });
                    
                    document.getElementById('zoom-out').addEventListener('click', () => {
                        svg.transition().duration(500).call(zoom.scaleBy, 0.75);
                    });
                    
                    document.getElementById('reset').addEventListener('click', () => {
                        svg.transition().duration(500).call(
                            zoom.transform, 
                            d3.zoomIdentity.translate(width / 2, height / 2).scale(1)
                        );
                    });
                    
                    // Filter controls
                    function applyFilters() {
                        // Get filter states
                        const highlightFunnel = document.getElementById('filter-funnel').checked;
                        const showSources = document.getElementById('filter-source').checked;
                        const showSinks = document.getElementById('filter-sink').checked;
                        const showDataFlow = document.getElementById('filter-dataflow').checked;
                        const showFindings = document.getElementById('filter-findings').checked;
                        
                        // Apply node visibility
                        node.style('display', d => {
                            if (d.type === 'Source' && !showSources) return 'none';
                            if (d.type === 'Sink' && !showSinks) return 'none';
                            if (d.type === 'DataFlowPath' && !showDataFlow) return 'none';
                            if (d.type === 'Finding' && !showFindings) return 'none';
                            return null;
                        });
                        
                        // Apply highlighting for funnel nodes
                        if (highlightFunnel) {
                            node.attr('stroke', d => d.is_funnel_identified ? (d.stroke_color || '#FFD700') : '#fff')
                                .attr('stroke-width', d => d.is_funnel_identified ? (d.stroke_width || 3) : 1.5)
                                .classed('funnel-node', d => d.is_funnel_identified);
                        } else {
                            node.attr('stroke', '#fff')
                                .attr('stroke-width', 1.5)
                                .classed('funnel-node', false);
                        }
                        
                        // Update links based on node visibility
                        link.style('display', d => {
                            // Get the source and target nodes
                            const sourceNode = graphData.nodes.find(n => n.id === d.source.id);
                            const targetNode = graphData.nodes.find(n => n.id === d.target.id);
                            
                            // Hide link if either source or target is hidden
                            if (sourceNode && targetNode) {
                                if (sourceNode.type === 'Source' && !showSources) return 'none';
                                if (sourceNode.type === 'Sink' && !showSinks) return 'none';
                                if (sourceNode.type === 'DataFlowPath' && !showDataFlow) return 'none';
                                if (sourceNode.type === 'Finding' && !showFindings) return 'none';
                                
                                if (targetNode.type === 'Source' && !showSources) return 'none';
                                if (targetNode.type === 'Sink' && !showSinks) return 'none';
                                if (targetNode.type === 'DataFlowPath' && !showDataFlow) return 'none';
                                if (targetNode.type === 'Finding' && !showFindings) return 'none';
                            }
                            
                            return null;
                        });
                        
                        // Update link style
                        link.attr('stroke', d => {
                            // Get the source and target nodes
                            const sourceNode = graphData.nodes.find(n => n.id === d.source.id);
                            const targetNode = graphData.nodes.find(n => n.id === d.target.id);
                            
                            // Highlight links between funnel-identified nodes if highlighting is enabled
                            if (highlightFunnel && sourceNode && targetNode) {
                                if (sourceNode.is_funnel_identified && targetNode.is_funnel_identified) {
                                    return '#FFD700';  // Gold for funnel links
                                }
                            }
                            
                            return '#999';  // Default color
                        });
                    }
                    
                    // Add event listeners for filters
                    document.getElementById('filter-funnel').addEventListener('change', applyFilters);
                    document.getElementById('filter-source').addEventListener('change', applyFilters);
                    document.getElementById('filter-sink').addEventListener('change', applyFilters);
                    document.getElementById('filter-dataflow').addEventListener('change', applyFilters);
                    document.getElementById('filter-findings').addEventListener('change', applyFilters);
                    
                    // Apply filters on initial load
                    applyFilters();
                    
                    // Initial reset to center the graph
                    svg.call(
                        zoom.transform,
                        d3.zoomIdentity.translate(width / 2, height / 2).scale(1)
                    );
                    """,
                    "</script>",
                    "</body>",
                    "</html>",
                ]
                
                return "\n".join(html)
            
            # Replace the method temporarily
            visualizer._generate_html_template = custom_template_method
            
            # Export the graph
            output_path = visualizer.export_graph_as_html(
                graph_data, args.output, f"Investigation {args.investigation_id}"
            )
            
            # Restore the original method
            visualizer._generate_html_template = original_method
            
        elif args.format == "json":
            # Export as JSON using our custom encoder
            with open(args.output, "w") as f:
                json.dump(graph_data, f, cls=CustomJSONEncoder, indent=2)
            output_path = args.output
            
        elif args.format == "svg":
            # Convert DateTime objects before passing to SVG export
            # which might use other libraries that don't handle our custom encoder
            output_path = visualizer.export_graph_as_svg(graph_data, args.output)
        
        print(f"Investigation graph exported to: {output_path}")
        
        # Print data summary
        print(f"Nodes: {len(graph_data['nodes'])}")
        print(f"Links: {len(graph_data['links'])}")
        
        # Count node types
        node_types = {}
        for node in graph_data['nodes']:
            node_type = node.get('type', 'unknown')
            node_types[node_type] = node_types.get(node_type, 0) + 1
        
        print("\nNode Types:")
        for node_type, count in node_types.items():
            print(f"  - {node_type}: {count}")
            
    except Exception as e:
        print(f"Error generating visualization: {e}")
        import traceback
        traceback.print_exc()
        
if __name__ == "__main__":
    main()
# Integrating Enhanced Visualization into the GUI

## Overview

We can integrate the enhanced visualization capabilities (sources/sinks highlighting) into the GUI by extending the existing visualization components. The application already has a foundation for graph visualization that uses 3D-force-graph, which is similar to our D3.js implementation.

## Implementation Plan

### 1. API Enhancements

First, we need to ensure the API returns the necessary data about sources, sinks, and data flow paths:

```typescript
// Add to skwaq/api/knowledge_graph.py
@router.get("/investigation/{investigation_id}/sources-sinks")
async def get_investigation_sources_sinks(investigation_id: str):
    """Get sources and sinks for an investigation."""
    connector = get_connector()
    
    # Query for Source nodes
    sources_query = """
    MATCH (i:Investigation {id: $id})-[:HAS_SOURCE]->(source:Source)
    OPTIONAL MATCH (source)-[:DEFINED_IN]->(sourcefile:File)
    RETURN source, sourcefile
    """
    sources = connector.run_query(sources_query, {"id": investigation_id})
    
    # Query for Sink nodes
    sinks_query = """
    MATCH (i:Investigation {id: $id})-[:HAS_SINK]->(sink:Sink)
    OPTIONAL MATCH (sink)-[:DEFINED_IN]->(sinkfile:File)
    RETURN sink, sinkfile
    """
    sinks = connector.run_query(sinks_query, {"id": investigation_id})
    
    # Query for DataFlowPath nodes
    paths_query = """
    MATCH (i:Investigation {id: $id})-[:HAS_DATA_FLOW_PATH]->(path:DataFlowPath),
          (source:Source)-[:FLOWS_TO]->(path)-[:FLOWS_TO]->(sink:Sink)
    RETURN path, id(source) as source_id, id(sink) as sink_id
    """
    paths = connector.run_query(paths_query, {"id": investigation_id})
    
    return {
        "sources": [format_node(s["source"], "Source") for s in sources],
        "sinks": [format_node(s["sink"], "Sink") for s in sinks],
        "paths": [format_path(p["path"], p["source_id"], p["sink_id"]) for p in paths]
    }
```

### 2. Update TypeScript Types

Add the necessary types:

```typescript
// Add to frontend/src/hooks/useInvestigationGraph.ts
export interface SourceNode extends GraphNode {
  source_type: string;
  confidence: number;
  is_funnel_identified: boolean;
}

export interface SinkNode extends GraphNode {
  sink_type: string;
  confidence: number;
  is_funnel_identified: boolean;
}

export interface DataFlowPath extends GraphNode {
  vulnerability_type: string;
  impact: string;
  source_id: string;
  sink_id: string;
  recommendations: string[];
  is_funnel_identified: boolean;
}
```

### 3. Update Visualization Component

Enhance the `InvestigationGraphVisualization.tsx` component:

```typescript
// Update node coloring in InvestigationGraphVisualization.tsx
.nodeColor((node: GraphNode) => {
  // First check if node is funnel-identified
  if (node.is_funnel_identified) {
    // Use brighter colors for funnel-identified nodes
    switch (node.type) {
      case 'source': return 'rgba(2, 204, 250, 0.9)';  // bright blue
      case 'sink': return 'rgba(250, 118, 2, 0.9)';    // bright orange
      case 'dataflowpath': return 'rgba(250, 2, 144, 0.9)'; // bright pink
      default: return node.color || 'rgba(255, 215, 0, 0.9)'; // gold
    }
  }
  
  // Original coloring for non-funnel nodes
  switch (node.type) {
    case 'investigation': return 'rgba(52, 152, 219, 0.8)';  // blue
    case 'repository': return 'rgba(46, 204, 113, 0.8)';     // green
    case 'finding': return 'rgba(231, 76, 60, 0.8)';         // red
    case 'vulnerability': return 'rgba(155, 89, 182, 0.8)';  // purple
    case 'file': return 'rgba(243, 156, 18, 0.8)';           // orange
    case 'function': return 'rgba(26, 188, 156, 0.8)';       // turquoise
    case 'source': return 'rgba(2, 204, 250, 0.7)';          // blue
    case 'sink': return 'rgba(250, 118, 2, 0.7)';            // orange
    case 'dataflowpath': return 'rgba(250, 2, 144, 0.7)';    // pink
    default: return 'rgba(158, 158, 158, 0.8)';              // gray
  }
})
```

### 4. Add Node Highlighting and Animations

```typescript
// Add to InvestigationGraphVisualization.tsx
.nodeThreeObject((node: GraphNode) => {
  // If node is funnel-identified, add special effects
  if (node.is_funnel_identified) {
    const material = new THREE.MeshLambertMaterial({
      color: node.color,
      transparent: true,
      opacity: 0.8
    });
    
    // Create glowing sphere with pulsing animation
    const sphere = new THREE.Mesh(
      new THREE.SphereGeometry(node.val || 5),
      material
    );
    
    // Add gold ring around funnel-identified nodes
    const ringGeometry = new THREE.TorusGeometry(
      (node.val || 5) * 1.2, // Slightly larger than the node
      0.5, // Thickness of the ring
      16, // Segments around the tube
      100 // Segments around the circumference
    );
    const ringMaterial = new THREE.MeshLambertMaterial({
      color: 0xFFD700, // Gold color
      transparent: true,
      opacity: 0.9
    });
    const ring = new THREE.Mesh(ringGeometry, ringMaterial);
    
    // Create a group for the node and its ring
    const group = new THREE.Group();
    group.add(sphere);
    group.add(ring);
    
    // Add pulsing animation
    const now = Date.now();
    const scale = 1 + 0.1 * Math.sin(now / 200);
    ring.scale.set(scale, scale, scale);
    
    return group;
  }
  
  // Default rendering for non-funnel nodes
  return false;
});
```

### 5. Add Filtering Controls

Add filtering options similar to our demo:

```tsx
// Add to controls section in InvestigationGraphVisualization.tsx
<h3>Filters</h3>
<div className="control-group">
  <label>
    <input
      type="checkbox"
      checked={showSources}
      onChange={(e) => setShowSources(e.target.checked)}
    />
    Show Sources
  </label>
</div>
<div className="control-group">
  <label>
    <input
      type="checkbox"
      checked={showSinks}
      onChange={(e) => setShowSinks(e.target.checked)}
    />
    Show Sinks
  </label>
</div>
<div className="control-group">
  <label>
    <input
      type="checkbox"
      checked={showDataFlows}
      onChange={(e) => setShowDataFlows(e.target.checked)}
    />
    Show Data Flow Paths
  </label>
</div>
<div className="control-group">
  <label>
    <input
      type="checkbox"
      checked={highlightFunnelNodes}
      onChange={(e) => setHighlightFunnelNodes(e.target.checked)}
    />
    Highlight Funnel-Identified Nodes
  </label>
</div>
```

### 6. Add Tooltip Enhancements

Enhance the tooltips to show detailed information:

```tsx
// Update tooltip content
const tooltipContent = document.createElement('div');
tooltipContent.className = 'node-tooltip';
tooltipContent.innerHTML = `
  <div class="tooltip-title">${node.label || node.name}</div>
  <div class="tooltip-type">${node.type}</div>
  ${node.is_funnel_identified ? 
    '<div class="tooltip-funnel">⭐ Funnel Identified</div>' : ''}
  ${node.type === 'source' ? 
    `<div>Source Type: ${node.source_type}</div>
     <div>Confidence: ${(node.confidence * 100).toFixed(0)}%</div>` : ''}
  ${node.type === 'sink' ? 
    `<div>Sink Type: ${node.sink_type}</div>
     <div>Confidence: ${(node.confidence * 100).toFixed(0)}%</div>` : ''}
  ${node.type === 'dataflowpath' ? 
    `<div>Vulnerability: ${node.vulnerability_type}</div>
     <div>Impact: ${node.impact}</div>` : ''}
`;
```

### 7. Update the Legend

Add entries for sources, sinks, and data flow paths:

```tsx
// Add to legend in InvestigationGraphVisualization.tsx
<div className="legend-item">
  <span className="legend-color source"></span>
  <span className="legend-label">Source</span>
</div>
<div className="legend-item">
  <span className="legend-color sink"></span>
  <span className="legend-label">Sink</span>
</div>
<div className="legend-item">
  <span className="legend-color dataflowpath"></span>
  <span className="legend-label">Data Flow Path</span>
</div>
<div className="legend-item">
  <span className="legend-color funnel-identified"></span>
  <span className="legend-label">Funnel Identified</span>
</div>
```

### 8. Add CSS for New Elements

```css
/* Add to src/styles/KnowledgeGraphVisualization.css */
.source { background-color: rgba(2, 204, 250, 0.7); }
.sink { background-color: rgba(250, 118, 2, 0.7); }
.dataflowpath { background-color: rgba(250, 2, 144, 0.7); }

.funnel-identified {
  background-color: #ffd700;
  border-radius: 50%;
}

.tooltip-funnel {
  color: #FFD700;
  font-weight: bold;
  margin-top: 5px;
}

@keyframes pulse {
  0% { opacity: 0.8; transform: scale(1); }
  50% { opacity: 1; transform: scale(1.1); }
  100% { opacity: 0.8; transform: scale(1); }
}

.funnel-node {
  animation: pulse 2s infinite;
}
```

## Benefits of Integration

By integrating these enhancements, we enable users to:

1. **Easily identify security-relevant nodes** through highlighted Sources and Sinks
2. **Focus on specific node types** using the filtering controls
3. **Quickly understand data flow paths** between sources and sinks
4. **Get detailed information** through enhanced tooltips
5. **Visualize funnel-identified nodes** with special highlighting

## Next Steps

1. Implement the API enhancements
2. Update the frontend components
3. Add tests for the new functionality
4. Document the enhanced visualization
5. Consider adding the ability to export the visualization for sharing

This integration will significantly improve the usability of the visualization for security analysis, making it easier for users to understand and address potential vulnerabilities in their code.
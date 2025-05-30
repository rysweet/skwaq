import React, { useEffect, useRef, useState } from 'react';
import { GraphData, GraphNode, GraphLink } from '../hooks/useKnowledgeGraph';
// eslint-disable-next-line @typescript-eslint/no-unused-vars
import { createForceGraph } from '../utils/forceGraphUtils';
import '../styles/KnowledgeGraphVisualization.css';

interface KnowledgeGraphVisualizationProps {
  graphData: GraphData;
  onNodeSelected: (node: GraphNode) => void;
  isLoading: boolean;
  darkMode?: boolean;
}

interface PhysicsSettings {
  gravity: number;
  linkStrength: number;
  linkDistance: number;
  chargeStrength: number;
}

/**
 * Component for visualizing the knowledge graph using 3D force graph
 */
const KnowledgeGraphVisualization: React.FC<KnowledgeGraphVisualizationProps> = ({
  graphData,
  onNodeSelected,
  isLoading,
  darkMode = false
}) => {
  const graphContainerRef = useRef<HTMLDivElement>(null);
  const graphInstanceRef = useRef<any>(null);
  const [showControls, setShowControls] = useState<boolean>(false);
  const [physicsSettings, setPhysicsSettings] = useState<PhysicsSettings>({
    gravity: -0.1,
    linkStrength: 1.5,
    linkDistance: 100,
    chargeStrength: -60
  });
  
  // Function to handle physics settings changes
  const handlePhysicsChange = (setting: keyof PhysicsSettings, value: number) => {
    setPhysicsSettings(prev => {
      const newSettings = { ...prev, [setting]: value };
      
      // Apply settings to graph if it exists
      if (graphInstanceRef.current) {
        const graph = graphInstanceRef.current;
        
        if (setting === 'gravity') {
          graph.d3Force('charge').strength(newSettings.gravity);
        } else if (setting === 'linkStrength') {
          graph.d3Force('link').strength(newSettings.linkStrength);
        } else if (setting === 'linkDistance') {
          graph.d3Force('link').distance(newSettings.linkDistance);
        } else if (setting === 'chargeStrength') {
          graph.d3Force('charge').strength(newSettings.chargeStrength);
        }
        
        // Re-heat the simulation
        graph.d3ReheatSimulation();
      }
      
      return newSettings;
    });
  };
  
  // Function to initialize the 3D force graph
  useEffect(() => {
    if (!graphContainerRef.current || isLoading) return;
    
    // Dynamic import to ensure 3d-force-graph only loads in browser environment
    import('3d-force-graph').then((ForceGraph3D) => {
      // Clear previous instance if it exists
      if (graphInstanceRef.current) {
        graphContainerRef.current?.querySelector('canvas')?.remove();
      }
      
      if (graphData.nodes.length === 0) {
        return;
      }
      
      // Node sizing based on connections
      const nodeDegrees: Record<string, number> = {};
      graphData.links.forEach(link => {
        const sourceId = typeof link.source === 'object' ? link.source.id : link.source;
        const targetId = typeof link.target === 'object' ? link.target.id : link.target;
        
        nodeDegrees[sourceId] = (nodeDegrees[sourceId] || 0) + 1;
        nodeDegrees[targetId] = (nodeDegrees[targetId] || 0) + 1;
      });
      
      // Initialize new graph
      // Create the ForceGraph3D instance
      const graph = createForceGraph(graphContainerRef.current as HTMLElement)
        .graphData(graphData)
        .backgroundColor(darkMode ? '#1a1a1a' : '#ffffff')
        .nodeLabel((node: GraphNode) => `${node.name} (${node.type})`)
        .nodeColor((node: GraphNode) => {
          // Color nodes based on type
          switch (node.type) {
            case 'vulnerability': return 'rgba(244, 67, 54, 0.8)';
            case 'cwe': return 'rgba(33, 150, 243, 0.8)';
            case 'concept': return 'rgba(76, 175, 80, 0.8)';
            case 'repository': return 'rgba(255, 193, 7, 0.8)';
            case 'file': return 'rgba(156, 39, 176, 0.8)';
            default: return 'rgba(158, 158, 158, 0.8)';
          }
        })
        .nodeRelSize(6)
        .nodeVal((node: GraphNode) => {
          // Size nodes based on their connections (degree)
          const degree = nodeDegrees[node.id] || 1;
          return Math.max(1, Math.sqrt(degree));
        })
        .linkLabel((link: GraphLink) => link.type || 'related')
        .linkColor(() => darkMode ? 'rgba(255, 255, 255, 0.2)' : 'rgba(0, 0, 0, 0.2)')
        .linkWidth((link: GraphLink) => link.value || 1)
        .linkDirectionalParticles(2)
        .linkDirectionalParticleWidth((link: GraphLink) => link.value || 1)
        .linkDirectionalParticleSpeed(0.005)
        .linkDirectionalArrowLength(3.5)
        .linkDirectionalArrowRelPos(1)
        .onNodeClick((node: GraphNode) => {
          // When a node is clicked, call the callback
          onNodeSelected(node as GraphNode);
          
          // Focus on the selected node
          graph.centerAt(node.x, node.y, node.z, 1000);
          graph.zoom(1.5, 1000);
        })
        .onNodeDragEnd((node: GraphNode) => {
          // Pin the node on drag (fx, fy, fz are fixed coordinates)
          node.fx = node.x;
          node.fy = node.y;
          node.fz = node.z;
        })
        .onNodeRightClick((node: GraphNode) => {
          // Unpin node on right-click
          node.fx = undefined;
          node.fy = undefined;
          node.fz = undefined;
          
          // Re-heat the simulation
          graph.d3ReheatSimulation();
        })
        .onLinkClick((link: GraphLink) => {
          // TODO: Add link details display or editing
          console.log('Link clicked:', link);
        });
      
      // Add node hover tooltips for additional information
      graph.nodeThreeObject((node: GraphNode) => {
        // Use default sphere rendering
        return false;
      });
      
      // Set force physics based on current settings
      graph.d3Force('charge').strength(physicsSettings.chargeStrength);
      graph.d3Force('link')
        .strength(physicsSettings.linkStrength)
        .distance(physicsSettings.linkDistance);
        
      // Add cool-down effect
      let cooldownTicks = 0;
      graph.onEngineTick(() => {
        cooldownTicks++;
        // Auto-stop the simulation after 200 ticks to save resources
        if (cooldownTicks > 200) {
          graph.cooldownTicks(0);
          cooldownTicks = 0;
        }
      });
      
      // Save reference to the graph instance
      graphInstanceRef.current = graph;
      
      // Handle window resize
      const handleResize = () => {
        graph.width(graphContainerRef.current?.clientWidth || 800);
        graph.height(graphContainerRef.current?.clientHeight || 600);
      };
      
      window.addEventListener('resize', handleResize);
      
      // Initial size
      handleResize();
      
      // Clean up on unmount
      return () => {
        window.removeEventListener('resize', handleResize);
        graph._destructor();
      };
    });
  }, [graphData, onNodeSelected, isLoading, darkMode, physicsSettings]);
  
  return (
    <div className="knowledge-graph-visualization" ref={graphContainerRef}>
      {isLoading && (
        <div className="loading-overlay">
          <div className="loading-spinner"></div>
          <p>Loading Knowledge Graph...</p>
        </div>
      )}
      {!isLoading && graphData.nodes.length === 0 && (
        <div className="empty-graph">
          <p>No graph data available. Try adjusting your filters.</p>
        </div>
      )}
      
      {/* Graph Control Panel */}
      <div className={`graph-controls ${showControls ? 'expanded' : 'collapsed'}`}>
        <button 
          className="controls-toggle" 
          onClick={() => setShowControls(!showControls)}
          aria-label={showControls ? "Hide controls" : "Show controls"}
        >
          {showControls ? '◀' : '▶'} Controls
        </button>
        
        {showControls && (
          <div className="controls-content">
            <h3>Physics Settings</h3>
            
            <div className="control-group">
              <label htmlFor="gravity">Gravity: {physicsSettings.gravity}</label>
              <input
                id="gravity"
                type="range"
                min="-1"
                max="1"
                step="0.05"
                value={physicsSettings.gravity}
                onChange={(e) => handlePhysicsChange('gravity', parseFloat(e.target.value))}
              />
            </div>
            
            <div className="control-group">
              <label htmlFor="linkStrength">Link Strength: {physicsSettings.linkStrength}</label>
              <input
                id="linkStrength"
                type="range"
                min="0"
                max="5"
                step="0.1"
                value={physicsSettings.linkStrength}
                onChange={(e) => handlePhysicsChange('linkStrength', parseFloat(e.target.value))}
              />
            </div>
            
            <div className="control-group">
              <label htmlFor="linkDistance">Link Distance: {physicsSettings.linkDistance}</label>
              <input
                id="linkDistance"
                type="range"
                min="10"
                max="300"
                step="5"
                value={physicsSettings.linkDistance}
                onChange={(e) => handlePhysicsChange('linkDistance', parseFloat(e.target.value))}
              />
            </div>
            
            <div className="control-group">
              <label htmlFor="chargeStrength">Charge Strength: {physicsSettings.chargeStrength}</label>
              <input
                id="chargeStrength"
                type="range"
                min="-200"
                max="0"
                step="5"
                value={physicsSettings.chargeStrength}
                onChange={(e) => handlePhysicsChange('chargeStrength', parseFloat(e.target.value))}
              />
            </div>
            
            <h3>Interaction Help</h3>
            <ul className="controls-help">
              <li><strong>Left-click + drag</strong>: Rotate view</li>
              <li><strong>Mouse wheel</strong>: Zoom in/out</li>
              <li><strong>Right-click + drag</strong>: Pan view</li>
              <li><strong>Click node</strong>: Select node</li>
              <li><strong>Drag node</strong>: Move and pin node</li>
              <li><strong>Right-click node</strong>: Unpin node</li>
            </ul>
            
            <button 
              className="reset-button"
              onClick={() => {
                if (graphInstanceRef.current) {
                  // Reset camera position
                  graphInstanceRef.current.zoomToFit(1000);
                  // Reheat simulation
                  graphInstanceRef.current.d3ReheatSimulation();
                  // Unpin all nodes
                  graphData.nodes.forEach((node: GraphNode) => {
                    node.fx = undefined;
                    node.fy = undefined;
                    node.fz = undefined;
                  });
                }
              }}
            >
              Reset View
            </button>
          </div>
        )}
      </div>
    </div>
  );
};

export default KnowledgeGraphVisualization;
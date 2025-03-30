import React, { useEffect, useRef, useState, useCallback } from 'react';
import { GraphData, GraphNode, GraphLink } from '../hooks/useKnowledgeGraph';
import { createForceGraph } from '../utils/forceGraphUtils';
import * as THREE from 'three';
import '../styles/KnowledgeGraphVisualization.css';

interface InvestigationGraphVisualizationProps {
  investigationId: string;
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
 * Component for visualizing a specific investigation graph using 3D force graph
 */
const InvestigationGraphVisualization: React.FC<InvestigationGraphVisualizationProps> = ({
  investigationId,
  onNodeSelected,
  isLoading,
  darkMode = false
}) => {
  const graphContainerRef = useRef<HTMLDivElement>(null);
  const graphInstanceRef = useRef<any>(null);
  const [showControls, setShowControls] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  const [graphData, setGraphData] = useState<GraphData>({ nodes: [], links: [] });
  const [physicsSettings, setPhysicsSettings] = useState<PhysicsSettings>({
    gravity: -0.1,
    linkStrength: 1.5,
    linkDistance: 100,
    chargeStrength: -60
  });
  
  // Add filter states for node types
  const [showSources, setShowSources] = useState<boolean>(true);
  const [showSinks, setShowSinks] = useState<boolean>(true);
  const [showDataFlowPaths, setShowDataFlowPaths] = useState<boolean>(true);
  const [showMethods, setShowMethods] = useState<boolean>(true);
  const [highlightFunnel, setHighlightFunnel] = useState<boolean>(true);
  
  // Track data loading state separately from prop 
  const [isDataLoading, setIsDataLoading] = useState<boolean>(false);
  
  // Fetch investigation graph data
  useEffect(() => {
    if (!investigationId) return;
    
    setIsDataLoading(true);
    setError(null);
    
    // Fetch graph data from the API
    console.log(`Fetching graph data for investigation: ${investigationId}`);
    fetch(`/api/investigations/${investigationId}/visualization`)
      .then(async response => {
        if (!response.ok) {
          // Try to get detailed error message from response
          let errorMessage = `Error ${response.status}: ${response.statusText}`;
          try {
            const errorData = await response.json();
            console.error('Error response data:', errorData);
            if (errorData && errorData.error) {
              errorMessage = errorData.error;
            }
          } catch (e) {
            console.error('Failed to parse error response:', e);
          }
          throw new Error(errorMessage);
        }
        return response.json();
      })
      .then(data => {
        console.log('Graph data received:', data);
        
        // Debug log for node types
        console.log('Node types before processing:');
        const typesBeforeProcessing = {};
        data.nodes.forEach((node: any) => {
          typesBeforeProcessing[node.type] = (typesBeforeProcessing[node.type] || 0) + 1;
        });
        console.table(typesBeforeProcessing);
        
        // Transform the nodes to ensure they have the needed properties
        const processedData = {
          nodes: data.nodes.map((node: any) => ({
            id: node.id,
            name: node.label || node.id,
            // Convert node type to lowercase for consistent handling
            type: (node.type || 'unknown').toLowerCase(),
            group: node.group || 1,
            properties: node.properties || {},
            is_funnel_identified: node.is_funnel_identified || false,
            color: node.color
          })),
          links: data.links.map((link: any) => ({
            source: link.source,
            target: link.target,
            type: link.type,
            value: link.value || 1
          }))
        };
        
        setGraphData(processedData);
        setIsDataLoading(false);
      })
      .catch(err => {
        console.error('Error fetching investigation graph:', err);
        setError(`Failed to load investigation graph: ${err.message}`);
        setIsDataLoading(false);
        
        // Create a minimal default graph if there's an error
        const defaultGraph = {
          nodes: [
            {
              id: investigationId,
              name: `Investigation ${investigationId}`,
              type: 'investigation',
              group: 1,
              properties: {},
              color: '#4b76e8'
            }
          ],
          links: []
        };
        
        setGraphData(defaultGraph);
      });
  }, [investigationId]);
  
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
  // Function to filter nodes based on filter settings
  const getFilteredGraphData = useCallback(() => {
    // Start with all nodes
    let filteredNodes = [...graphData.nodes];
    
    // Debug log filtered nodes
    console.log('Filtering nodes. Initial count:', filteredNodes.length);
    console.log('Node types before filtering:', filteredNodes.map(n => n.type));
    
    // Apply filters
    if (!showSources) {
      filteredNodes = filteredNodes.filter(node => node.type !== 'source');
    }
    
    if (!showSinks) {
      filteredNodes = filteredNodes.filter(node => node.type !== 'sink');
    }
    
    if (!showDataFlowPaths) {
      // Handle both capitalized and lowercase data flow path types
      filteredNodes = filteredNodes.filter(node => 
        node.type !== 'dataflowpath' && 
        node.type !== 'dataFlowPath' &&
        node.type !== 'DataFlowPath'
      );
    }
    
    if (!showMethods) {
      filteredNodes = filteredNodes.filter(node => node.type !== 'method');
    }
    
    console.log('Node count after filtering:', filteredNodes.length);
    
    // Get IDs of remaining nodes
    const nodeIds = new Set(filteredNodes.map(node => node.id));
    
    // Filter links where both source and target exist in filtered nodes
    const filteredLinks = graphData.links.filter(link => {
      const sourceId = typeof link.source === 'object' ? link.source.id : link.source;
      const targetId = typeof link.target === 'object' ? link.target.id : link.target;
      return nodeIds.has(sourceId) && nodeIds.has(targetId);
    });
    
    return { nodes: filteredNodes, links: filteredLinks };
  }, [graphData, showSources, showSinks, showDataFlowPaths, showMethods]);
  
  useEffect(() => {
    if (!graphContainerRef.current || isLoading || isDataLoading) return;
    
    // Dynamic import to ensure 3d-force-graph only loads in browser environment
    import('3d-force-graph').then((ForceGraph3D) => {
      // Clear previous instance if it exists
      if (graphInstanceRef.current) {
        graphContainerRef.current?.querySelector('canvas')?.remove();
      }
      
      if (graphData.nodes.length === 0) {
        return;
      }
      
      // Get filtered data based on current filter settings
      const filteredData = getFilteredGraphData();
      
      // Node sizing based on connections
      const nodeDegrees: Record<string, number> = {};
      filteredData.links.forEach((link: GraphLink) => {
        const sourceId = typeof link.source === 'object' ? link.source.id : link.source;
        const targetId = typeof link.target === 'object' ? link.target.id : link.target;
        
        nodeDegrees[sourceId] = (nodeDegrees[sourceId] || 0) + 1;
        nodeDegrees[targetId] = (nodeDegrees[targetId] || 0) + 1;
      });
      
      // Initialize new graph
      // Create the ForceGraph3D instance
      const graph = createForceGraph(graphContainerRef.current as HTMLElement)
        .graphData(filteredData)
        .backgroundColor(darkMode ? '#1a1a1a' : '#ffffff')
        .nodeLabel((node: GraphNode) => `${node.name} (${node.type})`)
        .nodeColor((node: GraphNode) => {
          // Color nodes based on type (with debug log)
          console.log(`Coloring node type: "${node.type}"`);
          
          // Normalize type to lowercase for consistent switch matching
          const nodeType = (node.type || 'unknown').toLowerCase();
          
          switch (nodeType) {
            case 'investigation': return 'rgba(75, 118, 232, 0.8)';  // #4b76e8
            case 'repository': return 'rgba(102, 16, 242, 0.8)';     // #6610f2
            case 'finding': return 'rgba(249, 65, 68, 0.8)';         // #f94144
            case 'vulnerability': return 'rgba(155, 89, 182, 0.8)';  // #9b59b6
            case 'file': return 'rgba(32, 201, 151, 0.8)';           // #20c997
            case 'source': return 'rgba(2, 204, 250, 0.8)';          // #02ccfa
            case 'sink': return 'rgba(250, 118, 2, 0.8)';            // #fa7602
            case 'dataflowpath': return 'rgba(250, 2, 144, 0.8)';    // #fa0290
            case 'method': return 'rgba(147, 112, 219, 0.8)';        // #9370db
            default: 
              console.log(`Unrecognized node type: "${nodeType}"`);
              return 'rgba(158, 158, 158, 0.8)';  // gray
          }
        })
        // Special effect for funnel-identified nodes
        .nodeThreeObject((node: GraphNode) => {
          if (highlightFunnel && node.is_funnel_identified) {
            // Create a glowing effect for funnel-identified nodes
            const sprite = new THREE.Sprite(
              new THREE.SpriteMaterial({
                map: new THREE.TextureLoader().load('/glow.png'),
                color: 0xFFD700, // Gold color
                transparent: true,
                blending: THREE.AdditiveBlending
              })
            );
            sprite.scale.set(12, 12, 1);
            return sprite;
          }
          // Use default rendering for non-funnel nodes
          return false;
        })
        .nodeRelSize(6)
        .nodeVal((node: GraphNode) => {
          // Size nodes based on their connections (degree) and type
          const degree = nodeDegrees[node.id] || 1;
          
          // Make certain nodes larger by default
          let multiplier = 1;
          if (node.type === 'investigation') multiplier = 2;
          if (node.type === 'repository') multiplier = 1.5;
          
          return Math.max(1, Math.sqrt(degree)) * multiplier;
        })
        .linkLabel((link: GraphLink) => link.type || 'related')
        .linkColor((link: GraphLink) => {
          // Different colors for different relationship types
          switch (link.type) {
            case 'HAS_FINDING': return darkMode ? 'rgba(231, 76, 60, 0.6)' : 'rgba(231, 76, 60, 0.6)';
            case 'IDENTIFIES': return darkMode ? 'rgba(155, 89, 182, 0.6)' : 'rgba(155, 89, 182, 0.6)';
            case 'FOUND_IN': return darkMode ? 'rgba(243, 156, 18, 0.6)' : 'rgba(243, 156, 18, 0.6)';
            case 'ANALYZES': return darkMode ? 'rgba(46, 204, 113, 0.6)' : 'rgba(46, 204, 113, 0.6)';
            default: return darkMode ? 'rgba(255, 255, 255, 0.2)' : 'rgba(0, 0, 0, 0.2)';
          }
        })
        .linkWidth((link: GraphLink) => link.value || 1)
        .linkDirectionalParticles(2)
        .linkDirectionalParticleWidth((link: GraphLink) => link.value || 1)
        .linkDirectionalParticleSpeed(0.005)
        .linkDirectionalArrowLength(3.5)
        .linkDirectionalArrowRelPos(1)
        .onNodeClick((node: GraphNode) => {
          // When a node is clicked, call the callback
          onNodeSelected(node as GraphNode);
          
          // Focus on the selected node if it has position coordinates
          if (node.x !== undefined && node.y !== undefined && node.z !== undefined) {
            // Safety check for centerAt method
            if (typeof graph.centerAt === 'function') {
              graph.centerAt(node.x, node.y, node.z, 1000);
            }
            
            // Safety check for zoom method
            if (typeof graph.zoom === 'function') {
              graph.zoom(1.5, 1000);
            }
          }
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
  }, [graphData, onNodeSelected, isLoading, isDataLoading, darkMode, physicsSettings, 
     showSources, showSinks, showDataFlowPaths, showMethods, highlightFunnel, getFilteredGraphData]);
  
  return (
    <div className="knowledge-graph-visualization" ref={graphContainerRef}>
      {isLoading && (
        <div className="loading-overlay">
          <div className="loading-spinner"></div>
          <p>Loading Investigation Graph...</p>
        </div>
      )}
      
      {!isLoading && error && (
        <div className="error-overlay">
          <div className="error-message">
            <h3>Error Loading Graph</h3>
            <p>{error}</p>
            {error.includes("pattern") && (
              <p className="error-hint">
                The investigation ID format is invalid. Investigation IDs can be in several formats:
                <br/>
                - UUID format: 123e4567-e89b-12d3-a456-426614174000
                <br/>
                - Short format: inv-c4e062ca
                <br/>
                - Custom format: inv-ai-samples-8d357166
              </p>
            )}
          </div>
        </div>
      )}
      {!isLoading && graphData.nodes.length === 0 && (
        <div className="empty-graph">
          <p>No graph data available for this investigation.</p>
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
            
            <h3>Filter Nodes</h3>
            <div className="control-group">
              <label>
                <input
                  type="checkbox"
                  checked={highlightFunnel}
                  onChange={(e) => {
                    setHighlightFunnel(e.target.checked);
                    if (graphInstanceRef.current) {
                      // Force redraw of nodes when changing highlight setting
                      graphInstanceRef.current.refresh();
                    }
                  }}
                />
                Highlight Funnel Identified Nodes
              </label>
            </div>
            <div className="control-group">
              <label>
                <input
                  type="checkbox"
                  checked={showSources}
                  onChange={(e) => {
                    setShowSources(e.target.checked);
                    if (graphInstanceRef.current) {
                      graphInstanceRef.current.refresh();
                    }
                  }}
                />
                Show Sources
              </label>
            </div>
            <div className="control-group">
              <label>
                <input
                  type="checkbox"
                  checked={showSinks}
                  onChange={(e) => {
                    setShowSinks(e.target.checked);
                    if (graphInstanceRef.current) {
                      graphInstanceRef.current.refresh();
                    }
                  }}
                />
                Show Sinks
              </label>
            </div>
            <div className="control-group">
              <label>
                <input
                  type="checkbox"
                  checked={showDataFlowPaths}
                  onChange={(e) => {
                    setShowDataFlowPaths(e.target.checked);
                    if (graphInstanceRef.current) {
                      graphInstanceRef.current.refresh();
                    }
                  }}
                />
                Show Data Flow Paths
              </label>
            </div>
            <div className="control-group">
              <label>
                <input
                  type="checkbox"
                  checked={showMethods}
                  onChange={(e) => {
                    setShowMethods(e.target.checked);
                    if (graphInstanceRef.current) {
                      graphInstanceRef.current.refresh();
                    }
                  }}
                />
                Show Methods
              </label>
            </div>
            
            <h3>Legend</h3>
            <div className="graph-legend">
              <div className="legend-item">
                <span className="legend-color investigation"></span>
                <span className="legend-label">Investigation</span>
              </div>
              <div className="legend-item">
                <span className="legend-color repository"></span>
                <span className="legend-label">Repository</span>
              </div>
              <div className="legend-item">
                <span className="legend-color finding"></span>
                <span className="legend-label">Finding</span>
              </div>
              <div className="legend-item">
                <span className="legend-color vulnerability"></span>
                <span className="legend-label">Vulnerability</span>
              </div>
              <div className="legend-item">
                <span className="legend-color file"></span>
                <span className="legend-label">File</span>
              </div>
              <div className="legend-item">
                <span className="legend-color source"></span>
                <span className="legend-label">Source</span>
              </div>
              <div className="legend-item">
                <span className="legend-color sink"></span>
                <span className="legend-label">Sink</span>
              </div>
              <div className="legend-item">
                <span className="legend-color dataFlowPath"></span>
                <span className="legend-label">Data Flow Path</span>
              </div>
              <div className="legend-item">
                <span className="legend-color method"></span>
                <span className="legend-label">Method</span>
              </div>
              
              {highlightFunnel && (
                <div className="funnel-section">
                  <h4>Funnel Identified Nodes</h4>
                  <p className="legend-hint">Funnel identified nodes have a gold glow</p>
                </div>
              )}
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

export default InvestigationGraphVisualization;
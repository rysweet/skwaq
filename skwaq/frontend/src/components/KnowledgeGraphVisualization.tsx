import React, { useEffect, useRef } from 'react';
import { GraphData, GraphNode } from '../hooks/useKnowledgeGraph';
import '../styles/KnowledgeGraphVisualization.css';

interface KnowledgeGraphVisualizationProps {
  graphData: GraphData;
  onNodeSelected: (node: GraphNode) => void;
  isLoading: boolean;
}

/**
 * Component for visualizing the knowledge graph using 3D force graph
 */
const KnowledgeGraphVisualization: React.FC<KnowledgeGraphVisualizationProps> = ({
  graphData,
  onNodeSelected,
  isLoading
}) => {
  const graphContainerRef = useRef<HTMLDivElement>(null);
  const graphInstanceRef = useRef<any>(null);
  
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
      
      // Initialize new graph
      const Graph = ForceGraph3D.default;
      const graph = Graph()(graphContainerRef.current as HTMLElement)
        .graphData(graphData)
        .nodeLabel('name')
        .nodeColor((node: any) => {
          // Color nodes based on type
          switch (node.type) {
            case 'vulnerability': return 'rgba(244, 67, 54, 0.8)';
            case 'cwe': return 'rgba(33, 150, 243, 0.8)';
            case 'concept': return 'rgba(76, 175, 80, 0.8)';
            default: return 'rgba(158, 158, 158, 0.8)';
          }
        })
        .nodeRelSize(6)
        .linkDirectionalParticles(2)
        .linkDirectionalParticleWidth(2)
        .linkLabel('type')
        .onNodeClick((node: any) => {
          // When a node is clicked, call the callback
          onNodeSelected(node as GraphNode);
          
          // Focus on the selected node
          graph.centerAt(node.x, node.y, node.z, 1000);
          graph.zoom(1.5, 1000);
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
  }, [graphData, onNodeSelected, isLoading]);
  
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
    </div>
  );
};

export default KnowledgeGraphVisualization;
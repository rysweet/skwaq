import { useState, useEffect, useCallback, useRef } from 'react';
import apiService from '../services/api';
import ForceGraph3D from '3d-force-graph';

export interface GraphData {
  nodes: GraphNode[];
  links: GraphLink[];
}

export interface GraphNode {
  id: string;
  name: string;
  type: string;
  group: number;
  properties?: Record<string, any>;
}

export interface GraphLink {
  source: string;
  target: string;
  type: string;
}

export interface GraphFilter {
  nodeTypes?: string[];
  relationshipTypes?: string[];
  searchTerm?: string;
}

/**
 * Custom hook for handling the knowledge graph visualization
 */
const useKnowledgeGraph = () => {
  const [graphData, setGraphData] = useState<GraphData>({ nodes: [], links: [] });
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const [selectedNode, setSelectedNode] = useState<GraphNode | null>(null);
  const graphRef = useRef<any>(null);
  
  /**
   * Fetch graph data from the API
   */
  const fetchGraphData = useCallback(async (filters?: GraphFilter) => {
    try {
      setLoading(true);
      setError(null);
      
      const queryParams = new URLSearchParams();
      if (filters?.nodeTypes?.length) {
        queryParams.append('nodeTypes', filters.nodeTypes.join(','));
      }
      if (filters?.relationshipTypes?.length) {
        queryParams.append('relationshipTypes', filters.relationshipTypes.join(','));
      }
      if (filters?.searchTerm) {
        queryParams.append('searchTerm', filters.searchTerm);
      }
      
      const url = `/knowledge-graph${queryParams.toString() ? `?${queryParams.toString()}` : ''}`;
      const data = await apiService.get<GraphData>(url);
      setGraphData(data);
    } catch (err) {
      setError('Failed to fetch graph data');
      console.error('Error fetching graph data:', err);
    } finally {
      setLoading(false);
    }
  }, []);
  
  /**
   * Initialize the 3D force graph
   */
  const initGraph = useCallback((containerElement: HTMLElement) => {
    if (!containerElement) return;
    
    // Initialize the graph
    const ForceGraph = ForceGraph3D.default;
    const graph = ForceGraph()(containerElement)
      .graphData(graphData)
      .nodeLabel('name')
      .nodeColor((node: GraphNode) => {
        // Color nodes based on type
        switch (node.type) {
          case 'vulnerability': return 'rgba(244, 67, 54, 0.8)';
          case 'cwe': return 'rgba(33, 150, 243, 0.8)';
          case 'concept': return 'rgba(76, 175, 80, 0.8)';
          default: return 'rgba(158, 158, 158, 0.8)';
        }
      })
      .linkDirectionalParticles(2)
      .linkDirectionalParticleWidth(2)
      .onNodeClick((node: GraphNode) => {
        // When a node is clicked, set it as selected
        setSelectedNode(node as GraphNode);
      });
    
    // Save graph instance to ref
    graphRef.current = graph;
    
    return () => {
      // Clean up
      if (containerElement) {
        containerElement.innerHTML = '';
      }
    };
  }, [graphData]);
  
  /**
   * Update the graph with new data
   */
  const updateGraph = useCallback(() => {
    if (graphRef.current) {
      graphRef.current.graphData(graphData);
    }
  }, [graphData]);
  
  // Update graph when data changes
  useEffect(() => {
    updateGraph();
  }, [graphData, updateGraph]);
  
  return {
    graphData,
    loading,
    error,
    selectedNode,
    fetchGraphData,
    initGraph,
    setSelectedNode
  };
};

export default useKnowledgeGraph;
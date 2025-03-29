import { useState, useEffect, useCallback } from 'react';
import { GraphData, GraphNode } from './useKnowledgeGraph';

/**
 * Custom hook for handling investigation graph data
 * 
 * @param investigationId The ID of the investigation to visualize
 */
const useInvestigationGraph = (investigationId?: string) => {
  const [graphData, setGraphData] = useState<GraphData>({ nodes: [], links: [] });
  const [loading, setLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  const [selectedNode, setSelectedNode] = useState<GraphNode | null>(null);
  
  /**
   * Fetch graph data for a specific investigation
   */
  const fetchInvestigationGraph = useCallback(async (id: string) => {
    try {
      setLoading(true);
      setError(null);
      
      console.log(`[useInvestigationGraph] Using minimal graph for ID: ${id}`);
      
      // Create a minimal default graph
      const defaultGraph = {
        nodes: [
          {
            id: id,
            name: `Investigation ${id}`,
            type: 'investigation',
            properties: {}
          }
        ],
        links: []
      };
      
      setGraphData(defaultGraph);
    } catch (err) {
      console.error('[useInvestigationGraph] Error setting graph data:', err);
      setError(`Failed to create graph: ${err instanceof Error ? err.message : 'Unknown error'}`);
    } finally {
      setLoading(false);
    }
  }, []);
  
  /**
   * Fetch graph data when investigationId changes
   */
  useEffect(() => {
    if (investigationId) {
      fetchInvestigationGraph(investigationId);
    }
  }, [investigationId, fetchInvestigationGraph]);
  
  return {
    graphData,
    loading,
    error,
    selectedNode,
    setSelectedNode,
    fetchInvestigationGraph
  };
};

export default useInvestigationGraph;
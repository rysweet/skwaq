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
      
      console.log(`[useInvestigationGraph] Fetching graph for ID: ${id}`);
      const response = await fetch(`/api/investigations/${id}/visualization`);
      
      if (!response.ok) {
        let errorMessage = `Error: ${response.status} ${response.statusText}`;
        try {
          const errorData = await response.json();
          console.error('[useInvestigationGraph] Error response:', errorData);
          if (errorData && errorData.error) {
            errorMessage = errorData.error;
          }
        } catch (e) {
          console.error('[useInvestigationGraph] Failed to parse error response');
        }
        throw new Error(errorMessage);
      }
      
      const data = await response.json();
      console.log(`[useInvestigationGraph] Received graph data with ${data.nodes?.length || 0} nodes and ${data.links?.length || 0} links`);
      
      // Transform data if needed to match the expected format
      const transformedData: GraphData = {
        nodes: data.nodes.map((node: any) => ({
          id: node.id,
          name: node.label || node.id,
          // Always convert node type to lowercase for consistent filtering
          type: (node.type || 'unknown').toLowerCase(),
          properties: node.properties || {},
          is_funnel_identified: node.is_funnel_identified || false,
          color: node.color
        })),
        links: data.links.map((link: any) => ({
          source: typeof link.source === 'object' ? link.source.id : link.source,
          target: typeof link.target === 'object' ? link.target.id : link.target,
          type: link.type,
          value: link.value || 1,
          properties: link.properties || {}
        }))
      };
      
      setGraphData(transformedData);
    } catch (err) {
      console.error('[useInvestigationGraph] Error fetching investigation graph:', err);
      setError(`Failed to load investigation graph: ${err instanceof Error ? err.message : 'Unknown error'}`);
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
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
      
      // Check content type and handle non-JSON responses
      const contentType = response.headers.get('content-type');
      let data;
      
      if (contentType && contentType.includes('application/json')) {
        data = await response.json();
      } else {
        // Handle text response if not properly formatted as JSON
        const text = await response.text();
        
        // If it starts with < it's likely HTML
        if (text.trim().startsWith('<')) {
          console.error('[useInvestigationGraph] Server returned HTML instead of JSON:', text.substring(0, 200));
          throw new Error('Server returned HTML instead of JSON. This usually indicates a server-side error. Check server logs for details.');
        }
        
        try {
          // Try to parse as JSON anyway
          data = JSON.parse(text);
        } catch (e: unknown) {
          console.error('[useInvestigationGraph] Failed to parse response as JSON:', e);
          console.log('[useInvestigationGraph] Raw response starts with:', text.substring(0, 100));
          const errorMessage = e instanceof Error ? e.message : 'Unknown parsing error';
          throw new Error(`Invalid JSON response from server: ${errorMessage}`);
        }
      }
      
      console.log(`[useInvestigationGraph] Received graph data with ${data.nodes?.length || 0} nodes and ${data.links?.length || 0} links`);
      
      // Validate that data has the expected structure
      if (!data || !Array.isArray(data.nodes) || !Array.isArray(data.links)) {
        console.error('[useInvestigationGraph] Invalid data structure:', data);
        throw new Error('Invalid data structure received from server. Missing nodes or links arrays.');
      }
      
      // Transform data if needed to match the expected format
      const transformedData: GraphData = {
        nodes: data.nodes.map((node: any) => {
          // Ensure node has an ID
          if (!node.id) {
            console.warn('[useInvestigationGraph] Node missing ID:', node);
          }
          
          return {
            // Ensure ID is a string
            id: String(node.id || ''),
            name: node.label || String(node.id || ''),
            // Always convert node type to lowercase for consistent filtering
            type: (node.type || 'unknown').toLowerCase(),
            properties: node.properties || {},
            is_funnel_identified: Boolean(node.is_funnel_identified),
            color: node.color || '#cccccc'
          };
        }),
        links: data.links.map((link: any) => {
          // Get source ID, ensuring it's a string
          const sourceId = typeof link.source === 'object' 
            ? String(link.source?.id || '')
            : String(link.source || '');
            
          // Get target ID, ensuring it's a string
          const targetId = typeof link.target === 'object'
            ? String(link.target?.id || '')
            : String(link.target || '');
            
          return {
            source: sourceId,
            target: targetId,
            type: link.type || 'related',
            value: Number(link.value) || 1,
            properties: link.properties || {}
          };
        })
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
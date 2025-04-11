import React, { useState, useEffect, useCallback } from 'react';
import workflowService, {
  AvailableWorkflow,
  WorkflowStatus,
  WorkflowResult,
  WorkflowParameters,
  AvailableTool
} from '../services/workflowService';
// We're using our own event system instead of the hook
// import { useRealTimeEvents } from './useRealTimeEvents';

export default function useWorkflows() {
  const [availableWorkflows, setAvailableWorkflows] = useState<AvailableWorkflow[]>([]);
  const [availableTools, setAvailableTools] = useState<AvailableTool[]>([]);
  const [activeWorkflows, setActiveWorkflows] = useState<WorkflowStatus[]>([]);
  const [workflowHistory, setWorkflowHistory] = useState<WorkflowStatus[]>([]);
  const [workflowResults, setWorkflowResults] = useState<Record<string, WorkflowResult[]>>({});
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  
  // Function to subscribe to workflow events
  // Using useMemo to wrap the subscription management to avoid dependency issues
  const subscriptionManager = React.useMemo(() => ({
    subscriptions: {} as Record<string, {channel: string, callback: any}>
  }), []);
  
  const subscribe = useCallback((channel: string, callback: any) => {
    // Create a unique subscription ID
    const subscriptionId = `${channel}-${Date.now()}`;
    
    // Store subscription info in our managed object
    subscriptionManager.subscriptions[subscriptionId] = {
      channel,
      callback
    };
    
    // Return an object with unsubscribe method
    return {
      unsubscribe: () => {
        // Clean up the subscription from our manager
        delete subscriptionManager.subscriptions[subscriptionId];
        console.log(`Unsubscribing from ${channel}`);
      }
    };
  }, [subscriptionManager]);

  // Fetch available workflows
  const fetchAvailableWorkflows = useCallback(async () => {
    try {
      const workflows = await workflowService.getAvailableWorkflows();
      setAvailableWorkflows(workflows);
    } catch (err) {
      setError('Failed to load available workflows');
      console.error('Error fetching available workflows:', err);
    }
  }, []);

  // Fetch available tools
  const fetchAvailableTools = useCallback(async () => {
    try {
      const tools = await workflowService.getAvailableTools();
      setAvailableTools(tools);
    } catch (err) {
      setError('Failed to load available tools');
      console.error('Error fetching available tools:', err);
    }
  }, []);

  // Fetch active workflows
  const fetchActiveWorkflows = useCallback(async () => {
    try {
      const workflows = await workflowService.getActiveWorkflows();
      setActiveWorkflows(workflows);
    } catch (err) {
      setError('Failed to load active workflows');
      console.error('Error fetching active workflows:', err);
    }
  }, []);

  // Fetch workflow history
  const fetchWorkflowHistory = useCallback(async (limit: number = 10, offset: number = 0) => {
    try {
      const history = await workflowService.getWorkflowHistory(limit, offset);
      setWorkflowHistory(history);
    } catch (err) {
      setError('Failed to load workflow history');
      console.error('Error fetching workflow history:', err);
    }
  }, []);

  // Fetch results for a specific workflow
  const fetchWorkflowResults = useCallback(async (workflowId: string) => {
    try {
      const results = await workflowService.getWorkflowResults(workflowId);
      setWorkflowResults(prev => ({
        ...prev,
        [workflowId]: results
      }));
      return results;
    } catch (err) {
      setError(`Failed to load results for workflow ${workflowId}`);
      console.error(`Error fetching results for workflow ${workflowId}:`, err);
      return [];
    }
  }, []);

  // Start a new workflow
  const startWorkflow = useCallback(async (workflowId: string, parameters: WorkflowParameters) => {
    try {
      const id = await workflowService.startWorkflow(workflowId, parameters);
      await fetchActiveWorkflows();
      return id;
    } catch (err) {
      setError('Failed to start workflow');
      console.error('Error starting workflow:', err);
      throw err;
    }
  }, [fetchActiveWorkflows]);

  // Stop a running workflow
  const stopWorkflow = useCallback(async (workflowId: string) => {
    try {
      await workflowService.stopWorkflow(workflowId);
      await fetchActiveWorkflows();
    } catch (err) {
      setError(`Failed to stop workflow ${workflowId}`);
      console.error(`Error stopping workflow ${workflowId}:`, err);
      throw err;
    }
  }, [fetchActiveWorkflows]);

  // Invoke a specific tool
  const invokeTool = useCallback(async (toolId: string, parameters: Record<string, any>) => {
    try {
      const executionId = await workflowService.invokeTool(toolId, parameters);
      return executionId;
    } catch (err) {
      setError(`Failed to invoke tool ${toolId}`);
      console.error(`Error invoking tool ${toolId}:`, err);
      throw err;
    }
  }, []);

  // Get tool execution results
  const getToolResults = useCallback(async (executionId: string) => {
    try {
      const results = await workflowService.getToolResults(executionId);
      return results;
    } catch (err) {
      setError(`Failed to get results for tool execution ${executionId}`);
      console.error(`Error getting tool execution results ${executionId}:`, err);
      throw err;
    }
  }, []);

  // Update workflow status in real-time from events
  const handleWorkflowStatusUpdate = useCallback((data: any) => {
    if (data.type === 'workflow_status_update') {
      setActiveWorkflows(prev => {
        const updated = [...prev];
        const index = updated.findIndex(w => w.id === data.workflow_id);
        
        if (index >= 0) {
          updated[index] = {
            ...updated[index],
            status: data.status,
            progress: data.progress,
            updated_at: new Date().toISOString()
          };
        } else if (data.status === 'running' || data.status === 'pending') {
          updated.push({
            id: data.workflow_id,
            name: data.workflow_name || 'Unknown Workflow',
            status: data.status,
            progress: data.progress,
            started_at: new Date().toISOString(),
            updated_at: new Date().toISOString()
          });
        }
        
        return updated;
      });
      
      // If workflow completed or failed, refresh history
      if (data.status === 'completed' || data.status === 'failed') {
        fetchWorkflowHistory();
      }
    }
  }, [fetchWorkflowHistory]);

  // Handle workflow result updates
  const handleWorkflowResultUpdate = useCallback((data: any) => {
    if (data.type === 'workflow_result_update') {
      setWorkflowResults(prev => {
        const current = prev[data.workflow_id] || [];
        return {
          ...prev,
          [data.workflow_id]: [...current, {
            workflow_id: data.workflow_id,
            step_name: data.step_name,
            status: data.status,
            progress: data.progress,
            data: data.data,
            errors: data.errors
          }]
        };
      });
    }
  }, []);

  // Initial data loading
  useEffect(() => {
    setIsLoading(true);
    Promise.all([
      fetchAvailableWorkflows(),
      fetchAvailableTools(),
      fetchActiveWorkflows(),
      fetchWorkflowHistory()
    ])
      .then(() => setIsLoading(false))
      .catch(err => {
        setError('Failed to load workflow data');
        console.error('Error loading workflow data:', err);
        setIsLoading(false);
      });
  }, [fetchAvailableWorkflows, fetchAvailableTools, fetchActiveWorkflows, fetchWorkflowHistory]);

  // Subscribe to real-time events
  useEffect(() => {
    const statusSubscription = subscribe('workflow_status', handleWorkflowStatusUpdate);
    const resultSubscription = subscribe('workflow_result', handleWorkflowResultUpdate);
    
    return () => {
      statusSubscription.unsubscribe();
      resultSubscription.unsubscribe();
    };
  }, [subscribe, handleWorkflowStatusUpdate, handleWorkflowResultUpdate]);

  // Periodic refresh of active workflows
  useEffect(() => {
    const intervalId = setInterval(() => {
      if (activeWorkflows.length > 0) {
        fetchActiveWorkflows();
      }
    }, 30000); // Refresh every 30 seconds
    
    return () => clearInterval(intervalId);
  }, [fetchActiveWorkflows, activeWorkflows.length]);

  return {
    availableWorkflows,
    availableTools,
    activeWorkflows,
    workflowHistory,
    workflowResults,
    isLoading,
    error,
    startWorkflow,
    stopWorkflow,
    fetchWorkflowResults,
    invokeTool,
    getToolResults,
    refreshActiveWorkflows: fetchActiveWorkflows,
    refreshWorkflowHistory: fetchWorkflowHistory
  };
}
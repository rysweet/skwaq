import api from './api';

export interface WorkflowParameters {
  repository_id?: string;
  focus_areas?: string[];
  workflow_id?: string;
  enable_persistence?: boolean;
  repository_path?: string;
  [key: string]: any;
}

export interface WorkflowStatus {
  id: string;
  name: string;
  status: 'pending' | 'running' | 'completed' | 'failed';
  progress: number;
  started_at: string;
  updated_at: string;
  completed_at?: string;
  error?: string;
}

export interface WorkflowResult {
  workflow_id: string;
  step_name?: string;
  status: string;
  progress: number;
  data: any;
  errors?: string[];
}

export interface AvailableWorkflow {
  id: string;
  name: string;
  description: string;
  parameters: {
    name: string;
    type: string;
    required: boolean;
    description: string;
    default?: any;
  }[];
}

export interface AvailableTool {
  id: string;
  name: string;
  description: string;
  parameters: {
    name: string;
    type: string;
    required: boolean;
    description: string;
  }[];
}

const workflowService = {
  /**
   * Get all available workflows
   */
  getAvailableWorkflows: async (): Promise<AvailableWorkflow[]> => {
    return await api.get('/workflows');
  },
  
  /**
   * Get all available tools for the tool invocation workflow
   */
  getAvailableTools: async (): Promise<AvailableTool[]> => {
    return await api.get('/workflows/tools');
  },
  
  /**
   * Start a workflow with the given parameters
   */
  startWorkflow: async (workflowId: string, parameters: WorkflowParameters): Promise<string> => {
    const response = await api.post(`/workflows/${workflowId}/start`, parameters);
    return response.workflow_id;
  },
  
  /**
   * Get the status of a workflow
   */
  getWorkflowStatus: async (workflowId: string): Promise<WorkflowStatus> => {
    return await api.get(`/workflows/${workflowId}/status`);
  },
  
  /**
   * Get the results of a workflow
   */
  getWorkflowResults: async (workflowId: string): Promise<WorkflowResult[]> => {
    return await api.get(`/workflows/${workflowId}/results`);
  },
  
  /**
   * Stop a running workflow
   */
  stopWorkflow: async (workflowId: string): Promise<void> => {
    await api.post(`/workflows/${workflowId}/stop`);
  },
  
  /**
   * Get all active workflows
   */
  getActiveWorkflows: async (): Promise<WorkflowStatus[]> => {
    return await api.get('/workflows/active');
  },
  
  /**
   * Get workflow history
   */
  getWorkflowHistory: async (limit: number = 10, offset: number = 0): Promise<WorkflowStatus[]> => {
    return await api.get(`/workflows/history?limit=${limit}&offset=${offset}`);
  },
  
  /**
   * Invoke a specific tool
   */
  invokeTool: async (toolId: string, parameters: Record<string, any>): Promise<string> => {
    const response = await api.post(`/workflows/tools/${toolId}/invoke`, parameters);
    return response.execution_id;
  },
  
  /**
   * Get tool execution results
   */
  getToolResults: async (executionId: string): Promise<any> => {
    return await api.get(`/workflows/tools/executions/${executionId}`);
  }
};

export default workflowService;
import React from 'react';
import { WorkflowStatus as WorkflowStatusType } from '../services/workflowService';
import '../styles/WorkflowStatus.css';

interface WorkflowStatusProps {
  workflows: WorkflowStatusType[];
  isLoading: boolean;
  onViewResults: (workflowId: string) => void;
  onStopWorkflow: (workflowId: string) => Promise<void>;
}

const formatTime = (dateString: string) => {
  const date = new Date(dateString);
  return date.toLocaleString();
};

const calculateDuration = (startDate: string, endDate?: string) => {
  const start = new Date(startDate).getTime();
  const end = endDate ? new Date(endDate).getTime() : Date.now();
  const durationMs = end - start;
  
  // Format duration as mm:ss or hh:mm:ss
  const seconds = Math.floor((durationMs / 1000) % 60);
  const minutes = Math.floor((durationMs / (1000 * 60)) % 60);
  const hours = Math.floor(durationMs / (1000 * 60 * 60));
  
  if (hours > 0) {
    return `${hours.toString().padStart(2, '0')}:${minutes.toString().padStart(2, '0')}:${seconds.toString().padStart(2, '0')}`;
  }
  
  return `${minutes.toString().padStart(2, '0')}:${seconds.toString().padStart(2, '0')}`;
};

const WorkflowStatus: React.FC<WorkflowStatusProps> = ({
  workflows,
  isLoading,
  onViewResults,
  onStopWorkflow
}) => {
  const activeWorkflows = workflows.filter(w => w.status === 'pending' || w.status === 'running');
  const completedWorkflows = workflows.filter(w => w.status === 'completed' || w.status === 'failed');
  
  const renderWorkflowItem = (workflow: WorkflowStatusType) => {
    const isActive = workflow.status === 'pending' || workflow.status === 'running';
    const isFailed = workflow.status === 'failed';
    
    return (
      <div 
        key={workflow.id} 
        className={`workflow-item ${workflow.status}`}
      >
        <div className="workflow-info">
          <h3>{workflow.name}</h3>
          <div className="workflow-details">
            <span className="workflow-id">ID: {workflow.id}</span>
            <span className="workflow-started">Started: {formatTime(workflow.started_at)}</span>
            {workflow.completed_at && (
              <span className="workflow-completed">Completed: {formatTime(workflow.completed_at)}</span>
            )}
            <span className="workflow-duration">
              Duration: {calculateDuration(workflow.started_at, workflow.completed_at)}
            </span>
          </div>
        </div>
        
        <div className="workflow-status-info">
          <div className="status-badge">
            <span className={`status-indicator ${workflow.status}`}></span>
            <span className="status-text">{workflow.status}</span>
          </div>
          {isActive && (
            <div className="progress-container">
              <div className="progress-bar">
                <div className="progress-fill" style={{ width: `${workflow.progress}%` }}></div>
              </div>
              <span className="progress-text">{workflow.progress}%</span>
            </div>
          )}
          {isFailed && workflow.error && (
            <div className="workflow-error">
              <span className="error-label">Error:</span>
              <span className="error-message">{workflow.error}</span>
            </div>
          )}
        </div>
        
        <div className="workflow-actions">
          {isActive && (
            <button 
              className="stop-button"
              onClick={() => onStopWorkflow(workflow.id)}
            >
              Stop
            </button>
          )}
          {(workflow.status === 'completed' || workflow.status === 'failed') && (
            <button 
              className="view-results-button"
              onClick={() => onViewResults(workflow.id)}
            >
              View Results
            </button>
          )}
        </div>
      </div>
    );
  };
  
  return (
    <div className="workflow-status">
      <h2>Workflows Status</h2>
      
      {isLoading ? (
        <p className="loading-message">Loading workflows...</p>
      ) : (
        <>
          {activeWorkflows.length > 0 && (
            <div className="active-workflows">
              <h3>Active Workflows</h3>
              {activeWorkflows.map(renderWorkflowItem)}
            </div>
          )}
          
          {completedWorkflows.length > 0 && (
            <div className="completed-workflows">
              <h3>Recent Workflows</h3>
              {completedWorkflows.map(renderWorkflowItem)}
            </div>
          )}
          
          {activeWorkflows.length === 0 && completedWorkflows.length === 0 && (
            <p className="no-workflows-message">No workflows found.</p>
          )}
        </>
      )}
    </div>
  );
};

export default WorkflowStatus;
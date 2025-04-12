import React, { useState, useCallback } from 'react';
import { saveAs } from 'file-saver';
import WorkflowLauncher from '../components/WorkflowLauncher';
import WorkflowStatus from '../components/WorkflowStatus';
import WorkflowResults from '../components/WorkflowResults';
import ToolInvocation from '../components/ToolInvocation';
import useWorkflows from '../hooks/useWorkflows';
import '../styles/Workflows.css';

const Workflows: React.FC = () => {
  const {
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
    refreshActiveWorkflows,
    refreshWorkflowHistory
  } = useWorkflows();
  
  const [selectedWorkflowId, setSelectedWorkflowId] = useState<string | null>(null);
  const [isLoadingResults, setIsLoadingResults] = useState(false);
  const [viewMode, setViewMode] = useState<'launcher' | 'status' | 'tools'>('launcher');
  
  // Handler for starting a new workflow
  const handleLaunchWorkflow = useCallback(async (workflowId: string, parameters: any) => {
    try {
      const id = await startWorkflow(workflowId, parameters);
      setViewMode('status');
      return id;
    } catch (err) {
      console.error('Error launching workflow:', err);
      throw err;
    }
  }, [startWorkflow]);
  
  // Handler for stopping a workflow
  const handleStopWorkflow = useCallback(async (workflowId: string) => {
    try {
      await stopWorkflow(workflowId);
    } catch (err) {
      console.error('Error stopping workflow:', err);
      throw err;
    }
  }, [stopWorkflow]);
  
  // Handler for viewing workflow results
  const handleViewResults = useCallback(async (workflowId: string) => {
    setSelectedWorkflowId(workflowId);
    setIsLoadingResults(true);
    
    try {
      await fetchWorkflowResults(workflowId);
    } catch (err) {
      console.error('Error fetching workflow results:', err);
    } finally {
      setIsLoadingResults(false);
    }
  }, [fetchWorkflowResults]);
  
  // Handler for closing results view
  const handleCloseResults = useCallback(() => {
    setSelectedWorkflowId(null);
  }, []);
  
  // Handler for invoking a tool
  const handleInvokeTool = useCallback(async (toolId: string, parameters: Record<string, any>) => {
    try {
      const executionId = await invokeTool(toolId, parameters);
      setViewMode('status');
      return executionId;
    } catch (err) {
      console.error('Error invoking tool:', err);
      throw err;
    }
  }, [invokeTool]);
  
  // Handler for exporting results
  const handleExportResults = useCallback((format: 'json' | 'csv' | 'markdown') => {
    if (!selectedWorkflowId || !workflowResults[selectedWorkflowId]) return;
    
    const results = workflowResults[selectedWorkflowId];
    let content: string;
    let filename: string;
    let mimeType: string;
    
    switch (format) {
      case 'json':
        content = JSON.stringify(results, null, 2);
        filename = `workflow-${selectedWorkflowId}-results.json`;
        mimeType = 'application/json';
        break;
      case 'csv':
        // Create CSV header based on first result's data structure
        const headers = ['workflow_id', 'step_name', 'status', 'progress'];
        if (results.length > 0 && results[0].data) {
          if (typeof results[0].data === 'object') {
            Object.keys(results[0].data).forEach(key => {
              headers.push(`data.${key}`);
            });
          } else {
            headers.push('data');
          }
        }
        
        // Create CSV rows
        const rows = results.map(result => {
          const row: Record<string, any> = {
            workflow_id: result.workflow_id,
            step_name: result.step_name || '',
            status: result.status,
            progress: result.progress
          };
          
          if (typeof result.data === 'object' && result.data !== null) {
            Object.entries(result.data).forEach(([key, value]) => {
              row[`data.${key}`] = typeof value === 'object' ? JSON.stringify(value) : value;
            });
          } else {
            row['data'] = result.data;
          }
          
          return row;
        });
        
        // Convert to CSV
        const csvContent = [
          headers.join(','),
          ...rows.map(row => headers.map(header => {
            const value = row[header];
            if (value === null || value === undefined) return '';
            if (typeof value === 'string') return `"${value.replace(/"/g, '""')}"`;
            return value;
          }).join(','))
        ].join('\n');
        
        content = csvContent;
        filename = `workflow-${selectedWorkflowId}-results.csv`;
        mimeType = 'text/csv;charset=utf-8';
        break;
      case 'markdown':
        // Create a markdown report
        const mdContent = [
          `# Workflow Results: ${selectedWorkflowId}`,
          `Generated on ${new Date().toLocaleString()}`,
          '',
          '## Results Summary',
          `- Total results: ${results.length}`,
          `- Status: ${results[results.length - 1]?.status || 'Unknown'}`,
          '',
          '## Detailed Results',
          '',
          ...results.map((result, index) => {
            const lines = [
              `### Result ${index + 1}${result.step_name ? `: ${result.step_name}` : ''}`,
              `- Status: ${result.status}`,
              `- Progress: ${result.progress}%`,
              '',
              '#### Data',
              '```json',
              JSON.stringify(result.data, null, 2),
              '```',
              ''
            ];
            
            if (result.errors && result.errors.length > 0) {
              lines.push('#### Errors');
              result.errors.forEach(error => {
                lines.push(`- ${error}`);
              });
              lines.push('');
            }
            
            return lines.join('\n');
          })
        ].join('\n');
        
        content = mdContent;
        filename = `workflow-${selectedWorkflowId}-results.md`;
        mimeType = 'text/markdown;charset=utf-8';
        break;
      default:
        return;
    }
    
    const blob = new Blob([content], { type: mimeType });
    saveAs(blob, filename);
  }, [selectedWorkflowId, workflowResults]);
  
  // Refresh data periodically
  React.useEffect(() => {
    const intervalId = setInterval(() => {
      refreshActiveWorkflows();
      refreshWorkflowHistory();
    }, 30000); // Refresh every 30 seconds
    
    return () => clearInterval(intervalId);
  }, [refreshActiveWorkflows, refreshWorkflowHistory]);
  
  return (
    <div className="workflows-page">
      <div className="workflows-header">
        <h1>Workflow Management</h1>
        {error && <div className="error-banner">{error}</div>}
        <div className="view-selector">
          <button
            className={viewMode === 'launcher' ? 'view-button active' : 'view-button'}
            onClick={() => setViewMode('launcher')}
          >
            Launch Workflows
          </button>
          <button
            className={viewMode === 'status' ? 'view-button active' : 'view-button'}
            onClick={() => setViewMode('status')}
          >
            Workflow Status
          </button>
          <button
            className={viewMode === 'tools' ? 'view-button active' : 'view-button'}
            onClick={() => setViewMode('tools')}
          >
            Security Tools
          </button>
        </div>
      </div>
      
      <div className="workflows-content">
        {viewMode === 'launcher' && (
          <WorkflowLauncher
            availableWorkflows={availableWorkflows}
            isLoading={isLoading}
            onLaunchWorkflow={handleLaunchWorkflow}
          />
        )}
        
        {viewMode === 'status' && (
          <WorkflowStatus
            workflows={[...activeWorkflows, ...workflowHistory]}
            isLoading={isLoading}
            onViewResults={handleViewResults}
            onStopWorkflow={handleStopWorkflow}
          />
        )}
        
        {viewMode === 'tools' && (
          <ToolInvocation
            availableTools={availableTools}
            isLoading={isLoading}
            onInvokeTool={handleInvokeTool}
          />
        )}
      </div>
      
      {selectedWorkflowId && (
        <div className="workflow-results-overlay">
          <div className="workflow-results-container">
            <WorkflowResults
              workflowId={selectedWorkflowId}
              results={workflowResults[selectedWorkflowId] || []}
              isLoading={isLoadingResults}
              onClose={handleCloseResults}
              onExport={handleExportResults}
            />
          </div>
        </div>
      )}
    </div>
  );
};

export default Workflows;
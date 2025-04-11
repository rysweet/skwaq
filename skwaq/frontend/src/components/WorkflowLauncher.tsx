import React, { useState } from 'react';
import { AvailableWorkflow, WorkflowParameters } from '../services/workflowService';
import '../styles/WorkflowLauncher.css';

interface WorkflowParameterInputProps {
  parameter: AvailableWorkflow['parameters'][0];
  value: any;
  onChange: (name: string, value: any) => void;
}

const WorkflowParameterInput: React.FC<WorkflowParameterInputProps> = ({ parameter, value, onChange }) => {
  switch (parameter.type) {
    case 'string':
      return (
        <input
          type="text"
          value={value || ''}
          onChange={(e) => onChange(parameter.name, e.target.value)}
          placeholder={parameter.description}
          required={parameter.required}
          className="workflow-parameter-input"
        />
      );
    case 'number':
      return (
        <input
          type="number"
          value={value || ''}
          onChange={(e) => onChange(parameter.name, e.target.value ? Number(e.target.value) : null)}
          placeholder={parameter.description}
          required={parameter.required}
          className="workflow-parameter-input"
        />
      );
    case 'boolean':
      return (
        <input
          type="checkbox"
          checked={value || false}
          onChange={(e) => onChange(parameter.name, e.target.checked)}
          className="workflow-parameter-checkbox"
        />
      );
    case 'array':
      return (
        <input
          type="text"
          value={Array.isArray(value) ? value.join(', ') : ''}
          onChange={(e) => onChange(parameter.name, e.target.value.split(',').map(item => item.trim()))}
          placeholder={`${parameter.description} (comma-separated)`}
          required={parameter.required}
          className="workflow-parameter-input"
        />
      );
    default:
      return (
        <input
          type="text"
          value={value || ''}
          onChange={(e) => onChange(parameter.name, e.target.value)}
          placeholder={parameter.description}
          required={parameter.required}
          className="workflow-parameter-input"
        />
      );
  }
};

interface WorkflowLauncherProps {
  availableWorkflows: AvailableWorkflow[];
  isLoading: boolean;
  onLaunchWorkflow: (workflowId: string, parameters: WorkflowParameters) => Promise<string | void>;
}

const WorkflowLauncher: React.FC<WorkflowLauncherProps> = ({
  availableWorkflows,
  isLoading,
  onLaunchWorkflow
}) => {
  const [selectedWorkflowId, setSelectedWorkflowId] = useState<string>('');
  const [parameters, setParameters] = useState<WorkflowParameters>({});
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const selectedWorkflow = availableWorkflows.find(w => w.id === selectedWorkflowId);

  const handleParameterChange = (name: string, value: any) => {
    setParameters(prev => ({
      ...prev,
      [name]: value
    }));
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedWorkflow) return;

    try {
      setIsSubmitting(true);
      setError(null);
      await onLaunchWorkflow(selectedWorkflowId, parameters);
      // Reset form after successful launch
      setParameters({});
    } catch (err) {
      console.error('Error launching workflow:', err);
      setError('Failed to launch workflow. Please try again.');
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div className="workflow-launcher">
      <h2>Launch Workflow</h2>
      {isLoading ? (
        <p>Loading available workflows...</p>
      ) : (
        <form onSubmit={handleSubmit}>
          <div className="form-group">
            <label htmlFor="workflow-select">Select Workflow</label>
            <select
              id="workflow-select"
              value={selectedWorkflowId}
              onChange={(e) => {
                setSelectedWorkflowId(e.target.value);
                setParameters({});  // Reset parameters when workflow changes
              }}
              required
              disabled={isSubmitting}
              className="workflow-select"
            >
              <option value="">-- Select a workflow --</option>
              {availableWorkflows.map(workflow => (
                <option key={workflow.id} value={workflow.id}>
                  {workflow.name}
                </option>
              ))}
            </select>
          </div>

          {selectedWorkflow && (
            <>
              <div className="workflow-description">
                <p>{selectedWorkflow.description}</p>
              </div>

              <div className="workflow-parameters">
                <h3>Parameters</h3>
                {selectedWorkflow.parameters.map(param => (
                  <div key={param.name} className="form-group">
                    <label htmlFor={`param-${param.name}`}>
                      {param.name}
                      {param.required && <span className="required">*</span>}
                    </label>
                    <div className="parameter-input-container">
                      <WorkflowParameterInput
                        parameter={param}
                        value={parameters[param.name] ?? param.default}
                        onChange={handleParameterChange}
                      />
                    </div>
                    <p className="parameter-description">{param.description}</p>
                  </div>
                ))}
              </div>
            </>
          )}

          {error && <div className="error-message">{error}</div>}

          <div className="form-actions">
            <button
              type="submit"
              disabled={!selectedWorkflowId || isSubmitting}
              className="launch-button"
            >
              {isSubmitting ? 'Launching...' : 'Launch Workflow'}
            </button>
          </div>
        </form>
      )}
    </div>
  );
};

export default WorkflowLauncher;
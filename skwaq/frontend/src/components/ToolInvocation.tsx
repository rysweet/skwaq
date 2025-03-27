import React, { useState, useEffect } from 'react';
import { AvailableTool } from '../services/workflowService';
import '../styles/ToolInvocation.css';

interface ToolInvocationProps {
  availableTools: AvailableTool[];
  isLoading: boolean;
  onInvokeTool: (toolId: string, parameters: Record<string, any>) => Promise<void>;
}

const ToolInvocation: React.FC<ToolInvocationProps> = ({
  availableTools,
  isLoading,
  onInvokeTool
}) => {
  const [selectedToolId, setSelectedToolId] = useState<string>('');
  const [parameters, setParameters] = useState<Record<string, any>>({});
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  
  const selectedTool = availableTools.find(t => t.id === selectedToolId);
  
  // Reset parameters when tool changes
  useEffect(() => {
    setParameters({});
  }, [selectedToolId]);
  
  const handleParameterChange = (name: string, value: any) => {
    setParameters(prev => ({
      ...prev,
      [name]: value
    }));
  };
  
  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedTool) return;
    
    try {
      setIsSubmitting(true);
      setError(null);
      await onInvokeTool(selectedToolId, parameters);
      setParameters({});
    } catch (err) {
      console.error('Error invoking tool:', err);
      setError('Failed to invoke tool. Please try again.');
    } finally {
      setIsSubmitting(false);
    }
  };
  
  return (
    <div className="tool-invocation">
      <h2>Security Tools</h2>
      {isLoading ? (
        <p className="loading-message">Loading available tools...</p>
      ) : (
        <form onSubmit={handleSubmit}>
          <div className="form-group">
            <label htmlFor="tool-select">Select Tool</label>
            <select
              id="tool-select"
              value={selectedToolId}
              onChange={(e) => setSelectedToolId(e.target.value)}
              required
              disabled={isSubmitting}
              className="tool-select"
            >
              <option value="">-- Select a security tool --</option>
              {availableTools.map(tool => (
                <option key={tool.id} value={tool.id}>
                  {tool.name}
                </option>
              ))}
            </select>
          </div>
          
          {selectedTool && (
            <>
              <div className="tool-description">
                <p>{selectedTool.description}</p>
              </div>
              
              <div className="tool-parameters">
                <h3>Parameters</h3>
                {selectedTool.parameters.map(param => (
                  <div key={param.name} className="form-group">
                    <label htmlFor={`param-${param.name}`}>
                      {param.name}
                      {param.required && <span className="required">*</span>}
                    </label>
                    <div className="parameter-input-container">
                      {param.type === 'boolean' ? (
                        <input
                          type="checkbox"
                          id={`param-${param.name}`}
                          checked={parameters[param.name] || false}
                          onChange={(e) => handleParameterChange(param.name, e.target.checked)}
                          className="parameter-checkbox"
                        />
                      ) : (
                        <input
                          type={param.type === 'number' ? 'number' : 'text'}
                          id={`param-${param.name}`}
                          value={parameters[param.name] || ''}
                          onChange={(e) => {
                            const value = param.type === 'number' 
                              ? (e.target.value ? Number(e.target.value) : null)
                              : e.target.value;
                            handleParameterChange(param.name, value);
                          }}
                          placeholder={param.description}
                          required={param.required}
                          className="parameter-input"
                        />
                      )}
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
              disabled={!selectedToolId || isSubmitting}
              className="invoke-button"
            >
              {isSubmitting ? 'Running...' : 'Run Tool'}
            </button>
          </div>
        </form>
      )}
    </div>
  );
};

export default ToolInvocation;
import React, { useState } from 'react';
import { WorkflowResult } from '../services/workflowService';
import '../styles/WorkflowResults.css';

interface WorkflowResultsProps {
  workflowId?: string;
  results: WorkflowResult[];
  isLoading: boolean;
  onClose: () => void;
  onExport: (format: 'json' | 'csv' | 'markdown') => void;
}

const WorkflowResults: React.FC<WorkflowResultsProps> = ({
  workflowId,
  results,
  isLoading,
  onClose,
  onExport
}) => {
  const [activeStep, setActiveStep] = useState<string | null>(null);
  
  if (!workflowId) {
    return null;
  }
  
  const steps = Array.from(new Set(results.map(r => r.step_name || 'Default'))).sort();
  
  const renderResultData = (data: any, depth: number = 0): React.ReactNode => {
    if (data === null || data === undefined) {
      return <span className="result-null">null</span>;
    }
    
    if (typeof data === 'string') {
      // Check if it's a markdown content
      if (data.includes('# ') || data.includes('\n## ') || data.includes('```')) {
        return (
          <div className="markdown-content" dangerouslySetInnerHTML={{ __html: data }} />
        );
      }
      return <span className="result-string">{data}</span>;
    }
    
    if (typeof data === 'number' || typeof data === 'boolean') {
      return <span className="result-primitive">{String(data)}</span>;
    }
    
    if (Array.isArray(data)) {
      if (data.length === 0) {
        return <span className="result-array-empty">[]</span>;
      }
      
      return (
        <div className="result-array" style={{ marginLeft: `${depth * 20}px` }}>
          {data.map((item, index) => (
            <div key={index} className="result-array-item">
              <span className="result-array-index">[{index}]:</span>
              {renderResultData(item, depth + 1)}
            </div>
          ))}
        </div>
      );
    }
    
    if (typeof data === 'object') {
      const entries = Object.entries(data);
      if (entries.length === 0) {
        return <span className="result-object-empty">{'{}'}</span>;
      }
      
      return (
        <div className="result-object" style={{ marginLeft: `${depth * 20}px` }}>
          {entries.map(([key, value]) => (
            <div key={key} className="result-object-property">
              <span className="result-object-key">{key}:</span>
              {renderResultData(value, depth + 1)}
            </div>
          ))}
        </div>
      );
    }
    
    return <span>{String(data)}</span>;
  };
  
  const filteredResults = activeStep 
    ? results.filter(r => (r.step_name || 'Default') === activeStep)
    : results;
  
  return (
    <div className="workflow-results">
      <div className="results-header">
        <h2>Results for Workflow {workflowId}</h2>
        <div className="results-actions">
          <div className="export-buttons">
            <button onClick={() => onExport('json')} className="export-button json">
              Export JSON
            </button>
            <button onClick={() => onExport('csv')} className="export-button csv">
              Export CSV
            </button>
            <button onClick={() => onExport('markdown')} className="export-button markdown">
              Export Markdown
            </button>
          </div>
          <button onClick={onClose} className="close-button">
            Close
          </button>
        </div>
      </div>
      
      {isLoading ? (
        <div className="loading-container">
          <p>Loading results...</p>
        </div>
      ) : (
        <>
          {steps.length > 1 && (
            <div className="results-steps">
              <button 
                className={!activeStep ? 'step-button active' : 'step-button'}
                onClick={() => setActiveStep(null)}
              >
                All Steps
              </button>
              {steps.map(step => (
                <button
                  key={step}
                  className={activeStep === step ? 'step-button active' : 'step-button'}
                  onClick={() => setActiveStep(step)}
                >
                  {step}
                </button>
              ))}
            </div>
          )}
          
          {filteredResults.length === 0 ? (
            <div className="no-results">
              <p>No results found for this workflow.</p>
            </div>
          ) : (
            <div className="results-content">
              {filteredResults.map((result, index) => (
                <div key={index} className="result-item">
                  {result.step_name && (
                    <div className="result-step">{result.step_name}</div>
                  )}
                  <div className="result-status">
                    <span className={`status-indicator ${result.status}`}></span>
                    <span className="status-text">{result.status}</span>
                    {result.progress < 100 && (
                      <div className="progress-container small">
                        <div className="progress-bar">
                          <div className="progress-fill" style={{ width: `${result.progress}%` }}></div>
                        </div>
                        <span className="progress-text">{result.progress}%</span>
                      </div>
                    )}
                  </div>
                  
                  <div className="result-data">
                    {renderResultData(result.data)}
                  </div>
                  
                  {result.errors && result.errors.length > 0 && (
                    <div className="result-errors">
                      <h4>Errors:</h4>
                      <ul>
                        {result.errors.map((error, idx) => (
                          <li key={idx} className="error-message">{error}</li>
                        ))}
                      </ul>
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}
        </>
      )}
    </div>
  );
};

export default WorkflowResults;
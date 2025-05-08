import React, { useState, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import InvestigationGraphVisualization from '../components/InvestigationGraphVisualization';
import useInvestigationGraph from '../hooks/useInvestigationGraph';
// GraphNode import commented out as it's not used
// import { GraphNode } from '../hooks/useKnowledgeGraph';
import '../styles/InvestigationVisualization.css';

interface InvestigationVisualizationProps {
  darkMode?: boolean;
}

/**
 * Page for visualizing a specific investigation graph
 */
const InvestigationVisualization: React.FC<InvestigationVisualizationProps> = ({ 
  darkMode = false 
}) => {
  const { investigationId } = useParams<{ investigationId: string }>();
  const navigate = useNavigate();
  const [investigationTitle, setInvestigationTitle] = useState<string>('Investigation');
  const [showASTNodes, setShowASTNodes] = useState<boolean>(false);
  const [showCodeSummaries, setShowCodeSummaries] = useState<boolean>(false);
  
  const {
    loading,
    // Error variable is declared but not used
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    error,
    selectedNode,
    setSelectedNode,
    fetchInvestigationGraph
  } = useInvestigationGraph(investigationId, { 
    showASTNodes,
    showCodeSummaries
  });
  
  // Refresh graph data when visualization options change
  useEffect(() => {
    if (investigationId) {
      fetchInvestigationGraph(investigationId);
    }
  }, [showASTNodes, showCodeSummaries, fetchInvestigationGraph, investigationId]);
  
  // Fetch investigation details (title, etc.) when ID changes
  useEffect(() => {
    if (!investigationId) return;
    
    // Fetch investigation details
    fetch(`/api/investigations/${investigationId}`)
      .then(response => {
        if (!response.ok) {
          throw new Error(`Error: ${response.status} ${response.statusText}`);
        }
        return response.json();
      })
      .then(data => {
        console.log('Investigation details:', data);
        setInvestigationTitle(data.title || data.name || `Investigation ${investigationId}`);
      })
      .catch(err => {
        console.error('Error fetching investigation details:', err);
      });
  }, [investigationId]);
  
  // If no investigation ID is provided, show a message or redirect
  if (!investigationId) {
    return (
      <div className="no-investigation">
        <h2>No Investigation Selected</h2>
        <p>Please select an investigation to visualize.</p>
        <button 
          className="primary-button" 
          onClick={() => navigate('/investigations')}
        >
          View Investigations
        </button>
      </div>
    );
  }
  
  // Render node details panel
  const renderNodeDetails = () => {
    if (!selectedNode) {
      return (
        <div className="empty-details">
          <p>Click on a graph node to see details here.</p>
        </div>
      );
    }
    
    return (
      <div className="node-details">
        <h3>{selectedNode.name}</h3>
        <div className="detail-row">
          <span className="detail-label">Type:</span>
          <span className={`detail-value node-type-${selectedNode.type.toLowerCase()}`}>{selectedNode.type}</span>
        </div>
        <div className="detail-row">
          <span className="detail-label">ID:</span>
          <span className="detail-value">{selectedNode.id}</span>
        </div>
        
        {/* Show code summary prominently if available */}
        {selectedNode.properties?.summary && (
          <div className="summary-section">
            <h4>Summary</h4>
            <div className="summary-content">
              {selectedNode.properties.summary}
            </div>
          </div>
        )}
        
        {/* Show code section if available */}
        {selectedNode.properties?.code && (
          <div className="code-section">
            <h4>Code</h4>
            <pre className="code-content">
              {selectedNode.properties.code}
            </pre>
          </div>
        )}
        
        {/* Other properties, excluding code and summary which are shown above */}
        {selectedNode.properties && Object.entries(selectedNode.properties)
          .filter(([key]) => key !== 'code' && key !== 'summary')
          .map(([key, value]) => (
            <div key={key} className="detail-row">
              <span className="detail-label">{key}:</span>
              <span className="detail-value">
                {typeof value === 'object' ? JSON.stringify(value) : String(value)}
              </span>
            </div>
          ))}
        
        <div className="detail-actions">
          {selectedNode.type === 'file' && selectedNode.properties?.path && (
            <button 
              className="detail-action"
              onClick={() => navigate(`/code/${investigationId}?path=${encodeURIComponent(String(selectedNode.properties?.path))}`)}
            >
              View File
            </button>
          )}
          {selectedNode.type === 'finding' && (
            <button 
              className="detail-action"
              onClick={() => navigate(`/findings/${selectedNode.id}`)}
            >
              View Finding Details
            </button>
          )}
          <button className="detail-action secondary" onClick={() => setSelectedNode(null)}>
            Close
          </button>
        </div>
      </div>
    );
  };
  
  return (
    <div className={`investigation-visualization-page ${darkMode ? 'dark' : ''}`}>
      <div className="investigation-visualization-header">
        <div className="header-left">
          <button 
            className="back-button" 
            onClick={() => navigate('/investigations')}
            aria-label="Back to investigations"
          >
            &larr;
          </button>
          <h1 className="page-title">{investigationTitle}</h1>
          <span className="investigation-id">ID: {investigationId}</span>
        </div>
        <div className="header-right">
          <div className="visualization-options">
            <label className="option-toggle">
              <input
                type="checkbox"
                checked={showASTNodes}
                onChange={(e) => setShowASTNodes(e.target.checked)}
              />
              Show AST Nodes
            </label>
            <label className="option-toggle">
              <input
                type="checkbox"
                checked={showCodeSummaries}
                onChange={(e) => setShowCodeSummaries(e.target.checked)}
              />
              Show Code Summaries
            </label>
          </div>
          <button 
            className="report-button"
            onClick={() => navigate(`/investigations/${investigationId}/report`)}
          >
            View Report
          </button>
        </div>
      </div>
      
      <div className="investigation-visualization-content">
        <div className="graph-visualization-container">
          <InvestigationGraphVisualization
            investigationId={investigationId}
            onNodeSelected={setSelectedNode}
            isLoading={loading}
            darkMode={darkMode}
            showASTNodes={showASTNodes}
            showCodeSummaries={showCodeSummaries}
          />
        </div>
        
        <div className="details-panel">
          {renderNodeDetails()}
        </div>
      </div>
    </div>
  );
};

export default InvestigationVisualization;
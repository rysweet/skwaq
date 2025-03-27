import React, { useEffect, useRef, useState } from 'react';
import '../styles/KnowledgeGraph.css';

// This is a placeholder implementation since we'll integrate the actual 3d-force-graph later
const KnowledgeGraph: React.FC = () => {
  const graphContainerRef = useRef<HTMLDivElement>(null);
  const [isLoading, setIsLoading] = useState(true);

  // Mock data for demonstration purposes
  const mockGraphData = {
    nodes: [
      { id: 'n1', name: 'SQL Injection', type: 'vulnerability', group: 1 },
      { id: 'n2', name: 'Cross-Site Scripting', type: 'vulnerability', group: 1 },
      { id: 'n3', name: 'CWE-89', type: 'cwe', group: 2 },
      { id: 'n4', name: 'CWE-79', type: 'cwe', group: 2 },
      { id: 'n5', name: 'Input Validation', type: 'concept', group: 3 },
      { id: 'n6', name: 'Database Security', type: 'concept', group: 3 },
    ],
    links: [
      { source: 'n1', target: 'n3', type: 'is_a' },
      { source: 'n2', target: 'n4', type: 'is_a' },
      { source: 'n1', target: 'n5', type: 'related_to' },
      { source: 'n1', target: 'n6', type: 'related_to' },
      { source: 'n2', target: 'n5', type: 'related_to' },
    ]
  };

  useEffect(() => {
    // Simulate loading the graph data
    const timer = setTimeout(() => {
      setIsLoading(false);
    }, 1500);

    return () => clearTimeout(timer);
  }, []);

  return (
    <div className="knowledge-graph-container">
      <div className="graph-header">
        <h1 className="page-title">Knowledge Graph</h1>
        <div className="graph-controls">
          <button className="control-button">
            <span className="button-icon">🔍</span>
            <span>Zoom</span>
          </button>
          <button className="control-button">
            <span className="button-icon">🔄</span>
            <span>Reset</span>
          </button>
          <button className="control-button">
            <span className="button-icon">⬇️</span>
            <span>Export</span>
          </button>
          <select className="filter-select">
            <option value="all">All Node Types</option>
            <option value="vulnerability">Vulnerabilities</option>
            <option value="cwe">CWEs</option>
            <option value="concept">Concepts</option>
          </select>
        </div>
      </div>

      <div className="graph-container" ref={graphContainerRef}>
        {isLoading ? (
          <div className="loading-state">
            <div className="loading-spinner"></div>
            <p>Loading Knowledge Graph...</p>
          </div>
        ) : (
          <div className="graph-placeholder">
            <p className="placeholder-text">3D Force Graph will be integrated here</p>
            <div className="graph-stats">
              <p>Nodes: {mockGraphData.nodes.length}</p>
              <p>Links: {mockGraphData.links.length}</p>
            </div>
            <div className="nodes-preview">
              {mockGraphData.nodes.map(node => (
                <div key={node.id} className={`node-preview node-${node.type}`}>
                  <span className="node-name">{node.name}</span>
                  <span className="node-type">{node.type}</span>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>

      <div className="graph-details-panel">
        <h3>Node Details</h3>
        <p className="details-help">Click on a graph node to see details here.</p>
      </div>
    </div>
  );
};

export default KnowledgeGraph;
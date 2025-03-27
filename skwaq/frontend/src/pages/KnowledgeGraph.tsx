import React, { useEffect, useState, useCallback } from 'react';
import KnowledgeGraphVisualization from '../components/KnowledgeGraphVisualization';
import GraphFilter, { SavedFilter } from '../components/GraphFilter';
import useKnowledgeGraph, { GraphNode, GraphFilter as FilterConfig } from '../hooks/useKnowledgeGraph';
import '../styles/KnowledgeGraph.css';

interface KnowledgeGraphProps {
  darkMode?: boolean;
}

const KnowledgeGraph: React.FC<KnowledgeGraphProps> = ({ darkMode = false }) => {
  const { 
    graphData, 
    loading, 
    error, 
    selectedNode, 
    fetchGraphData, 
    setSelectedNode 
  } = useKnowledgeGraph();
  
  const [savedFilters, setSavedFilters] = useState<SavedFilter[]>([]);
  const [showFilterPanel, setShowFilterPanel] = useState<boolean>(true);
  const [exportFormat, setExportFormat] = useState<string>('json');
  const [showExportOptions, setShowExportOptions] = useState<boolean>(false);

  // Available node and relationship types (in a real implementation, these would come from the API)
  const availableNodeTypes = ['vulnerability', 'cwe', 'concept', 'repository', 'file', 'function', 'class'];
  const availableRelationshipTypes = ['is_a', 'contains', 'related_to', 'implements', 'extends', 'calls', 'references'];

  // Fetch graph data on component mount
  useEffect(() => {
    fetchGraphData();
    
    // Load saved filters from localStorage
    const storedFilters = localStorage.getItem('knowledgeGraphFilters');
    if (storedFilters) {
      try {
        setSavedFilters(JSON.parse(storedFilters));
      } catch (err) {
        console.error('Error loading saved filters:', err);
      }
    }
  }, [fetchGraphData]);

  // Handle filter changes
  const handleFilterChange = useCallback((filters: FilterConfig) => {
    fetchGraphData(filters);
  }, [fetchGraphData]);

  // Save filter to localStorage
  const handleSaveFilter = useCallback((filter: SavedFilter) => {
    setSavedFilters(prev => {
      const newFilters = [...prev, filter];
      // Save to localStorage
      localStorage.setItem('knowledgeGraphFilters', JSON.stringify(newFilters));
      return newFilters;
    });
  }, []);

  // Export graph data
  const handleExport = useCallback(() => {
    if (exportFormat === 'json') {
      // Export as JSON
      const dataStr = JSON.stringify(graphData, null, 2);
      const dataUri = `data:application/json;charset=utf-8,${encodeURIComponent(dataStr)}`;
      const filename = `knowledge-graph-export-${new Date().toISOString().slice(0, 10)}.json`;
      
      // Create a download link and trigger it
      const link = document.createElement('a');
      link.setAttribute('href', dataUri);
      link.setAttribute('download', filename);
      link.click();
    } else if (exportFormat === 'csv') {
      // Export nodes as CSV
      const nodesHeader = 'id,name,type,group\n';
      const nodesData = graphData.nodes.map(node => 
        `${node.id},${node.name},${node.type},${node.group}`
      ).join('\n');
      
      // Export links as CSV
      const linksHeader = 'source,target,type\n';
      const linksData = graphData.links.map(link => 
        `${typeof link.source === 'object' ? link.source.id : link.source},` +
        `${typeof link.target === 'object' ? link.target.id : link.target},` +
        `${link.type}`
      ).join('\n');
      
      // Create node CSV file
      const nodesUri = `data:text/csv;charset=utf-8,${encodeURIComponent(nodesHeader + nodesData)}`;
      const nodesFilename = `knowledge-graph-nodes-${new Date().toISOString().slice(0, 10)}.csv`;
      
      // Create links CSV file
      const linksUri = `data:text/csv;charset=utf-8,${encodeURIComponent(linksHeader + linksData)}`;
      const linksFilename = `knowledge-graph-links-${new Date().toISOString().slice(0, 10)}.csv`;
      
      // Download both files
      const nodesLink = document.createElement('a');
      nodesLink.setAttribute('href', nodesUri);
      nodesLink.setAttribute('download', nodesFilename);
      nodesLink.click();
      
      setTimeout(() => {
        const linksLink = document.createElement('a');
        linksLink.setAttribute('href', linksUri);
        linksLink.setAttribute('download', linksFilename);
        linksLink.click();
      }, 100);
    }
    
    setShowExportOptions(false);
  }, [graphData, exportFormat]);

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
          <span className={`detail-value node-type-${selectedNode.type}`}>{selectedNode.type}</span>
        </div>
        <div className="detail-row">
          <span className="detail-label">ID:</span>
          <span className="detail-value">{selectedNode.id}</span>
        </div>
        {selectedNode.properties && Object.entries(selectedNode.properties).map(([key, value]) => (
          <div key={key} className="detail-row">
            <span className="detail-label">{key}:</span>
            <span className="detail-value">
              {typeof value === 'object' ? JSON.stringify(value) : String(value)}
            </span>
          </div>
        ))}
        
        <div className="detail-actions">
          <button className="detail-action" onClick={() => window.open(`/knowledge/${selectedNode.id}`, '_blank')}>
            View Full Details
          </button>
          <button className="detail-action secondary" onClick={() => setSelectedNode(null)}>
            Close
          </button>
        </div>
      </div>
    );
  };

  return (
    <div className={`knowledge-graph-page ${darkMode ? 'dark' : ''}`}>
      <div className="knowledge-graph-header">
        <h1 className="page-title">Knowledge Graph</h1>
        <div className="header-actions">
          <button 
            className="action-button"
            onClick={() => setShowFilterPanel(!showFilterPanel)}
            aria-label={showFilterPanel ? 'Hide filters' : 'Show filters'}
          >
            {showFilterPanel ? 'Hide Filters' : 'Show Filters'}
          </button>
          
          <div className="export-dropdown">
            <button 
              className="action-button"
              onClick={() => setShowExportOptions(!showExportOptions)}
              aria-label="Export graph"
            >
              Export
            </button>
            
            {showExportOptions && (
              <div className="export-options">
                <h4>Export Format</h4>
                <div className="export-format-options">
                  <label>
                    <input 
                      type="radio" 
                      name="exportFormat" 
                      value="json" 
                      checked={exportFormat === 'json'} 
                      onChange={() => setExportFormat('json')}
                    />
                    JSON
                  </label>
                  <label>
                    <input 
                      type="radio" 
                      name="exportFormat" 
                      value="csv" 
                      checked={exportFormat === 'csv'} 
                      onChange={() => setExportFormat('csv')}
                    />
                    CSV
                  </label>
                </div>
                <div className="export-actions">
                  <button 
                    className="export-button"
                    onClick={handleExport}
                    disabled={graphData.nodes.length === 0}
                  >
                    Download
                  </button>
                  <button 
                    className="cancel-button"
                    onClick={() => setShowExportOptions(false)}
                  >
                    Cancel
                  </button>
                </div>
              </div>
            )}
          </div>
        </div>
      </div>
      
      <div className="knowledge-graph-content">
        {showFilterPanel && (
          <div className="filter-panel">
            <GraphFilter
              onFilterChange={handleFilterChange}
              availableNodeTypes={availableNodeTypes}
              availableRelationshipTypes={availableRelationshipTypes}
              savedFilters={savedFilters}
              onSaveFilter={handleSaveFilter}
              darkMode={darkMode}
            />
          </div>
        )}
        
        <div className="graph-visualization-container">
          <KnowledgeGraphVisualization
            graphData={graphData}
            onNodeSelected={setSelectedNode}
            isLoading={loading}
            darkMode={darkMode}
          />
          
          {error && (
            <div className="error-message">
              <p>Error loading graph data: {error}</p>
              <button onClick={() => fetchGraphData()}>Retry</button>
            </div>
          )}
        </div>
        
        <div className="details-panel">
          {renderNodeDetails()}
        </div>
      </div>
    </div>
  );
};

export default KnowledgeGraph;
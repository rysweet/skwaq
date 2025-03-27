import React, { useState, useEffect } from 'react';
import { GraphFilter as FilterConfig } from '../hooks/useKnowledgeGraph';
import '../styles/GraphFilter.css';

interface GraphFilterProps {
  onFilterChange: (filters: FilterConfig) => void;
  availableNodeTypes: string[];
  availableRelationshipTypes: string[];
  savedFilters?: SavedFilter[];
  onSaveFilter?: (filter: SavedFilter) => void;
  darkMode?: boolean;
}

export interface SavedFilter {
  id: string;
  name: string;
  description?: string;
  config: FilterConfig;
}

/**
 * Component for filtering knowledge graph data
 */
const GraphFilter: React.FC<GraphFilterProps> = ({
  onFilterChange,
  availableNodeTypes,
  availableRelationshipTypes,
  savedFilters = [],
  onSaveFilter,
  darkMode = false
}) => {
  const [selectedNodeTypes, setSelectedNodeTypes] = useState<string[]>([]);
  const [selectedRelationshipTypes, setSelectedRelationshipTypes] = useState<string[]>([]);
  const [searchTerm, setSearchTerm] = useState<string>('');
  const [showAdvanced, setShowAdvanced] = useState<boolean>(false);
  const [minConnections, setMinConnections] = useState<number>(0);
  const [maxResults, setMaxResults] = useState<number>(100);
  const [selectedFilter, setSelectedFilter] = useState<string>('');
  const [newFilterName, setNewFilterName] = useState<string>('');
  const [newFilterDescription, setNewFilterDescription] = useState<string>('');
  const [showSaveDialog, setShowSaveDialog] = useState<boolean>(false);

  // Apply filter when filter parameters change
  useEffect(() => {
    onFilterChange({
      nodeTypes: selectedNodeTypes.length > 0 ? selectedNodeTypes : undefined,
      relationshipTypes: selectedRelationshipTypes.length > 0 ? selectedRelationshipTypes : undefined,
      searchTerm: searchTerm || undefined,
      minConnections: minConnections > 0 ? minConnections : undefined,
      maxResults: maxResults !== 100 ? maxResults : undefined
    });
  }, [selectedNodeTypes, selectedRelationshipTypes, searchTerm, minConnections, maxResults, onFilterChange]);

  // Apply saved filter when selected
  useEffect(() => {
    if (selectedFilter) {
      const filter = savedFilters.find(f => f.id === selectedFilter);
      if (filter) {
        const { nodeTypes, relationshipTypes, searchTerm: term, minConnections: min, maxResults: max } = filter.config;
        
        setSelectedNodeTypes(nodeTypes || []);
        setSelectedRelationshipTypes(relationshipTypes || []);
        setSearchTerm(term || '');
        setMinConnections(min || 0);
        setMaxResults(max || 100);
      }
    }
  }, [selectedFilter, savedFilters]);

  const handleNodeTypeChange = (nodeType: string, checked: boolean) => {
    if (checked) {
      setSelectedNodeTypes(prev => [...prev, nodeType]);
    } else {
      setSelectedNodeTypes(prev => prev.filter(type => type !== nodeType));
    }
  };

  const handleRelationshipTypeChange = (relType: string, checked: boolean) => {
    if (checked) {
      setSelectedRelationshipTypes(prev => [...prev, relType]);
    } else {
      setSelectedRelationshipTypes(prev => prev.filter(type => type !== relType));
    }
  };

  const handleSaveFilter = () => {
    if (!newFilterName.trim()) return;
    
    const newFilter: SavedFilter = {
      id: `filter-${Date.now()}`,
      name: newFilterName.trim(),
      description: newFilterDescription.trim() || undefined,
      config: {
        nodeTypes: selectedNodeTypes.length > 0 ? selectedNodeTypes : undefined,
        relationshipTypes: selectedRelationshipTypes.length > 0 ? selectedRelationshipTypes : undefined,
        searchTerm: searchTerm || undefined,
        minConnections: minConnections > 0 ? minConnections : undefined,
        maxResults: maxResults !== 100 ? maxResults : undefined
      }
    };
    
    if (onSaveFilter) {
      onSaveFilter(newFilter);
    }
    
    setNewFilterName('');
    setNewFilterDescription('');
    setShowSaveDialog(false);
    setSelectedFilter(newFilter.id);
  };

  const handleClearFilters = () => {
    setSelectedNodeTypes([]);
    setSelectedRelationshipTypes([]);
    setSearchTerm('');
    setMinConnections(0);
    setMaxResults(100);
    setSelectedFilter('');
  };

  return (
    <div className={`graph-filter ${darkMode ? 'dark' : ''}`}>
      <div className="filter-section">
        <h3>Search</h3>
        <div className="search-input-container">
          <input
            type="text"
            placeholder="Search knowledge graph..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="search-input"
          />
          {searchTerm && (
            <button 
              className="clear-search"
              onClick={() => setSearchTerm('')}
              aria-label="Clear search"
            >
              ×
            </button>
          )}
        </div>
      </div>
      
      <div className="filter-section">
        <h3>Node Types</h3>
        <div className="checkbox-list">
          {availableNodeTypes.length === 0 ? (
            <p className="no-options">No node types available</p>
          ) : (
            availableNodeTypes.map(nodeType => (
              <label key={nodeType} className="checkbox-item">
                <input
                  type="checkbox"
                  checked={selectedNodeTypes.includes(nodeType)}
                  onChange={(e) => handleNodeTypeChange(nodeType, e.target.checked)}
                />
                <span className="item-label">{nodeType}</span>
              </label>
            ))
          )}
        </div>
      </div>
      
      <div className="filter-section">
        <h3>Relationship Types</h3>
        <div className="checkbox-list">
          {availableRelationshipTypes.length === 0 ? (
            <p className="no-options">No relationship types available</p>
          ) : (
            availableRelationshipTypes.map(relType => (
              <label key={relType} className="checkbox-item">
                <input
                  type="checkbox"
                  checked={selectedRelationshipTypes.includes(relType)}
                  onChange={(e) => handleRelationshipTypeChange(relType, e.target.checked)}
                />
                <span className="item-label">{relType}</span>
              </label>
            ))
          )}
        </div>
      </div>
      
      <div className="filter-section">
        <button 
          className="toggle-advanced"
          onClick={() => setShowAdvanced(!showAdvanced)}
        >
          {showAdvanced ? 'Hide Advanced Filters' : 'Show Advanced Filters'}
        </button>
        
        {showAdvanced && (
          <div className="advanced-filters">
            <div className="filter-control">
              <label htmlFor="min-connections">Minimum Connections</label>
              <div className="slider-with-value">
                <input
                  id="min-connections"
                  type="range"
                  min="0"
                  max="10"
                  value={minConnections}
                  onChange={(e) => setMinConnections(parseInt(e.target.value))}
                />
                <span className="slider-value">{minConnections}</span>
              </div>
            </div>
            
            <div className="filter-control">
              <label htmlFor="max-results">Maximum Results</label>
              <div className="slider-with-value">
                <input
                  id="max-results"
                  type="range"
                  min="10"
                  max="500"
                  step="10"
                  value={maxResults}
                  onChange={(e) => setMaxResults(parseInt(e.target.value))}
                />
                <span className="slider-value">{maxResults}</span>
              </div>
            </div>
          </div>
        )}
      </div>
      
      {savedFilters.length > 0 && (
        <div className="filter-section">
          <h3>Saved Filters</h3>
          <select 
            value={selectedFilter}
            onChange={(e) => setSelectedFilter(e.target.value)}
            className="saved-filter-select"
          >
            <option value="">-- Select a saved filter --</option>
            {savedFilters.map(filter => (
              <option key={filter.id} value={filter.id}>{filter.name}</option>
            ))}
          </select>
          
          {selectedFilter && (
            <div className="selected-filter-info">
              <p>{savedFilters.find(f => f.id === selectedFilter)?.description}</p>
            </div>
          )}
        </div>
      )}
      
      <div className="filter-actions">
        <button 
          className="action-button clear"
          onClick={handleClearFilters}
        >
          Clear Filters
        </button>
        
        {onSaveFilter && (
          <>
            <button 
              className="action-button save"
              onClick={() => setShowSaveDialog(true)}
            >
              Save Filter
            </button>
            
            {showSaveDialog && (
              <div className="save-filter-dialog">
                <h4>Save Current Filter</h4>
                <div className="form-group">
                  <label htmlFor="filter-name">Filter Name</label>
                  <input
                    id="filter-name"
                    type="text"
                    placeholder="My Saved Filter"
                    value={newFilterName}
                    onChange={(e) => setNewFilterName(e.target.value)}
                  />
                </div>
                
                <div className="form-group">
                  <label htmlFor="filter-description">Description (optional)</label>
                  <textarea
                    id="filter-description"
                    placeholder="Filter description..."
                    value={newFilterDescription}
                    onChange={(e) => setNewFilterDescription(e.target.value)}
                    rows={3}
                  />
                </div>
                
                <div className="dialog-actions">
                  <button 
                    className="cancel-button"
                    onClick={() => setShowSaveDialog(false)}
                  >
                    Cancel
                  </button>
                  <button 
                    className="save-button"
                    onClick={handleSaveFilter}
                    disabled={!newFilterName.trim()}
                  >
                    Save
                  </button>
                </div>
              </div>
            )}
          </>
        )}
      </div>
    </div>
  );
};

export default GraphFilter;
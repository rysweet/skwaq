import React, { useState, useEffect } from 'react';
import { useNavigate, useParams } from 'react-router-dom';
import InvestigationsList from '../components/InvestigationsList';
import useInvestigations from '../hooks/useInvestigations';
import '../styles/Investigations.css';

/**
 * Page for listing and managing investigations
 */
const Investigations: React.FC = () => {
  const navigate = useNavigate();
  const { investigationId } = useParams<{ investigationId?: string }>();
  const { investigations, isLoading, error, fetchInvestigationById, selectedInvestigation } = useInvestigations();
  const [searchQuery, setSearchQuery] = useState('');
  const [showDetail, setShowDetail] = useState<boolean>(false);
  
  // Fetch investigation details if an ID is provided in the URL
  useEffect(() => {
    if (investigationId) {
      fetchInvestigationById(investigationId);
      setShowDetail(true);
    } else {
      setShowDetail(false);
    }
  }, [investigationId, fetchInvestigationById]);
  
  // Filter investigations based on search query
  const filteredInvestigations = searchQuery 
    ? investigations.filter(inv => 
        inv.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
        inv.description.toLowerCase().includes(searchQuery.toLowerCase()) ||
        inv.repository_name.toLowerCase().includes(searchQuery.toLowerCase())
      )
    : investigations;
  
  // Render investigation detail view
  const renderInvestigationDetail = () => {
    if (isLoading) {
      return (
        <div className="investigation-detail-loading">
          <div className="loading-spinner"></div>
          <p>Loading investigation details...</p>
        </div>
      );
    }
    
    if (!selectedInvestigation) {
      return (
        <div className="investigation-detail-error">
          <p>Investigation not found.</p>
          <button 
            className="primary-button"
            onClick={() => navigate('/investigations')}
          >
            Back to Investigations
          </button>
        </div>
      );
    }
    
    return (
      <div className="investigation-detail">
        <div className="detail-header">
          <button 
            className="back-button"
            onClick={() => navigate('/investigations')}
          >
            &larr; Back to List
          </button>
          <h2 className="detail-title">{selectedInvestigation.title || 'Untitled Investigation'}</h2>
          <div className="detail-status">
            <span className={`status-badge status-${selectedInvestigation.status}`}>
              {selectedInvestigation.status || 'Status Unknown'}
            </span>
          </div>
        </div>
        
        <div className="detail-metadata">
          <div className="metadata-item">
            <span className="metadata-label">Repository:</span>
            <span className="metadata-value">{selectedInvestigation.repository_name}</span>
          </div>
          <div className="metadata-item">
            <span className="metadata-label">Created:</span>
            <span className="metadata-value">
              {selectedInvestigation.creation_date ? 
                new Date(selectedInvestigation.creation_date).toLocaleString() : 
                'Unknown'
              }
            </span>
          </div>
          <div className="metadata-item">
            <span className="metadata-label">Last Updated:</span>
            <span className="metadata-value">
              {selectedInvestigation.update_date ? 
                new Date(selectedInvestigation.update_date).toLocaleString() : 
                'Unknown'
              }
            </span>
          </div>
        </div>
        
        <div className="detail-description">
          <h3>Description</h3>
          <p>{selectedInvestigation.description || 'No description available.'}</p>
        </div>
        
        <div className="detail-stats">
          <div className="stat-card">
            <div className="stat-value">{selectedInvestigation.findings_count || 0}</div>
            <div className="stat-label">Findings</div>
          </div>
          <div className="stat-card">
            <div className="stat-value">{selectedInvestigation.vulnerabilities_count || 0}</div>
            <div className="stat-label">Vulnerabilities</div>
          </div>
        </div>
        
        <div className="detail-actions">
          <button 
            className="action-button"
            onClick={() => navigate(`/investigations/${selectedInvestigation.id}/visualization`)}
          >
            <i className="fa fa-project-diagram"></i> Visualize
          </button>
          <button 
            className="action-button"
            onClick={() => navigate(`/investigations/${selectedInvestigation.id}/report`)}
          >
            <i className="fa fa-file-alt"></i> View Report
          </button>
        </div>
        
        {selectedInvestigation.findings && selectedInvestigation.findings.length > 0 ? (
          <div className="detail-findings">
            <h3>Findings</h3>
            <div className="findings-list">
              {selectedInvestigation.findings.map((finding, index) => (
                <div key={finding.id || index} className="finding-item">
                  <div className="finding-header">
                    <h4 className="finding-title">{finding.title}</h4>
                    <span className={`severity-badge severity-${finding.severity || 'unknown'}`}>
                      {finding.severity || 'Unknown'} Severity
                    </span>
                  </div>
                  <p className="finding-description">{finding.description}</p>
                  {finding.location && (
                    <div className="finding-location">
                      <span className="location-label">Location:</span>
                      <code className="location-value">{finding.location}</code>
                    </div>
                  )}
                </div>
              ))}
            </div>
          </div>
        ) : (
          <div className="detail-findings empty">
            <h3>Findings</h3>
            <p>No findings recorded for this investigation.</p>
          </div>
        )}
      </div>
    );
  };

  // If we're showing a specific investigation
  if (showDetail) {
    return renderInvestigationDetail();
  }

  // Otherwise show the investigations list
  return (
    <div className="investigations-page">
      <div className="page-header">
        <h1 className="page-title">Investigations</h1>
        <div className="page-actions">
          <div className="search-container">
            <input
              type="text"
              className="search-input"
              placeholder="Search investigations..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
            />
            <button 
              className="search-button"
              onClick={() => setSearchQuery('')}
              title={searchQuery ? 'Clear search' : 'Search'}
            >
              {searchQuery ? '×' : '🔍'}
            </button>
          </div>
          
          <button 
            className="primary-button new-investigation-button"
            onClick={() => navigate('/repositories')}
          >
            <i className="fa fa-plus"></i> New Investigation
          </button>
        </div>
      </div>
      
      <div className="investigations-summary">
        <div className="summary-card total-investigations">
          <div className="summary-value">{investigations.length}</div>
          <div className="summary-label">Total Investigations</div>
        </div>
        
        <div className="summary-card active-investigations">
          <div className="summary-value">
            {investigations.filter(inv => inv.status === 'in_progress').length}
          </div>
          <div className="summary-label">Active Investigations</div>
        </div>
        
        <div className="summary-card total-findings">
          <div className="summary-value">
            {investigations.reduce((acc, inv) => acc + inv.findings_count, 0)}
          </div>
          <div className="summary-label">Total Findings</div>
        </div>
        
        <div className="summary-card total-vulnerabilities">
          <div className="summary-value">
            {investigations.reduce((acc, inv) => acc + inv.vulnerabilities_count, 0)}
          </div>
          <div className="summary-label">Total Vulnerabilities</div>
        </div>
      </div>
      
      <div className="investigations-filters">
        {/* Placeholder for future filters */}
      </div>
      
      <InvestigationsList 
        investigations={filteredInvestigations} 
        isLoading={isLoading} 
        error={error}
      />
    </div>
  );
};

export default Investigations;
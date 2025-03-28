import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import InvestigationsList from '../components/InvestigationsList';
import useInvestigations from '../hooks/useInvestigations';
import '../styles/Investigations.css';

/**
 * Page for listing and managing investigations
 */
const Investigations: React.FC = () => {
  const navigate = useNavigate();
  const { investigations, isLoading, error, fetchInvestigations } = useInvestigations();
  const [searchQuery, setSearchQuery] = useState('');
  
  // Filter investigations based on search query
  const filteredInvestigations = searchQuery 
    ? investigations.filter(inv => 
        inv.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
        inv.description.toLowerCase().includes(searchQuery.toLowerCase()) ||
        inv.repository_name.toLowerCase().includes(searchQuery.toLowerCase())
      )
    : investigations;
  
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
import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Investigation } from '../hooks/useInvestigations';
import useWorkflows from '../hooks/useWorkflows';
import '../styles/InvestigationsList.css';

interface InvestigationsListProps {
  investigations: Investigation[];
  isLoading: boolean;
  error: string | null;
}

const InvestigationsList: React.FC<InvestigationsListProps> = ({
  investigations,
  isLoading,
  error
}) => {
  const navigate = useNavigate();
  const { startWorkflow } = useWorkflows();
  const [isLaunchingWorkflow, setIsLaunchingWorkflow] = useState<{[key: string]: boolean}>({});

  const handleViewInvestigation = (id: string) => {
    navigate(`/investigations/${id}`);
  };

  const handleVisualizeInvestigation = (id: string) => {
    navigate(`/investigations/${id}/visualization`);
  };

  const handleViewReport = (id: string) => {
    navigate(`/investigations/${id}/report`);
  };
  
  const handleSourcesAndSinksAnalysis = async (id: string) => {
    try {
      setIsLaunchingWorkflow({...isLaunchingWorkflow, [id]: true});
      
      // Start the sources and sinks workflow
      const workflowId = await startWorkflow('sources_and_sinks', {
        investigation_id: id,
        output_format: 'markdown'
      });
      
      // Navigate to the workflows page to view the results
      if (workflowId) {
        navigate('/workflows');
      }
    } catch (error) {
      console.error('Error launching sources and sinks workflow:', error);
      alert('Failed to launch sources and sinks analysis. Please try again.');
    } finally {
      setIsLaunchingWorkflow({...isLaunchingWorkflow, [id]: false});
    }
  };

  if (isLoading) {
    return (
      <div className="investigations-list-loading">
        <div className="loading-spinner"></div>
        <p>Loading investigations...</p>
      </div>
    );
  }

  if (error) {
    return (
      <div className="investigations-list-error">
        <p>Error: {error}</p>
      </div>
    );
  }

  if (investigations.length === 0) {
    return (
      <div className="investigations-list-empty">
        <p>No investigations found.</p>
        <button 
          className="primary-button"
          onClick={() => navigate('/repositories')}
        >
          Browse Repositories
        </button>
      </div>
    );
  }

  return (
    <div className="investigations-list">
      <div className="investigations-list-header">
        <div className="header-cell title-cell">Title</div>
        <div className="header-cell repository-cell">Repository</div>
        <div className="header-cell date-cell">Created</div>
        <div className="header-cell status-cell">Status</div>
        <div className="header-cell findings-cell">Findings</div>
        <div className="header-cell actions-cell">Actions</div>
      </div>
      
      {investigations.map(investigation => (
        <div 
          key={investigation.id} 
          className="investigation-row"
          onClick={() => handleViewInvestigation(investigation.id)}
        >
          <div className="cell title-cell">
            <div className="investigation-title">{investigation.title}</div>
            <div className="investigation-description">{investigation.description}</div>
          </div>
          
          <div className="cell repository-cell">
            {investigation.repository_name}
          </div>
          
          <div className="cell date-cell">
            {new Date(investigation.creation_date).toLocaleDateString()}
          </div>
          
          <div className="cell status-cell">
            <span className={`status-badge status-${investigation.status}`}>
              {investigation.status}
            </span>
          </div>
          
          <div className="cell findings-cell">
            <div className="findings-count">
              <span className="count">{investigation.findings_count}</span> findings
            </div>
            <div className="vulnerabilities-count">
              <span className="count">{investigation.vulnerabilities_count}</span> vulnerabilities
            </div>
          </div>
          
          <div className="cell actions-cell" onClick={e => e.stopPropagation()}>
            <button 
              className="action-button"
              onClick={(e) => {
                e.stopPropagation();
                handleVisualizeInvestigation(investigation.id);
              }}
              title="Visualize Investigation"
            >
              <i className="fa fa-project-diagram"></i>
            </button>
            
            <button 
              className="action-button"
              onClick={(e) => {
                e.stopPropagation();
                handleViewReport(investigation.id);
              }}
              title="View Report"
            >
              <i className="fa fa-file-alt"></i>
            </button>

            <button 
              className="action-button sources-sinks-button"
              onClick={(e) => {
                e.stopPropagation();
                handleSourcesAndSinksAnalysis(investigation.id);
              }}
              disabled={isLaunchingWorkflow[investigation.id]}
              title="Run Sources & Sinks Analysis"
            >
              {isLaunchingWorkflow[investigation.id] ? (
                <span className="mini-spinner"></span>
              ) : (
                <i className="fa fa-code-branch"></i>
              )}
            </button>
          </div>
        </div>
      ))}
    </div>
  );
};

export default InvestigationsList;
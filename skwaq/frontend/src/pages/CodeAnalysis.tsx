import React, { useState } from 'react';
import '../styles/CodeAnalysis.css';

const CodeAnalysis: React.FC = () => {
  const [repoUrl, setRepoUrl] = useState('');
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  
  // Mock repositories for demo
  const mockRepos = [
    {
      id: 'repo1',
      name: 'example/vuln-repo',
      description: 'Example vulnerable repository',
      status: 'Analyzed',
      vulnerabilities: 8,
      lastAnalyzed: '2025-03-24T10:30:00Z',
    },
    {
      id: 'repo2',
      name: 'example/secure-app',
      description: 'Secure application example',
      status: 'Analyzing',
      vulnerabilities: null,
      lastAnalyzed: null,
    },
    {
      id: 'repo3',
      name: 'example/legacy-code',
      description: 'Legacy code base with technical debt',
      status: 'Analyzed',
      vulnerabilities: 15,
      lastAnalyzed: '2025-03-22T14:45:00Z',
    },
  ];

  const handleAddRepository = (e: React.FormEvent) => {
    e.preventDefault();
    if (!repoUrl) return;
    
    setIsAnalyzing(true);
    
    // Simulate repository analysis process
    setTimeout(() => {
      setIsAnalyzing(false);
      setRepoUrl('');
      // In a real implementation, we would add the repo to the list
    }, 2000);
  };

  return (
    <div className="code-analysis-container">
      <h1 className="page-title">Code Analysis</h1>
      
      <div className="repository-form-card">
        <h2>Add Repository</h2>
        <form className="repository-form" onSubmit={handleAddRepository}>
          <div className="form-group">
            <label htmlFor="repo-url">Repository URL</label>
            <input
              type="text"
              id="repo-url"
              className="form-input"
              placeholder="https://github.com/username/repository"
              value={repoUrl}
              onChange={(e) => setRepoUrl(e.target.value)}
              disabled={isAnalyzing}
            />
          </div>
          <div className="form-options">
            <div className="form-group checkbox-group">
              <input type="checkbox" id="deep-analysis" />
              <label htmlFor="deep-analysis">Deep Analysis</label>
            </div>
            <div className="form-group checkbox-group">
              <input type="checkbox" id="include-dependencies" />
              <label htmlFor="include-dependencies">Include Dependencies</label>
            </div>
          </div>
          <button
            type="submit"
            className={`submit-button ${isAnalyzing ? 'loading' : ''}`}
            disabled={isAnalyzing || !repoUrl}
          >
            {isAnalyzing ? 'Analyzing...' : 'Add Repository'}
          </button>
        </form>
      </div>
      
      <div className="repositories-section">
        <div className="section-header">
          <h2>Your Repositories</h2>
          <div className="section-actions">
            <select className="filter-select">
              <option value="all">All Repositories</option>
              <option value="analyzed">Analyzed</option>
              <option value="analyzing">In Progress</option>
            </select>
            <button className="refresh-button">Refresh</button>
          </div>
        </div>
        
        <div className="repositories-list">
          {mockRepos.map(repo => (
            <div key={repo.id} className="repository-card">
              <div className="repository-header">
                <h3 className="repository-name">{repo.name}</h3>
                <span className={`repository-status status-${repo.status.toLowerCase()}`}>
                  {repo.status}
                </span>
              </div>
              <p className="repository-description">{repo.description}</p>
              
              {repo.status === 'Analyzed' && (
                <div className="repository-details">
                  <div className="details-item">
                    <span className="details-label">Vulnerabilities:</span>
                    <span className="details-value vulnerabilities">{repo.vulnerabilities}</span>
                  </div>
                  <div className="details-item">
                    <span className="details-label">Last Analyzed:</span>
                    <span className="details-value">
                      {new Date(repo.lastAnalyzed as string).toLocaleString()}
                    </span>
                  </div>
                </div>
              )}
              
              {repo.status === 'Analyzing' && (
                <div className="analyzing-indicator">
                  <div className="progress-bar">
                    <div className="progress-value" style={{width: '60%'}}></div>
                  </div>
                  <span className="progress-text">60% complete</span>
                </div>
              )}
              
              <div className="repository-actions">
                {repo.status === 'Analyzed' && (
                  <>
                    <button className="action-btn view-btn">View Results</button>
                    <button className="action-btn reanalyze-btn">Re-analyze</button>
                  </>
                )}
                {repo.status === 'Analyzing' && (
                  <button className="action-btn cancel-btn">Cancel</button>
                )}
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};

export default CodeAnalysis;
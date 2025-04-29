import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import '../styles/Repositories.css';
import useRepositories from '../hooks/useRepositories';
import { Repository } from '../services/repositoryService';

/**
 * Page component for browsing and adding repositories
 */
const Repositories: React.FC = () => {
  const navigate = useNavigate();
  const { repositories, loading: isLoading, error, addRepository } = useRepositories();
  const [searchQuery, setSearchQuery] = useState('');
  const [showAddForm, setShowAddForm] = useState(false);
  const [newRepoUrl, setNewRepoUrl] = useState('');
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [formError, setFormError] = useState<string | null>(null);

  // Filter repositories based on search
  const filteredRepositories = searchQuery 
    ? repositories.filter((repo: Repository) => 
        repo.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
        (repo.description && repo.description.toLowerCase().includes(searchQuery.toLowerCase()))
      )
    : repositories;

  const handleAddRepository = async (e: React.FormEvent) => {
    e.preventDefault();
    
    if (!newRepoUrl.trim()) {
      setFormError('Repository URL is required');
      return;
    }
    
    try {
      setIsSubmitting(true);
      setFormError(null);
      // Pass the default options that match the repository service interface
      const options = {
        deepAnalysis: false,
        includeDependencies: false
      };
      await addRepository(newRepoUrl, options);
      setNewRepoUrl('');
      setShowAddForm(false);
    } catch (error) {
      console.error('Error adding repository:', error);
      setFormError('Failed to add repository. Please check the URL and try again.');
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleRepositorySelect = (repoId: string) => {
    // Create investigation from the repository
    // For now, just navigate back to investigations
    // In a real implementation, this would create an investigation first
    navigate('/investigations');
  };

  return (
    <div className="repositories-page">
      <div className="page-header">
        <h1 className="page-title">Repositories</h1>
        <div className="page-actions">
          <div className="search-container">
            <input
              type="text"
              className="search-input"
              placeholder="Search repositories..."
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
            className="primary-button new-repository-button"
            onClick={() => setShowAddForm(true)}
          >
            <i className="fa fa-plus"></i> Add Repository
          </button>
        </div>
      </div>

      {showAddForm && (
        <div className="add-repository-form">
          <form onSubmit={handleAddRepository}>
            <h2>Add New Repository</h2>
            <div className="form-group">
              <label htmlFor="repoUrl">Repository URL</label>
              <input
                type="text"
                id="repoUrl"
                value={newRepoUrl}
                onChange={(e) => setNewRepoUrl(e.target.value)}
                placeholder="https://github.com/username/repository"
                required
              />
              <p className="form-hint">Enter the URL of a Git repository to analyze</p>
            </div>
            
            {formError && <div className="form-error">{formError}</div>}
            
            <div className="form-actions">
              <button 
                type="button" 
                className="cancel-button"
                onClick={() => {
                  setShowAddForm(false);
                  setNewRepoUrl('');
                  setFormError(null);
                }}
              >
                Cancel
              </button>
              <button 
                type="submit" 
                className="submit-button"
                disabled={isSubmitting}
              >
                {isSubmitting ? 'Adding...' : 'Add Repository'}
              </button>
            </div>
          </form>
        </div>
      )}

      {isLoading ? (
        <div className="repositories-loading">
          <div className="loading-spinner"></div>
          <p>Loading repositories...</p>
        </div>
      ) : error ? (
        <div className="repositories-error">
          <p>Error: {error}</p>
        </div>
      ) : (
        <div className="repositories-list">
          {filteredRepositories.length === 0 ? (
            <div className="no-repositories">
              <p>No repositories found.</p>
              <button 
                className="primary-button"
                onClick={() => setShowAddForm(true)}
              >
                Add Your First Repository
              </button>
            </div>
          ) : (
            <>
              <div className="repositories-count">
                {filteredRepositories.length} {filteredRepositories.length === 1 ? 'repository' : 'repositories'} found
              </div>
              
              <div className="repositories-grid">
                {filteredRepositories.map((repo: Repository) => (
                  <div key={repo.id} className="repository-card" onClick={() => handleRepositorySelect(repo.id)}>
                    <div className="repository-header">
                      <h3 className="repository-name">{repo.name}</h3>
                      <span className={`repository-status status-${repo.status?.toLowerCase()}`}>
                        {repo.status}
                      </span>
                    </div>
                    
                    <p className="repository-description">
                      {repo.description || 'No description available'}
                    </p>
                    
                    <div className="repository-meta">
                      {repo.vulnerabilities !== null && (
                        <div className="vulnerabilities-badge">
                          {repo.vulnerabilities} vulnerabilities
                        </div>
                      )}
                      
                      {repo.lastAnalyzed && (
                        <div className="last-analyzed">
                          Last analyzed: {new Date(repo.lastAnalyzed).toLocaleDateString()}
                        </div>
                      )}
                    </div>
                    
                    <div className="repository-actions">
                      <button 
                        className="action-button analyze-button"
                        onClick={(e) => {
                          e.stopPropagation();
                          handleRepositorySelect(repo.id);
                        }}
                      >
                        Create Investigation
                      </button>
                    </div>
                  </div>
                ))}
              </div>
            </>
          )}
        </div>
      )}
    </div>
  );
};

export default Repositories;
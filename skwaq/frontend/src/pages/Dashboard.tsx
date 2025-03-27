import React from 'react';
import '../styles/Dashboard.css';

/**
 * Dashboard page component
 * Shows overview of system status, recent activities, and quick actions
 */
const Dashboard: React.FC = () => {
  return (
    <div className="dashboard-container">
      <h1 className="page-title">Dashboard</h1>
      
      <div className="dashboard-summary">
        <div className="summary-card">
          <h3>Repositories</h3>
          <div className="summary-value">3</div>
          <p className="summary-description">Active repositories under analysis</p>
        </div>
        <div className="summary-card">
          <h3>Vulnerabilities</h3>
          <div className="summary-value">12</div>
          <p className="summary-description">Potential vulnerabilities detected</p>
        </div>
        <div className="summary-card">
          <h3>Knowledge</h3>
          <div className="summary-value">1,240</div>
          <p className="summary-description">Knowledge graph entities</p>
        </div>
      </div>
      
      <div className="dashboard-grid">
        <div className="dashboard-card">
          <h2 className="card-title">Recent Activities</h2>
          <div className="activity-list">
            <div className="activity-item">
              <div className="activity-time">10:45 AM</div>
              <div className="activity-content">
                <strong>Code Analysis Completed</strong>
                <p>Repository: example/vuln-repo</p>
              </div>
            </div>
            <div className="activity-item">
              <div className="activity-time">Yesterday</div>
              <div className="activity-content">
                <strong>Vulnerability Found</strong>
                <p>SQL Injection in auth.py</p>
              </div>
            </div>
            <div className="activity-item">
              <div className="activity-time">2 days ago</div>
              <div className="activity-content">
                <strong>New Repository Added</strong>
                <p>Added: example/secure-app</p>
              </div>
            </div>
          </div>
        </div>
        
        <div className="dashboard-card">
          <h2 className="card-title">Quick Actions</h2>
          <div className="action-buttons">
            <button className="action-button">
              <span className="action-icon">➕</span>
              <span>Add Repository</span>
            </button>
            <button className="action-button">
              <span className="action-icon">🔍</span>
              <span>Start Assessment</span>
            </button>
            <button className="action-button">
              <span className="action-icon">📊</span>
              <span>View Reports</span>
            </button>
            <button className="action-button">
              <span className="action-icon">💬</span>
              <span>Ask Question</span>
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Dashboard;
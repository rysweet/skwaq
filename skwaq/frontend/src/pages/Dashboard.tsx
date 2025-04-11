import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import apiService from '../services/api';
import eventService from '../services/eventService';
import '../styles/Dashboard.css';

interface DashboardStats {
  repositories: number;
  vulnerabilities: number;
  knowledgeEntities: number;
}

interface Activity {
  id: string;
  type: string;
  title: string;
  description: string;
  timestamp: string;
  relativeTime: string;
}

/**
 * Dashboard page component
 * Shows overview of system status, recent activities, and quick actions
 * All data is fetched from the API, no mock data is used
 */
const Dashboard: React.FC = () => {
  const navigate = useNavigate();
  const [loading, setLoading] = useState<boolean>(true);
  const [stats, setStats] = useState<DashboardStats>({
    repositories: 0,
    vulnerabilities: 0,
    knowledgeEntities: 0
  });
  const [activities, setActivities] = useState<Activity[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [eventSubscriptionId, setEventSubscriptionId] = useState<string | null>(null);

  // Load dashboard data on component mount
  useEffect(() => {
    const fetchDashboardData = async () => {
      setLoading(true);
      setError(null);
      
      try {
        // Fetch repositories count
        const repositories = await apiService.get('/repositories');
        
        // For each repository, fetch vulnerabilities
        let totalVulnerabilities = 0;
        for (const repo of repositories) {
          try {
            const vulnerabilities = await apiService.get(`/repositories/${repo.id}/vulnerabilities`);
            totalVulnerabilities += vulnerabilities.length;
          } catch (err) {
            console.error(`Error fetching vulnerabilities for repo ${repo.id}:`, err);
          }
        }
        
        // Fetch knowledge entities count (if available)
        let knowledgeCount = 0;
        try {
          const knowledge = await apiService.get('/knowledge/stats');
          knowledgeCount = knowledge.totalEntities || 0;
        } catch (err) {
          console.error('Error fetching knowledge stats:', err);
          // Silently fail, as this endpoint might not exist yet
        }
        
        // Update stats
        setStats({
          repositories: repositories.length,
          vulnerabilities: totalVulnerabilities,
          knowledgeEntities: knowledgeCount
        });
        
        // Fetch recent activities
        try {
          const events = await apiService.get('/events/recent');
          
          // Transform events into activities
          const recentActivities = events.map((event: any) => {
            // Calculate relative time
            const timestamp = new Date(event.timestamp);
            const now = new Date();
            const diffMs = now.getTime() - timestamp.getTime();
            const diffMins = Math.floor(diffMs / 60000);
            const diffHours = Math.floor(diffMins / 60);
            const diffDays = Math.floor(diffHours / 24);
            
            let relativeTime;
            if (diffMins < 60) {
              relativeTime = diffMins <= 1 ? 'Just now' : `${diffMins} mins ago`;
            } else if (diffHours < 24) {
              relativeTime = diffHours === 1 ? '1 hour ago' : `${diffHours} hours ago`;
            } else {
              relativeTime = diffDays === 1 ? 'Yesterday' : `${diffDays} days ago`;
            }
            
            return {
              id: event.id,
              type: event.type,
              title: event.title || event.type,
              description: event.description || '',
              timestamp: event.timestamp,
              relativeTime
            };
          });
          
          setActivities(recentActivities);
        } catch (err) {
          console.error('Error fetching recent activities:', err);
          // If we can't get activities from the API, try to use system events
          // from the SSE connection instead
        }
      } catch (err: any) {
        console.error('Error loading dashboard data:', err);
        setError('Failed to load dashboard data. Please check API connection.');
      } finally {
        setLoading(false);
      }
    };
    
    fetchDashboardData();
    
    // Subscribe to system events for real-time updates
    const subscribeToEvents = () => {
      const id = eventService.subscribe('system', '*', (event) => {
        // Add new events to activities
        const timestamp = new Date(event.timestamp || Date.now());
        setActivities(prev => [{
          id: event.id || Math.random().toString(36).substring(7),
          type: event.type,
          title: event.title || event.type,
          description: event.data?.message || JSON.stringify(event.data),
          timestamp: timestamp.toISOString(),
          relativeTime: 'Just now'
        }, ...prev].slice(0, 10)); // Keep only the 10 most recent activities
      });
      
      setEventSubscriptionId(id);
    };
    
    subscribeToEvents();
    
    // Cleanup event subscription
    return () => {
      if (eventSubscriptionId) {
        eventService.unsubscribe(eventSubscriptionId);
      }
    };
  }, [eventSubscriptionId]);
  
  // Update relative times for activities periodically
  useEffect(() => {
    const interval = setInterval(() => {
      setActivities(prev => prev.map(activity => {
        const timestamp = new Date(activity.timestamp);
        const now = new Date();
        const diffMs = now.getTime() - timestamp.getTime();
        const diffMins = Math.floor(diffMs / 60000);
        const diffHours = Math.floor(diffMins / 60);
        const diffDays = Math.floor(diffHours / 24);
        
        let relativeTime;
        if (diffMins < 60) {
          relativeTime = diffMins <= 1 ? 'Just now' : `${diffMins} mins ago`;
        } else if (diffHours < 24) {
          relativeTime = diffHours === 1 ? '1 hour ago' : `${diffHours} hours ago`;
        } else {
          relativeTime = diffDays === 1 ? 'Yesterday' : `${diffDays} days ago`;
        }
        
        return { ...activity, relativeTime };
      }));
    }, 60000); // Update every minute
    
    return () => clearInterval(interval);
  }, []);
  
  // Quick action handlers
  const handleAddRepository = () => {
    navigate('/repositories');
  };
  
  const handleStartAssessment = () => {
    navigate('/assessment');
  };
  
  const handleViewReports = () => {
    navigate('/investigations');
  };
  
  const handleAskQuestion = () => {
    // Navigate to chat page or open chat interface
    navigate('/workflows');
  };

  return (
    <div className="dashboard-container">
      <h1 className="page-title">Dashboard</h1>
      
      {error && (
        <div className="error-banner">
          {error}
        </div>
      )}
      
      <div className="dashboard-summary">
        <div className="summary-card">
          <h3>Repositories</h3>
          <div className="summary-value">
            {loading ? '...' : stats.repositories}
          </div>
          <p className="summary-description">Active repositories under analysis</p>
        </div>
        <div className="summary-card">
          <h3>Vulnerabilities</h3>
          <div className="summary-value">
            {loading ? '...' : stats.vulnerabilities}
          </div>
          <p className="summary-description">Potential vulnerabilities detected</p>
        </div>
        <div className="summary-card">
          <h3>Knowledge</h3>
          <div className="summary-value">
            {loading ? '...' : stats.knowledgeEntities}
          </div>
          <p className="summary-description">Knowledge graph entities</p>
        </div>
      </div>
      
      <div className="dashboard-grid">
        <div className="dashboard-card">
          <h2 className="card-title">Recent Activities</h2>
          {loading ? (
            <div className="loading-indicator">Loading activities...</div>
          ) : activities.length === 0 ? (
            <div className="empty-state">No recent activities found</div>
          ) : (
            <div className="activity-list">
              {activities.map(activity => (
                <div className="activity-item" key={activity.id}>
                  <div className="activity-time">{activity.relativeTime}</div>
                  <div className="activity-content">
                    <strong>{activity.title}</strong>
                    <p>{activity.description}</p>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
        
        <div className="dashboard-card">
          <h2 className="card-title">Quick Actions</h2>
          <div className="action-buttons">
            <button className="action-button" onClick={handleAddRepository}>
              <span className="action-icon">➕</span>
              <span>Add Repository</span>
            </button>
            <button className="action-button" onClick={handleStartAssessment}>
              <span className="action-icon">🔍</span>
              <span>Start Assessment</span>
            </button>
            <button className="action-button" onClick={handleViewReports}>
              <span className="action-icon">📊</span>
              <span>View Reports</span>
            </button>
            <button className="action-button" onClick={handleAskQuestion}>
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
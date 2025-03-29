import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import apiService from '../services/api';

/**
 * API Status Indicator Component
 * Shows a visual indicator of whether the backend API is running
 * When clicked, it navigates to the API test page
 */
const ApiStatusIndicator: React.FC = () => {
  const [apiStatus, setApiStatus] = useState<'online' | 'offline' | 'checking'>('checking');
  const [lastChecked, setLastChecked] = useState<Date | null>(null);

  const checkApiHealth = async () => {
    setApiStatus('checking');
    try {
      await apiService.get('/health');
      setApiStatus('online');
    } catch (error) {
      console.error('API health check failed:', error);
      setApiStatus('offline');
    }
    setLastChecked(new Date());
  };

  // Check API health on component mount and every 30 seconds
  useEffect(() => {
    checkApiHealth();
    const interval = setInterval(checkApiHealth, 30000);
    return () => clearInterval(interval);
  }, []);

  // Determine the appearance based on status
  let color, icon, title;
  switch (apiStatus) {
    case 'online':
      color = '#4caf50'; // Green
      icon = '✓';
      title = 'API Online - Click to test';
      break;
    case 'offline':
      color = '#f44336'; // Red
      icon = '✗';
      title = 'API Offline - Click to check status';
      break;
    case 'checking':
    default:
      color = '#ffc107'; // Amber
      icon = '…';
      title = 'Checking API status...';
      break;
  }

  return (
    <Link to="/api-test" className="api-status-indicator" title={title}>
      <span 
        className="status-dot" 
        style={{ 
          backgroundColor: color,
          display: 'inline-block',
          width: '12px',
          height: '12px',
          borderRadius: '50%',
          marginRight: '5px',
          animation: apiStatus === 'checking' ? 'pulse 1.5s infinite' : 'none',
        }}
      />
      <span className="status-text">API</span>
      <style jsx>{`
        @keyframes pulse {
          0% { opacity: 0.6; }
          50% { opacity: 1; }
          100% { opacity: 0.6; }
        }
        
        .api-status-indicator {
          display: inline-flex;
          align-items: center;
          padding: 5px 10px;
          border-radius: 15px;
          background-color: rgba(0, 0, 0, 0.1);
          color: inherit;
          text-decoration: none;
          font-size: 12px;
          transition: background-color 0.2s;
        }
        
        .api-status-indicator:hover {
          background-color: rgba(0, 0, 0, 0.2);
        }
      `}</style>
    </Link>
  );
};

export default ApiStatusIndicator;
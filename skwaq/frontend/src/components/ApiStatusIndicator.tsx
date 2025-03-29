import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import apiService from '../services/api';
import '../styles/ApiStatusIndicator.css';

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
  let statusClass, title;
  switch (apiStatus) {
    case 'online':
      statusClass = 'status-online';
      title = 'API Online - Click to test';
      break;
    case 'offline':
      statusClass = 'status-offline';
      title = 'API Offline - Click to check status';
      break;
    case 'checking':
    default:
      statusClass = 'status-checking';
      title = 'Checking API status...';
      break;
  }

  return (
    <Link to="/api-test" className={`api-status-indicator ${statusClass}`} title={title}>
      <span className="status-dot" />
      <span className="status-text">API</span>
    </Link>
  );
};

export default ApiStatusIndicator;
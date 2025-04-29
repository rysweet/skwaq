import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import apiService from '../services/api';
import '../styles/ApiStatusIndicator.css';

interface HealthCheckResponse {
  status: 'healthy' | 'degraded' | 'unhealthy';
  api_version?: string;
  database?: {
    connected: boolean;
    message: string;
  };
  error?: string;
  details?: any;
  timestamp?: string;
}

/**
 * API Status Indicator Component
 * Shows a visual indicator of whether the backend API is running
 * When clicked, it navigates to the API test page
 */
const ApiStatusIndicator: React.FC = () => {
  const [apiStatus, setApiStatus] = useState<'online' | 'degraded' | 'offline' | 'checking'>('checking');
  const [errorDetails, setErrorDetails] = useState<string | null>(null);

  const checkApiHealth = async () => {
    setApiStatus('checking');
    try {
      const healthResponse = await apiService.get<HealthCheckResponse>('/health');
      
      // Set status based on the health check response
      if (healthResponse.status === 'healthy') {
        setApiStatus('online');
        setErrorDetails(null);
      } else if (healthResponse.status === 'degraded') {
        setApiStatus('degraded');
        const message = healthResponse.database?.message || 'API is degraded';
        setErrorDetails(message);
      } else {
        setApiStatus('offline');
        setErrorDetails(healthResponse.error || 'Unknown error');
      }
    } catch (error: any) {
      console.error('API health check failed:', error);
      setApiStatus('offline');
      setErrorDetails(error.message || 'Failed to connect to API');
      // No health data available
    }
    // Update was performed now
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
    case 'degraded':
      statusClass = 'status-degraded';
      title = `API Degraded: ${errorDetails || 'Some services unavailable'} - Click for details`;
      break;
    case 'offline':
      statusClass = 'status-offline';
      title = `API Offline: ${errorDetails || 'Connection failed'} - Click for details`;
      break;
    case 'checking':
    default:
      statusClass = 'status-checking';
      title = 'Checking API status...';
      break;
  }

  return (
    <Link 
      to="/api-test"
      className={`api-status-indicator ${statusClass}`} 
      title={title}
    >
      <span className="status-dot" />
      <span className="status-text">API</span>
    </Link>
  );
};

export default ApiStatusIndicator;
import React from 'react';
import { Link } from 'react-router-dom';
import '../styles/NotFound.css';

/**
 * NotFound page component
 * Displays a 404 error page when a route is not found
 */
const NotFound: React.FC = () => {
  return (
    <div className="not-found-container">
      <div className="not-found-content">
        <h1 className="error-code">404</h1>
        <h2 className="error-title">Page Not Found</h2>
        <p className="error-message">
          The page you are looking for might have been removed, had its name changed,
          or is temporarily unavailable.
        </p>
        <div className="action-links">
          <Link to="/" className="home-link">
            Return to Dashboard
          </Link>
        </div>
      </div>
    </div>
  );
};

export default NotFound;
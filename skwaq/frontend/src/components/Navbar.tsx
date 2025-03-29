import React, { useState } from 'react';
import { Link } from 'react-router-dom';
import ApiStatusIndicator from './ApiStatusIndicator';
import '../styles/Navbar.css';

interface NavbarProps {
  darkMode?: boolean;
  toggleDarkMode?: () => void;
}

/**
 * Navigation bar component for the top of the application
 * Contains logo, search functionality, and user settings
 */
const Navbar: React.FC<NavbarProps> = ({ darkMode = false, toggleDarkMode }) => {
  const [searchQuery, setSearchQuery] = useState('');

  const handleSearchSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    // Handle search logic here
    console.log('Search for:', searchQuery);
  };

  return (
    <nav className="navbar">
      <div className="navbar-brand">
        <Link to="/" className="logo">
          <span className="logo-text">Skwaq</span>
          <span className="logo-subtitle">Vulnerability Assessment Copilot</span>
        </Link>
      </div>
      
      <form className="search-form" onSubmit={handleSearchSubmit}>
        <input
          type="search"
          className="search-input"
          placeholder="Search code, vulnerabilities, or knowledge..."
          value={searchQuery}
          onChange={(e) => setSearchQuery(e.target.value)}
        />
        <button type="submit" className="search-button">
          Search
        </button>
      </form>
      
      <div className="navbar-actions">
        {/* API Status Indicator */}
        <ApiStatusIndicator />

        {toggleDarkMode && (
          <button 
            className="theme-toggle-btn" 
            onClick={toggleDarkMode}
            aria-label={darkMode ? "Switch to light mode" : "Switch to dark mode"}
          >
            <span>{darkMode ? '☀️' : '🌙'}</span>
          </button>
        )}
        <button className="notification-btn" aria-label="Notifications">
          <span className="notification-icon">🔔</span>
        </button>
        <div className="user-profile">
          <button className="profile-btn" aria-label="User profile">
            <span className="profile-icon">👤</span>
          </button>
        </div>
      </div>
    </nav>
  );
};

export default Navbar;
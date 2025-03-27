import React, { useState } from 'react';
import { NavLink } from 'react-router-dom';
import '../styles/Sidebar.css';

/**
 * Sidebar navigation component that contains main application routes
 */
const Sidebar: React.FC = () => {
  const [collapsed, setCollapsed] = useState(false);

  const toggleSidebar = () => {
    setCollapsed(!collapsed);
  };

  return (
    <aside className={`sidebar ${collapsed ? 'collapsed' : ''}`}>
      <button className="sidebar-toggle" onClick={toggleSidebar}>
        {collapsed ? '→' : '←'}
      </button>
      
      <nav className="sidebar-nav">
        <ul className="nav-list">
          <li className="nav-item">
            <NavLink to="/" className={({ isActive }) => isActive ? 'nav-link active' : 'nav-link'}>
              <span className="nav-icon">📊</span>
              <span className="nav-text">Dashboard</span>
            </NavLink>
          </li>
          <li className="nav-item">
            <NavLink to="/knowledge" className={({ isActive }) => isActive ? 'nav-link active' : 'nav-link'}>
              <span className="nav-icon">🧠</span>
              <span className="nav-text">Knowledge Graph</span>
            </NavLink>
          </li>
          <li className="nav-item">
            <NavLink to="/code-analysis" className={({ isActive }) => isActive ? 'nav-link active' : 'nav-link'}>
              <span className="nav-icon">💻</span>
              <span className="nav-text">Code Analysis</span>
            </NavLink>
          </li>
          <li className="nav-item">
            <NavLink to="/assessment" className={({ isActive }) => isActive ? 'nav-link active' : 'nav-link'}>
              <span className="nav-icon">🔍</span>
              <span className="nav-text">Vulnerability Assessment</span>
            </NavLink>
          </li>
          <li className="nav-item">
            <NavLink to="/workflows" className={({ isActive }) => isActive ? 'nav-link active' : 'nav-link'}>
              <span className="nav-icon">🔄</span>
              <span className="nav-text">Workflows</span>
            </NavLink>
          </li>
          <li className="nav-divider"></li>
          <li className="nav-item">
            <NavLink to="/settings" className={({ isActive }) => isActive ? 'nav-link active' : 'nav-link'}>
              <span className="nav-icon">⚙️</span>
              <span className="nav-text">Settings</span>
            </NavLink>
          </li>
        </ul>
      </nav>
      
      <div className="sidebar-footer">
        <div className="version">Version 0.1.0</div>
      </div>
    </aside>
  );
};

export default Sidebar;
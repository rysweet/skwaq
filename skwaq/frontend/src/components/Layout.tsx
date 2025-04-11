import React from 'react';
import Navbar from './Navbar';
import Sidebar from './Sidebar';
import '../styles/Layout.css';

export interface LayoutProps {
  children: React.ReactNode;
  darkMode?: boolean;
  toggleDarkMode?: () => void;
}

/**
 * Main layout component that wraps all pages
 * Includes the navbar and sidebar navigation
 */
const Layout: React.FC<LayoutProps> = ({ children, darkMode = false, toggleDarkMode }) => {
  return (
    <div className={`layout ${darkMode ? 'dark-mode' : 'light-mode'}`}>
      <Navbar darkMode={darkMode} toggleDarkMode={toggleDarkMode} />
      <div className="layout-content">
        <Sidebar />
        <main className="main-content">
          {children}
        </main>
      </div>
    </div>
  );
};

export default Layout;
import React from 'react';
import Navbar from './Navbar';
import Sidebar from './Sidebar';
import '../styles/Layout.css';

interface LayoutProps {
  children: React.ReactNode;
}

/**
 * Main layout component that wraps all pages
 * Includes the navbar and sidebar navigation
 */
const Layout: React.FC<LayoutProps> = ({ children }) => {
  return (
    <div className="layout">
      <Navbar />
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
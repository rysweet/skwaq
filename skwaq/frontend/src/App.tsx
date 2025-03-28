import React, { useState, useEffect } from 'react';
import { Routes, Route, useNavigate, useLocation } from 'react-router-dom';
import Layout from './components/Layout';
import Dashboard from './pages/Dashboard';
import KnowledgeGraph from './pages/KnowledgeGraph';
import CodeAnalysis from './pages/CodeAnalysis';
import VulnerabilityAssessment from './pages/VulnerabilityAssessment';
import Workflows from './pages/Workflows';
import Settings from './pages/Settings';
import NotFound from './pages/NotFound';
import InvestigationVisualization from './pages/InvestigationVisualization';
import HelpOverlay from './components/HelpOverlay';
import './styles/App.css';

/**
 * Main App component that handles routing and layout
 */
function App() {
  const [showHelp, setShowHelp] = useState<boolean>(false);
  const [darkMode, setDarkMode] = useState<boolean>(false);
  const navigate = useNavigate();
  const location = useLocation();

  // Handle keyboard shortcuts
  useEffect(() => {
    const handleKeydown = (e: KeyboardEvent) => {
      // Help overlay shortcut
      if (e.key === '?' || (e.key === '/' && e.ctrlKey)) {
        e.preventDefault();
        setShowHelp(prev => !prev);
      }
      
      // Dark mode toggle
      if (e.key === 'd' && e.altKey) {
        e.preventDefault();
        setDarkMode(prev => !prev);
      }
      
      // Navigation shortcuts
      if (e.altKey && !e.ctrlKey && !e.shiftKey && !e.metaKey) {
        switch (e.key) {
          case '1':
            e.preventDefault();
            navigate('/');
            break;
          case '2':
            e.preventDefault();
            navigate('/knowledge');
            break;
          case '3':
            e.preventDefault();
            navigate('/code-analysis');
            break;
          case '4':
            e.preventDefault();
            navigate('/assessment');
            break;
          case '5':
            e.preventDefault();
            navigate('/workflows');
            break;
          case '6':
            e.preventDefault();
            navigate('/settings');
            break;
        }
      }
    };
    
    window.addEventListener('keydown', handleKeydown);
    return () => window.removeEventListener('keydown', handleKeydown);
  }, [navigate]);

  // Apply dark mode to the document root
  useEffect(() => {
    if (darkMode) {
      document.documentElement.classList.add('dark-mode');
    } else {
      document.documentElement.classList.remove('dark-mode');
    }
  }, [darkMode]);

  // Show welcome help on first visit
  useEffect(() => {
    const hasVisited = localStorage.getItem('hasVisitedBefore');
    if (!hasVisited && location.pathname === '/') {
      setShowHelp(true);
      localStorage.setItem('hasVisitedBefore', 'true');
    }
  }, [location.pathname]);

  return (
    <>
      <Layout darkMode={darkMode} toggleDarkMode={() => setDarkMode(prev => !prev)}>
        <Routes>
          <Route path="/" element={<Dashboard />} />
          <Route path="/knowledge" element={<KnowledgeGraph darkMode={darkMode} />} />
          <Route path="/code-analysis" element={<CodeAnalysis />} />
          <Route path="/assessment" element={<VulnerabilityAssessment />} />
          <Route path="/workflows" element={<Workflows />} />
          <Route path="/settings" element={<Settings />} />
          <Route path="/investigations/:investigationId/visualization" element={<InvestigationVisualization darkMode={darkMode} />} />
          <Route path="*" element={<NotFound />} />
        </Routes>
      </Layout>
      
      {showHelp && <HelpOverlay onClose={() => setShowHelp(false)} />}
    </>
  );
}

export default App;
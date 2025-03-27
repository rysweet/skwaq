import React from 'react';
import { Routes, Route } from 'react-router-dom';
import Layout from './components/Layout';
import Dashboard from './pages/Dashboard';
import KnowledgeGraph from './pages/KnowledgeGraph';
import CodeAnalysis from './pages/CodeAnalysis';
import VulnerabilityAssessment from './pages/VulnerabilityAssessment';
import Settings from './pages/Settings';
import NotFound from './pages/NotFound';
import './styles/App.css';

/**
 * Main App component that handles routing and layout
 */
function App() {
  return (
    <Layout>
      <Routes>
        <Route path="/" element={<Dashboard />} />
        <Route path="/knowledge" element={<KnowledgeGraph />} />
        <Route path="/code-analysis" element={<CodeAnalysis />} />
        <Route path="/assessment" element={<VulnerabilityAssessment />} />
        <Route path="/settings" element={<Settings />} />
        <Route path="*" element={<NotFound />} />
      </Routes>
    </Layout>
  );
}

export default App;
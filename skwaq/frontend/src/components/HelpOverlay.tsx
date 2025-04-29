import React, { useState, useEffect, useCallback } from 'react';
import '../styles/HelpOverlay.css';

interface HelpSection {
  title: string;
  content: React.ReactNode;
}

interface HelpOverlayProps {
  onClose: () => void;
}

/**
 * HelpOverlay component that displays contextual help based on the current page
 */
const HelpOverlay: React.FC<HelpOverlayProps> = ({ onClose }) => {
  const [activeSection, setActiveSection] = useState<string>('general');
  const [currentPath, setCurrentPath] = useState<string>(window.location.pathname);

  useEffect(() => {
    setCurrentPath(window.location.pathname);
  }, []);

  // Close on escape key
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        onClose();
      }
    };
    
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [onClose]);

  // Get contextual help sections based on current path
  const getHelpSections = useCallback((): Record<string, HelpSection> => {
    const generalSection: HelpSection = {
      title: 'General Help',
      content: (
        <div>
          <p>
            Skwaq is a Vulnerability Assessment Copilot designed to help you analyze codebases 
            for security vulnerabilities. The interface is divided into several main sections 
            accessible from the sidebar.
          </p>
          <h4>Keyboard Shortcuts</h4>
          <div className="help-shortcuts">
            <div className="shortcut-row">
              <span className="shortcut-key">?</span>
              <span className="shortcut-desc">Show/hide help</span>
            </div>
            <div className="shortcut-row">
              <span className="shortcut-key">Ctrl + /</span>
              <span className="shortcut-desc">Focus search</span>
            </div>
            <div className="shortcut-row">
              <span className="shortcut-key">Esc</span>
              <span className="shortcut-desc">Close dialogs or cancel</span>
            </div>
            <div className="shortcut-row">
              <span className="shortcut-key">Alt + 1-5</span>
              <span className="shortcut-desc">Navigate to main sections</span>
            </div>
            <div className="shortcut-row">
              <span className="shortcut-key">Alt + D</span>
              <span className="shortcut-desc">Toggle dark mode</span>
            </div>
          </div>
        </div>
      )
    };
    
    // Path-specific help
    const pathHelpMap: Record<string, Record<string, HelpSection>> = {
      '/': {
        dashboard: {
          title: 'Dashboard Help',
          content: (
            <div>
              <p>The Dashboard provides an overview of your vulnerability assessment activities:</p>
              <ul>
                <li><strong>Summary Cards</strong>: Quick stats on repositories, vulnerabilities, and knowledge entities</li>
                <li><strong>Recent Activities</strong>: Timeline of recent actions and findings</li>
                <li><strong>Quick Actions</strong>: Shortcuts to common tasks</li>
              </ul>
              <p>Click on any card or activity to view more details.</p>
            </div>
          )
        }
      },
      '/knowledge': {
        graph: {
          title: 'Knowledge Graph Help',
          content: (
            <div>
              <p>The Knowledge Graph visualizes security concepts and their relationships:</p>
              <ul>
                <li><strong>Navigation</strong>: Drag to move, scroll to zoom, right-click + drag to rotate</li>
                <li><strong>Nodes</strong>: Click on nodes to see details</li>
                <li><strong>Filtering</strong>: Use controls above the graph to filter by node or relationship type</li>
                <li><strong>Search</strong>: Use the search bar to find specific nodes</li>
              </ul>
              <p>The different colors represent different node types:</p>
              <ul>
                <li><span className="color-sample vulnerability"></span> <strong>Red</strong>: Vulnerabilities</li>
                <li><span className="color-sample cwe"></span> <strong>Blue</strong>: CWEs</li>
                <li><span className="color-sample concept"></span> <strong>Green</strong>: Security Concepts</li>
              </ul>
            </div>
          )
        }
      },
      '/code-analysis': {
        repositories: {
          title: 'Code Analysis Help',
          content: (
            <div>
              <p>The Code Analysis section allows you to analyze repositories for vulnerabilities:</p>
              <ul>
                <li><strong>Add Repository</strong>: Enter a GitHub URL to add a new repository</li>
                <li><strong>Repository Cards</strong>: View status and findings for each repository</li>
                <li><strong>Analysis Options</strong>: Configure deep analysis and dependency scanning</li>
                <li><strong>Results</strong>: View vulnerabilities discovered in each repository</li>
              </ul>
              <p>Analysis may take several minutes depending on repository size.</p>
            </div>
          )
        }
      },
      '/assessment': {
        workflows: {
          title: 'Vulnerability Assessment Help',
          content: (
            <div>
              <p>The Vulnerability Assessment section offers three approaches:</p>
              <ul>
                <li><strong>Guided Assessment</strong>: Step-by-step workflow with structured guidance</li>
                <li><strong>Chat Interface</strong>: Natural language conversation with the AI copilot</li>
                <li><strong>Workflows</strong>: Pre-configured assessment approaches for specific scenarios</li>
              </ul>
              <p>Select the appropriate tab for your preferred assessment style.</p>
            </div>
          )
        }
      },
      '/settings': {
        settings: {
          title: 'Settings Help',
          content: (
            <div>
              <p>The Settings section allows you to configure the application:</p>
              <ul>
                <li><strong>General Settings</strong>: UI preferences, telemetry, and defaults</li>
                <li><strong>API Configuration</strong>: API keys and endpoints for AI services</li>
                <li><strong>External Tools</strong>: Configure CodeQL and other analysis tools</li>
                <li><strong>Storage & Database</strong>: Manage Neo4j database and local storage</li>
                <li><strong>About</strong>: Version information and documentation links</li>
              </ul>
              <p>Changes are saved automatically when you modify settings.</p>
            </div>
          )
        }
      }
    };
    
    // Find path-specific help or fall back to general
    const pathComponents = currentPath.split('/').filter(Boolean);
    const basePath = '/' + (pathComponents.length > 0 ? pathComponents[0] : '');
    
    return {
      general: generalSection,
      ...(pathHelpMap[basePath] || {})
    };
  }, [currentPath]);

  const helpSections = getHelpSections();
  
  return (
    <div className="help-overlay">
      <div className="help-modal">
        <div className="help-header">
          <h2>Skwaq Help</h2>
          <button className="help-close-btn" onClick={onClose}>×</button>
        </div>
        
        <div className="help-content">
          <div className="help-sidebar">
            {Object.entries(helpSections).map(([key, section]) => (
              <button
                key={key}
                className={`help-section-btn ${activeSection === key ? 'active' : ''}`}
                onClick={() => setActiveSection(key)}
              >
                {section.title}
              </button>
            ))}
            <a 
              href="/docs/gui_guide.md" 
              className="help-docs-link"
              target="_blank"
              rel="noopener noreferrer"
            >
              Full Documentation
            </a>
          </div>
          
          <div className="help-main-content">
            {helpSections[activeSection]?.content || (
              <p>No help content available for this section.</p>
            )}
          </div>
        </div>
        
        <div className="help-footer">
          <p>Press <kbd>?</kbd> anytime to open this help overlay</p>
        </div>
      </div>
    </div>
  );
};

export default HelpOverlay;
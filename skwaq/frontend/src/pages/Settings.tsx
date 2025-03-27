import React, { useState } from 'react';
import '../styles/Settings.css';

const Settings: React.FC = () => {
  const [activeSection, setActiveSection] = useState('general');
  
  // Mock settings for demonstration
  const [generalSettings, setGeneralSettings] = useState({
    telemetryEnabled: true,
    darkMode: false,
    autoSave: true,
    defaultRepository: '',
  });
  
  const [apiSettings, setApiSettings] = useState({
    apiKey: '••••••••••••••••',
    apiEndpoint: 'https://api.openai.azure.com/',
    model: 'gpt4o',
    maxTokens: 2000,
  });
  
  const [toolSettings, setToolSettings] = useState({
    codeqlEnabled: true,
    codeqlPath: '/usr/local/bin/codeql',
    blarifyEnabled: true,
    customToolsEnabled: false,
  });
  
  const handleGeneralSettingsChange = (e: React.ChangeEvent<HTMLInputElement | HTMLSelectElement>) => {
    const { name, value, type } = e.target;
    const checked = (e.target as HTMLInputElement).checked;
    
    setGeneralSettings({
      ...generalSettings,
      [name]: type === 'checkbox' ? checked : value,
    });
  };
  
  const handleApiSettingsChange = (e: React.ChangeEvent<HTMLInputElement | HTMLSelectElement>) => {
    const { name, value } = e.target;
    
    setApiSettings({
      ...apiSettings,
      [name]: value,
    });
  };
  
  const handleToolSettingsChange = (e: React.ChangeEvent<HTMLInputElement | HTMLSelectElement>) => {
    const { name, value, type } = e.target;
    const checked = (e.target as HTMLInputElement).checked;
    
    setToolSettings({
      ...toolSettings,
      [name]: type === 'checkbox' ? checked : value,
    });
  };
  
  return (
    <div className="settings-container">
      <h1 className="page-title">Settings</h1>
      
      <div className="settings-layout">
        <div className="settings-sidebar">
          <button 
            className={`settings-nav-item ${activeSection === 'general' ? 'active' : ''}`}
            onClick={() => setActiveSection('general')}
          >
            General
          </button>
          <button 
            className={`settings-nav-item ${activeSection === 'api' ? 'active' : ''}`}
            onClick={() => setActiveSection('api')}
          >
            API Configuration
          </button>
          <button 
            className={`settings-nav-item ${activeSection === 'tools' ? 'active' : ''}`}
            onClick={() => setActiveSection('tools')}
          >
            External Tools
          </button>
          <button 
            className={`settings-nav-item ${activeSection === 'storage' ? 'active' : ''}`}
            onClick={() => setActiveSection('storage')}
          >
            Storage & Database
          </button>
          <button 
            className={`settings-nav-item ${activeSection === 'about' ? 'active' : ''}`}
            onClick={() => setActiveSection('about')}
          >
            About
          </button>
        </div>
        
        <div className="settings-content">
          {activeSection === 'general' && (
            <div className="settings-section">
              <h2 className="settings-section-title">General Settings</h2>
              
              <div className="settings-form">
                <div className="form-group checkbox-group">
                  <input 
                    type="checkbox" 
                    id="telemetryEnabled" 
                    name="telemetryEnabled"
                    checked={generalSettings.telemetryEnabled}
                    onChange={handleGeneralSettingsChange}
                  />
                  <label htmlFor="telemetryEnabled">Enable Telemetry</label>
                  <p className="setting-description">
                    Allow anonymous usage data collection to improve the product.
                  </p>
                </div>
                
                <div className="form-group checkbox-group">
                  <input 
                    type="checkbox" 
                    id="darkMode" 
                    name="darkMode"
                    checked={generalSettings.darkMode}
                    onChange={handleGeneralSettingsChange}
                  />
                  <label htmlFor="darkMode">Dark Mode</label>
                  <p className="setting-description">
                    Enable dark mode for the user interface.
                  </p>
                </div>
                
                <div className="form-group checkbox-group">
                  <input 
                    type="checkbox" 
                    id="autoSave" 
                    name="autoSave"
                    checked={generalSettings.autoSave}
                    onChange={handleGeneralSettingsChange}
                  />
                  <label htmlFor="autoSave">Auto-save Investigations</label>
                  <p className="setting-description">
                    Automatically save investigation progress.
                  </p>
                </div>
                
                <div className="form-group">
                  <label htmlFor="defaultRepository">Default Repository</label>
                  <input 
                    type="text" 
                    id="defaultRepository" 
                    name="defaultRepository"
                    value={generalSettings.defaultRepository}
                    onChange={handleGeneralSettingsChange}
                    placeholder="username/repository"
                    className="form-input"
                  />
                  <p className="setting-description">
                    Default repository to use when starting a new investigation.
                  </p>
                </div>
                
                <div className="settings-actions">
                  <button className="save-button">Save Settings</button>
                  <button className="reset-button">Reset to Defaults</button>
                </div>
              </div>
            </div>
          )}
          
          {activeSection === 'api' && (
            <div className="settings-section">
              <h2 className="settings-section-title">API Configuration</h2>
              
              <div className="settings-form">
                <div className="form-group">
                  <label htmlFor="apiKey">API Key</label>
                  <div className="api-key-input">
                    <input 
                      type="password" 
                      id="apiKey" 
                      name="apiKey"
                      value={apiSettings.apiKey}
                      onChange={handleApiSettingsChange}
                      className="form-input"
                    />
                    <button className="show-key-button">Show</button>
                  </div>
                  <p className="setting-description">
                    Your Azure OpenAI API key.
                  </p>
                </div>
                
                <div className="form-group">
                  <label htmlFor="apiEndpoint">API Endpoint</label>
                  <input 
                    type="text" 
                    id="apiEndpoint" 
                    name="apiEndpoint"
                    value={apiSettings.apiEndpoint}
                    onChange={handleApiSettingsChange}
                    className="form-input"
                  />
                  <p className="setting-description">
                    The Azure OpenAI endpoint URL.
                  </p>
                </div>
                
                <div className="form-group">
                  <label htmlFor="model">Model</label>
                  <select 
                    id="model" 
                    name="model"
                    value={apiSettings.model}
                    onChange={handleApiSettingsChange}
                    className="form-select"
                  >
                    <option value="gpt4o">GPT-4o</option>
                    <option value="o1">Claude-3 Opus</option>
                    <option value="o3">Claude-3 Sonnet</option>
                  </select>
                  <p className="setting-description">
                    The AI model to use for analysis and interactions.
                  </p>
                </div>
                
                <div className="form-group">
                  <label htmlFor="maxTokens">Max Tokens</label>
                  <input 
                    type="number" 
                    id="maxTokens" 
                    name="maxTokens"
                    value={apiSettings.maxTokens}
                    onChange={handleApiSettingsChange}
                    className="form-input number-input"
                    min="100"
                    max="8000"
                  />
                  <p className="setting-description">
                    Maximum number of tokens for API responses.
                  </p>
                </div>
                
                <div className="settings-actions">
                  <button className="save-button">Save API Settings</button>
                  <button className="test-button">Test Connection</button>
                </div>
              </div>
            </div>
          )}
          
          {activeSection === 'tools' && (
            <div className="settings-section">
              <h2 className="settings-section-title">External Tools</h2>
              
              <div className="settings-form">
                <div className="form-group checkbox-group">
                  <input 
                    type="checkbox" 
                    id="codeqlEnabled" 
                    name="codeqlEnabled"
                    checked={toolSettings.codeqlEnabled}
                    onChange={handleToolSettingsChange}
                  />
                  <label htmlFor="codeqlEnabled">Enable CodeQL</label>
                  <p className="setting-description">
                    Use CodeQL for static analysis of code.
                  </p>
                </div>
                
                <div className="form-group">
                  <label htmlFor="codeqlPath">CodeQL Path</label>
                  <input 
                    type="text" 
                    id="codeqlPath" 
                    name="codeqlPath"
                    value={toolSettings.codeqlPath}
                    onChange={handleToolSettingsChange}
                    className="form-input"
                    disabled={!toolSettings.codeqlEnabled}
                  />
                  <p className="setting-description">
                    Path to the CodeQL executable.
                  </p>
                </div>
                
                <div className="form-group checkbox-group">
                  <input 
                    type="checkbox" 
                    id="blarifyEnabled" 
                    name="blarifyEnabled"
                    checked={toolSettings.blarifyEnabled}
                    onChange={handleToolSettingsChange}
                  />
                  <label htmlFor="blarifyEnabled">Enable Blarify</label>
                  <p className="setting-description">
                    Use Blarify for code graph generation.
                  </p>
                </div>
                
                <div className="form-group checkbox-group">
                  <input 
                    type="checkbox" 
                    id="customToolsEnabled" 
                    name="customToolsEnabled"
                    checked={toolSettings.customToolsEnabled}
                    onChange={handleToolSettingsChange}
                  />
                  <label htmlFor="customToolsEnabled">Enable Custom Tools</label>
                  <p className="setting-description">
                    Allow integration with custom external tools.
                  </p>
                </div>
                
                <div className="settings-actions">
                  <button className="save-button">Save Tool Settings</button>
                  <button className="verify-button">Verify Tools</button>
                </div>
              </div>
            </div>
          )}
          
          {activeSection === 'storage' && (
            <div className="settings-section">
              <h2 className="settings-section-title">Storage & Database</h2>
              
              <div className="settings-form">
                <div className="database-status">
                  <h3>Neo4j Database</h3>
                  <div className="status-indicator connected">
                    <span className="status-dot"></span>
                    <span className="status-text">Connected</span>
                  </div>
                  <p className="database-info">
                    Version: 5.10.0<br />
                    Address: localhost:7687<br />
                    Database Size: 125 MB
                  </p>
                </div>
                
                <div className="form-actions">
                  <button className="action-button danger">Clear Database</button>
                  <button className="action-button">Backup Database</button>
                  <button className="action-button">Restore Backup</button>
                </div>
                
                <h3 className="section-subtitle">Local Storage</h3>
                <div className="storage-info">
                  <p>
                    <strong>Cache Size:</strong> 45 MB<br />
                    <strong>Repository Cache:</strong> 3 repositories (250 MB)
                  </p>
                </div>
                
                <div className="form-actions">
                  <button className="action-button">Clear Cache</button>
                  <button className="action-button danger">Reset All Data</button>
                </div>
              </div>
            </div>
          )}
          
          {activeSection === 'about' && (
            <div className="settings-section">
              <h2 className="settings-section-title">About Skwaq</h2>
              
              <div className="about-content">
                <div className="about-logo">Skwaq</div>
                <div className="version-info">Version 0.1.0</div>
                <p className="about-description">
                  Skwaq is a Vulnerability Assessment Copilot designed to assist vulnerability researchers in analyzing codebases to discover potential security vulnerabilities. The name "skwaq" is derived from the Lushootseed language of the Pacific Northwest, meaning "Raven."
                </p>
                
                <h3>Technologies</h3>
                <ul className="technologies-list">
                  <li>Neo4j Graph Database</li>
                  <li>Azure OpenAI Service</li>
                  <li>AutoGen Core Framework</li>
                  <li>React + TypeScript</li>
                </ul>
                
                <div className="links-section">
                  <a href="#" className="about-link">Documentation</a>
                  <a href="#" className="about-link">GitHub Repository</a>
                  <a href="#" className="about-link">Report Issue</a>
                  <a href="#" className="about-link">License Information</a>
                </div>
                
                <div className="copyright">
                  © 2025 Skwaq Contributors
                </div>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default Settings;
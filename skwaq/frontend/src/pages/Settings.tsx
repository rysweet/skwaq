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
    authMethod: 'api-key', // 'api-key', 'entra-id', or 'bearer-token'
    apiKey: '••••••••••••••••',
    apiEndpoint: 'https://api.openai.azure.com/',
    apiVersion: '2023-05-15',
    model: 'gpt4o',
    maxTokens: 2000,
    useEntraId: false,
    tenantId: '',
    clientId: '',
    clientSecret: '••••••••••••••••',
    tokenScope: 'https://cognitiveservices.azure.com/.default',
    modelDeployments: {
      chat: 'gpt4o',
      code: 'o3',
      reasoning: 'o1'
    }
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
              <h2 className="settings-section-title">Azure OpenAI Configuration</h2>
              
              <div className="settings-form">
                <div className="form-group">
                  <label htmlFor="authMethod">Authentication Method</label>
                  <select 
                    id="authMethod" 
                    name="authMethod"
                    value={apiSettings.authMethod}
                    onChange={handleApiSettingsChange}
                    className="form-select"
                  >
                    <option value="api-key">API Key</option>
                    <option value="entra-id">Microsoft Entra ID (Client Credentials)</option>
                    <option value="bearer-token">Microsoft Entra ID (Bearer Token)</option>
                  </select>
                  <p className="setting-description">
                    Select the authentication method for Azure OpenAI.
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
                  <label htmlFor="apiVersion">API Version</label>
                  <input 
                    type="text" 
                    id="apiVersion" 
                    name="apiVersion"
                    value={apiSettings.apiVersion}
                    onChange={handleApiSettingsChange}
                    className="form-input"
                  />
                  <p className="setting-description">
                    Azure OpenAI API version (e.g., 2023-05-15).
                  </p>
                </div>
                
                {apiSettings.authMethod === 'api-key' && (
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
                )}
                
                {apiSettings.authMethod === 'bearer-token' && (
                  <>
                    <div className="form-group">
                      <label htmlFor="tokenScope">Token Scope</label>
                      <input 
                        type="text" 
                        id="tokenScope" 
                        name="tokenScope"
                        value={apiSettings.tokenScope}
                        onChange={handleApiSettingsChange}
                        className="form-input"
                      />
                      <p className="setting-description">
                        The scope for the bearer token, typically "https://cognitiveservices.azure.com/.default".
                      </p>
                    </div>
                    
                    <div className="info-panel">
                      <p className="info-text">
                        Bearer token authentication uses the DefaultAzureCredential from the azure-identity package.
                        This will automatically use available credentials from environment variables, managed identities,
                        Visual Studio Code credentials, Azure CLI credentials, and more.
                      </p>
                      <p className="info-text">
                        No additional credentials need to be provided here as they will be obtained from the system.
                      </p>
                    </div>
                  </>
                )}
                
                {apiSettings.authMethod === 'entra-id' && (
                  <>
                    <div className="form-group">
                      <label htmlFor="tenantId">Tenant ID</label>
                      <input 
                        type="text" 
                        id="tenantId" 
                        name="tenantId"
                        value={apiSettings.tenantId}
                        onChange={handleApiSettingsChange}
                        className="form-input"
                      />
                      <p className="setting-description">
                        Your Microsoft Entra ID tenant ID.
                      </p>
                    </div>
                    
                    <div className="form-group">
                      <label htmlFor="clientId">Client ID</label>
                      <input 
                        type="text" 
                        id="clientId" 
                        name="clientId"
                        value={apiSettings.clientId}
                        onChange={handleApiSettingsChange}
                        className="form-input"
                      />
                      <p className="setting-description">
                        Your application's client ID.
                      </p>
                    </div>
                    
                    <div className="form-group">
                      <label htmlFor="clientSecret">Client Secret</label>
                      <div className="api-key-input">
                        <input 
                          type="password" 
                          id="clientSecret" 
                          name="clientSecret"
                          value={apiSettings.clientSecret}
                          onChange={handleApiSettingsChange}
                          className="form-input"
                        />
                        <button className="show-key-button">Show</button>
                      </div>
                      <p className="setting-description">
                        Your application's client secret. Leave blank to use managed identity.
                      </p>
                    </div>
                  </>
                )}
                
                <h3 className="section-subtitle">Model Deployments</h3>
                
                <div className="form-group">
                  <label htmlFor="chatModel">Chat Model Deployment</label>
                  <input 
                    type="text" 
                    id="chatModel" 
                    name="chatModel"
                    value={apiSettings.modelDeployments.chat}
                    onChange={(e) => {
                      setApiSettings({
                        ...apiSettings,
                        modelDeployments: {
                          ...apiSettings.modelDeployments,
                          chat: e.target.value
                        }
                      });
                    }}
                    className="form-input"
                  />
                  <p className="setting-description">
                    Deployment name for chat model.
                  </p>
                </div>
                
                <div className="form-group">
                  <label htmlFor="codeModel">Code Model Deployment</label>
                  <input 
                    type="text" 
                    id="codeModel" 
                    name="codeModel"
                    value={apiSettings.modelDeployments.code}
                    onChange={(e) => {
                      setApiSettings({
                        ...apiSettings,
                        modelDeployments: {
                          ...apiSettings.modelDeployments,
                          code: e.target.value
                        }
                      });
                    }}
                    className="form-input"
                  />
                  <p className="setting-description">
                    Deployment name for code analysis model.
                  </p>
                </div>
                
                <div className="form-group">
                  <label htmlFor="reasoningModel">Reasoning Model Deployment</label>
                  <input 
                    type="text" 
                    id="reasoningModel" 
                    name="reasoningModel"
                    value={apiSettings.modelDeployments.reasoning}
                    onChange={(e) => {
                      setApiSettings({
                        ...apiSettings,
                        modelDeployments: {
                          ...apiSettings.modelDeployments,
                          reasoning: e.target.value
                        }
                      });
                    }}
                    className="form-input"
                  />
                  <p className="setting-description">
                    Deployment name for reasoning model.
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
                  <button 
                    className="save-button" 
                    onClick={() => {
                      // In a real implementation, this would make an API call to save settings
                      alert('API settings saved successfully!');
                    }}
                  >
                    Save API Settings
                  </button>
                  <button 
                    className="test-button"
                    onClick={() => {
                      // In a real implementation, this would make an API call to test connection
                      const authMethod = apiSettings.authMethod === 'api-key' ? 'API Key' : 'Microsoft Entra ID';
                      alert(`Connection successful using ${authMethod} authentication!`);
                    }}
                  >
                    Test Connection
                  </button>
                  <button 
                    className="export-button"
                    onClick={() => {
                      // In a real implementation, this would fetch the .env content from the server
                      // and then create a download
                      
                      // Create .env file content manually for the demo
                      const authMethod = apiSettings.authMethod;
                      let envContent = "# Azure OpenAI Configuration\n";
                      
                      // Common configuration
                      envContent += `AZURE_OPENAI_ENDPOINT=${apiSettings.apiEndpoint}\n`;
                      envContent += `AZURE_OPENAI_API_VERSION=${apiSettings.apiVersion}\n`;
                      
                      // Authentication-specific configuration
                      if (authMethod === 'api-key') {
                        envContent += "AZURE_OPENAI_USE_ENTRA_ID=false\n";
                        envContent += `AZURE_OPENAI_API_KEY=${apiSettings.apiKey}\n`;
                      } else if (authMethod === 'bearer-token') {
                        envContent += "AZURE_OPENAI_USE_ENTRA_ID=true\n";
                        envContent += "AZURE_OPENAI_AUTH_METHOD=bearer_token\n";
                        envContent += `AZURE_OPENAI_TOKEN_SCOPE=${apiSettings.tokenScope}\n`;
                        envContent += "# Note: Bearer token auth uses DefaultAzureCredential, which will use environment variables or other methods\n";
                        envContent += "# like Azure CLI credentials, managed identities, Visual Studio Code credentials, etc.\n";
                      } else {
                        envContent += "AZURE_OPENAI_USE_ENTRA_ID=true\n";
                        envContent += `AZURE_TENANT_ID=${apiSettings.tenantId}\n`;
                        envContent += `AZURE_CLIENT_ID=${apiSettings.clientId}\n`;
                        if (apiSettings.clientSecret) {
                          envContent += `AZURE_CLIENT_SECRET=${apiSettings.clientSecret}\n`;
                        }
                      }
                      
                      // Model deployments
                      const deployments = apiSettings.modelDeployments;
                      envContent += `AZURE_OPENAI_MODEL_DEPLOYMENTS={"chat":"${deployments.chat}","code":"${deployments.code}","reasoning":"${deployments.reasoning}"}\n`;
                      
                      // Create and download the .env file
                      const element = document.createElement('a');
                      const file = new Blob([envContent], {type: 'text/plain'});
                      element.href = URL.createObjectURL(file);
                      element.download = '.env';
                      document.body.appendChild(element);
                      element.click();
                      document.body.removeChild(element);
                    }}
                  >
                    Export as .env
                  </button>
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
                  <a href="https://docs.example.com/skwaq" className="about-link">Documentation</a>
                  <a href="https://github.com/example/skwaq" className="about-link">GitHub Repository</a>
                  <a href="https://github.com/example/skwaq/issues" className="about-link">Report Issue</a>
                  <a href="https://github.com/example/skwaq/blob/main/LICENSE" className="about-link">License Information</a>
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
import React, { useState, useEffect, useCallback } from 'react';
import apiService from '../services/api';
import authService from '../services/authService';
import repositoryService from '../services/repositoryService';
import chatService from '../services/chatService';
import eventService from '../services/eventService';
// Commenting out unused import
// import workflowService from '../services/workflowService';

/**
 * A comprehensive test page for checking API integration
 */
const ApiTestPage: React.FC = () => {
  // Authentication state
  const [username, setUsername] = useState<string>('admin');
  const [password, setPassword] = useState<string>('admin');
  const [authToken, setAuthToken] = useState<string | null>(localStorage.getItem('authToken'));
  const [loginStatus, setLoginStatus] = useState<string>('');
  const [currentUser, setCurrentUser] = useState<any>(null);
  
  // API testing state
  const [url, setUrl] = useState<string>('/health');
  const [response, setResponse] = useState<any>(null);
  const [loading, setLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  
  // Repository state
  const [repositories, setRepositories] = useState<any[]>([]);
  const [repoUrl, setRepoUrl] = useState<string>('https://github.com/example/repo');
  // Commented out unused state variables
  // const [selectedRepoId, setSelectedRepoId] = useState<string>('');
  
  // Workflow state
  const [activeWorkflows, setActiveWorkflows] = useState<any[]>([]);
  
  // Chat state
  const [conversations, setConversations] = useState<any[]>([]);
  const [selectedConversationId, setSelectedConversationId] = useState<string>('');
  const [conversationMessages, setConversationMessages] = useState<any[]>([]);
  const [messageText, setMessageText] = useState<string>('');
  
  // Event state
  const [events, setEvents] = useState<any[]>([]);
  const [eventSubscriptionId, setEventSubscriptionId] = useState<string | null>(null);
  const [showEvents, setShowEvents] = useState<boolean>(true);
  
  // Update baseURL to use port 5001
  useEffect(() => {
    if (apiService['api'] && apiService['api'].defaults && apiService['api'].defaults.baseURL) {
      // Only update if not already set to 5001
      if (!apiService['api'].defaults.baseURL.includes('5001')) {
        apiService['api'].defaults.baseURL = 'http://localhost:5001/api';
        console.log('API base URL updated to:', apiService['api'].defaults.baseURL);
      }
    }
  }, []);
  
  // Health status state
  const [healthStatus, setHealthStatus] = useState<any>(null);
  const [healthError, setHealthError] = useState<string | null>(null);
  const [healthLoading, setHealthLoading] = useState<boolean>(true);
  
  // Check health on load
  useEffect(() => {
    const checkHealth = async () => {
      setHealthLoading(true);
      try {
        const health = await apiService.get('/health');
        console.log('API Health:', health);
        setHealthStatus(health);
        setHealthError(null);
      } catch (err: any) {
        console.error('Error checking API health:', err);
        setHealthStatus(null);
        setHealthError(err.message || 'Failed to connect to API');
      } finally {
        setHealthLoading(false);
      }
    };
    
    checkHealth();
  }, []);
  
  // Check if user is authenticated on load
  useEffect(() => {
    const checkAuth = async () => {
      if (authToken) {
        try {
          const user = await authService.getCurrentUser();
          setCurrentUser(user);
        } catch (err) {
          console.error('Error checking auth:', err);
          localStorage.removeItem('authToken');
          setAuthToken(null);
        }
      }
    };
    
    checkAuth();
  }, [authToken]);
  
  // Define the subscribeToEvents function before using it
  const subscribeToEvents = useCallback(() => {
    // Unsubscribe if already subscribed
    if (eventSubscriptionId) {
      eventService.unsubscribe(eventSubscriptionId);
    }
    
    // Subscribe to system events
    const id = eventService.subscribe('system', '*', (event) => {
      setEvents(prev => [event, ...prev].slice(0, 20));
    });
    
    setEventSubscriptionId(id);
    console.log('Subscribed to system events with ID:', id);
  }, [eventSubscriptionId]);
  
  // Subscribe to events
  useEffect(() => {
    if (authToken && showEvents) {
      subscribeToEvents();
    }
    
    return () => {
      if (eventSubscriptionId) {
        eventService.unsubscribe(eventSubscriptionId);
      }
    };
  }, [authToken, showEvents, eventSubscriptionId, subscribeToEvents]);
  
  const testApi = async () => {
    setLoading(true);
    setError(null);
    try {
      console.log(`Testing API at: ${url}`);
      const result = await apiService.get(url);
      console.log('API test result:', result);
      setResponse(result);
    } catch (err: any) {
      console.error('API test error:', err);
      setError(err.message || 'Unknown error');
    } finally {
      setLoading(false);
    }
  };
  
  const login = async () => {
    setLoading(true);
    setError(null);
    try {
      const result = await authService.login({ username, password });
      console.log('Login result:', result);
      setResponse(result);
      
      if (result && result.token) {
        setAuthToken(result.token);
        setCurrentUser(result.user);
        setLoginStatus('Login successful');
      }
    } catch (err: any) {
      console.error('Login error:', err);
      setError(err.message || 'Login failed');
      setLoginStatus('Login failed');
    } finally {
      setLoading(false);
    }
  };
  
  const logout = async () => {
    setLoading(true);
    setError(null);
    try {
      await authService.logout();
      setAuthToken(null);
      setCurrentUser(null);
      setLoginStatus('Logged out');
      setResponse(null);
    } catch (err: any) {
      console.error('Logout error:', err);
      setError(err.message || 'Logout failed');
    } finally {
      setLoading(false);
    }
  };
  
  const refreshToken = async () => {
    setLoading(true);
    setError(null);
    try {
      const result = await authService.refreshToken();
      console.log('Token refresh result:', result);
      setResponse(result);
      setLoginStatus('Token refreshed');
    } catch (err: any) {
      console.error('Token refresh error:', err);
      setError(err.message || 'Token refresh failed');
    } finally {
      setLoading(false);
    }
  };
  
  const getRepositories = async () => {
    setLoading(true);
    setError(null);
    try {
      const repos = await repositoryService.getRepositories();
      console.log('Repositories:', repos);
      setRepositories(repos);
      setResponse(repos);
    } catch (err: any) {
      console.error('Get repositories error:', err);
      setError(err.message || 'Failed to get repositories');
    } finally {
      setLoading(false);
    }
  };
  
  const addRepository = async () => {
    setLoading(true);
    setError(null);
    try {
      const result = await repositoryService.addRepository(repoUrl, {
        deepAnalysis: true,
        includeDependencies: false
      });
      console.log('Add repository result:', result);
      setResponse(result);
      
      // Refresh repositories list
      getRepositories();
    } catch (err: any) {
      console.error('Add repository error:', err);
      setError(err.message || 'Failed to add repository');
    } finally {
      setLoading(false);
    }
  };
  
  const getRepositoryDetails = async (id: string) => {
    setLoading(true);
    setError(null);
    try {
      const repo = await repositoryService.getRepository(id);
      console.log('Repository details:', repo);
      setResponse(repo);
    } catch (err: any) {
      console.error('Get repository details error:', err);
      setError(err.message || 'Failed to get repository details');
    } finally {
      setLoading(false);
    }
  };
  
  const startAnalysis = async (id: string) => {
    setLoading(true);
    setError(null);
    try {
      const result = await repositoryService.analyzeRepository(id, {
        deepAnalysis: true,
        includeDependencies: false
      });
      console.log('Start analysis result:', result);
      setResponse(result);
    } catch (err: any) {
      console.error('Start analysis error:', err);
      setError(err.message || 'Failed to start analysis');
    } finally {
      setLoading(false);
    }
  };
  
  const getVulnerabilities = async (id: string) => {
    setLoading(true);
    setError(null);
    try {
      const vulns = await repositoryService.getVulnerabilities(id);
      console.log('Vulnerabilities:', vulns);
      setResponse(vulns);
    } catch (err: any) {
      console.error('Get vulnerabilities error:', err);
      setError(err.message || 'Failed to get vulnerabilities');
    } finally {
      setLoading(false);
    }
  };
  
  const getWorkflows = async () => {
    setLoading(true);
    setError(null);
    try {
      const result = await apiService.get('/workflows');
      console.log('Workflows:', result);
      setResponse(result);
    } catch (err: any) {
      console.error('Get workflows error:', err);
      setError(err.message || 'Failed to get workflows');
    } finally {
      setLoading(false);
    }
  };
  
  const getActiveWorkflows = async () => {
    setLoading(true);
    setError(null);
    try {
      const result = await apiService.get('/workflows/active');
      console.log('Active workflows:', result);
      setActiveWorkflows(result);
      setResponse(result);
    } catch (err: any) {
      console.error('Get active workflows error:', err);
      setError(err.message || 'Failed to get active workflows');
    } finally {
      setLoading(false);
    }
  };
  
  const getChatConversations = async () => {
    setLoading(true);
    setError(null);
    try {
      const result = await chatService.getChatSessions();
      console.log('Chat conversations:', result);
      setConversations(result);
      setResponse(result);
    } catch (err: any) {
      console.error('Get chat conversations error:', err);
      setError(err.message || 'Failed to get chat conversations');
    } finally {
      setLoading(false);
    }
  };
  
  const createConversation = async () => {
    setLoading(true);
    setError(null);
    try {
      const result = await chatService.createChatSession('New Conversation');
      console.log('Create conversation result:', result);
      setResponse(result);
      setSelectedConversationId(result.id);
      
      // Refresh conversations list
      getChatConversations();
    } catch (err: any) {
      console.error('Create conversation error:', err);
      setError(err.message || 'Failed to create conversation');
    } finally {
      setLoading(false);
    }
  };
  
  const getConversationMessages = async (id: string) => {
    setLoading(true);
    setError(null);
    try {
      const result = await chatService.getMessages(id);
      console.log('Conversation messages:', result);
      setConversationMessages(result);
      setResponse(result);
    } catch (err: any) {
      console.error('Get conversation messages error:', err);
      setError(err.message || 'Failed to get conversation messages');
    } finally {
      setLoading(false);
    }
  };
  
  const sendMessage = async () => {
    if (!selectedConversationId || !messageText) {
      setError('Please select a conversation and enter a message');
      return;
    }
    
    setLoading(true);
    setError(null);
    try {
      const result = await chatService.sendMessage(selectedConversationId, messageText);
      console.log('Send message result:', result);
      setResponse(result);
      setMessageText('');
      
      // Refresh messages
      getConversationMessages(selectedConversationId);
    } catch (err: any) {
      console.error('Send message error:', err);
      setError(err.message || 'Failed to send message');
    } finally {
      setLoading(false);
    }
  };
  
  return (
    <div style={{ padding: '20px', fontFamily: 'system-ui, sans-serif' }}>
      <h1>API Integration Test</h1>
      
      {/* API Health Status Section */}
      <div style={{ marginBottom: '30px', padding: '15px', border: '1px solid #ddd', borderRadius: '5px' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '10px' }}>
          <h2 style={{ margin: 0 }}>API Health Status</h2>
          <button 
            onClick={() => {
              const checkHealth = async () => {
                setHealthLoading(true);
                try {
                  const health = await apiService.get('/health');
                  console.log('API Health:', health);
                  setHealthStatus(health);
                  setHealthError(null);
                } catch (err: any) {
                  console.error('Error checking API health:', err);
                  setHealthStatus(null);
                  setHealthError(err.message || 'Failed to connect to API');
                } finally {
                  setHealthLoading(false);
                }
              };
              
              checkHealth();
            }}
            style={{ 
              padding: '5px 10px', 
              backgroundColor: '#007bff',
              color: 'white',
              border: 'none',
              borderRadius: '4px',
              cursor: 'pointer'
            }}
            disabled={healthLoading}
          >
            {healthLoading ? 'Checking...' : 'Check Health'}
          </button>
        </div>
        {healthLoading ? (
          <div style={{ padding: '10px', textAlign: 'center' }}>Checking API health...</div>
        ) : healthError ? (
          <div style={{ 
            padding: '10px', 
            backgroundColor: '#fdecea', 
            color: '#721c24', 
            border: '1px solid #f5c6cb',
            borderRadius: '4px'
          }}>
            <h3>API Connection Error</h3>
            <pre style={{ 
              whiteSpace: 'pre-wrap', 
              overflow: 'auto', 
              backgroundColor: '#f8d7da', 
              padding: '10px', 
              borderRadius: '4px'
            }}>
              {healthError}
            </pre>
            <button 
              onClick={() => window.location.reload()}
              style={{ 
                marginTop: '10px', 
                padding: '5px 10px', 
                backgroundColor: '#dc3545',
                color: 'white',
                border: 'none',
                borderRadius: '4px',
                cursor: 'pointer'
              }}
            >
              Retry Connection
            </button>
          </div>
        ) : healthStatus ? (
          <div>
            <div style={{ 
              display: 'flex', 
              alignItems: 'center', 
              marginBottom: '10px',
              padding: '10px',
              backgroundColor: healthStatus.status === 'healthy' ? '#d4edda' : healthStatus.status === 'degraded' ? '#fff3cd' : '#f8d7da',
              borderRadius: '4px'
            }}>
              <span style={{ 
                display: 'inline-block',
                width: '16px',
                height: '16px',
                borderRadius: '50%',
                marginRight: '10px',
                backgroundColor: healthStatus.status === 'healthy' ? '#28a745' : healthStatus.status === 'degraded' ? '#ffc107' : '#dc3545'
              }}></span>
              <span>
                <strong>Status: </strong>
                {healthStatus.status === 'healthy' ? 'Healthy' : healthStatus.status === 'degraded' ? 'Degraded' : 'Unhealthy'}
              </span>
              <button 
                onClick={() => window.location.reload()}
                style={{ 
                  marginLeft: 'auto', 
                  padding: '3px 8px', 
                  backgroundColor: 'transparent',
                  border: '1px solid #6c757d',
                  borderRadius: '4px',
                  cursor: 'pointer',
                  fontSize: '0.8rem'
                }}
              >
                Refresh
              </button>
            </div>
            
            {healthStatus.database && (
              <div style={{ marginBottom: '10px' }}>
                <h3>Database Status</h3>
                <div style={{ 
                  padding: '10px', 
                  backgroundColor: healthStatus.database.connected ? '#d4edda' : '#f8d7da',
                  borderRadius: '4px'
                }}>
                  <strong>Connection: </strong>
                  {healthStatus.database.connected ? 'Connected' : 'Disconnected'}
                  <div><strong>Message: </strong>{healthStatus.database.message}</div>
                </div>
              </div>
            )}
            
            {healthStatus.api_version && (
              <div style={{ marginBottom: '10px' }}>
                <strong>API Version: </strong>{healthStatus.api_version}
              </div>
            )}
            
            {healthStatus.timestamp && (
              <div>
                <strong>Timestamp: </strong>
                {new Date(healthStatus.timestamp).toLocaleString()}
              </div>
            )}
            
            {healthStatus.error && (
              <div style={{ 
                marginTop: '10px',
                padding: '10px', 
                backgroundColor: '#f8d7da', 
                borderRadius: '4px'
              }}>
                <h3>Error Details</h3>
                <pre style={{ whiteSpace: 'pre-wrap', overflow: 'auto' }}>
                  {healthStatus.error}
                </pre>
                {healthStatus.details && healthStatus.details.traceback && (
                  <details style={{ marginTop: '10px' }}>
                    <summary>Traceback</summary>
                    <pre style={{ 
                      whiteSpace: 'pre-wrap', 
                      overflow: 'auto',
                      backgroundColor: '#f8d7da',
                      padding: '10px',
                      marginTop: '5px',
                      fontSize: '0.8rem'
                    }}>
                      {healthStatus.details.traceback}
                    </pre>
                  </details>
                )}
              </div>
            )}
          </div>
        ) : (
          <div style={{ padding: '10px', textAlign: 'center' }}>No health information available</div>
        )}
      </div>
      
      <div style={{ display: 'flex', gap: '20px' }}>
        <div style={{ width: '60%' }}>
          {/* Authentication Section */}
          <div style={{ marginBottom: '30px', padding: '15px', border: '1px solid #ddd', borderRadius: '5px' }}>
            <h2>Authentication</h2>
            {authToken ? (
              <div>
                <div style={{ marginBottom: '10px' }}>
                  <strong>Status:</strong> Authenticated
                  {currentUser && (
                    <div>
                      <strong>User:</strong> {currentUser.username}
                      <div><strong>Roles:</strong> {currentUser.roles?.join(', ')}</div>
                    </div>
                  )}
                </div>
                <div style={{ display: 'flex', gap: '10px' }}>
                  <button 
                    onClick={logout}
                    disabled={loading}
                    style={{ padding: '5px 10px' }}
                  >
                    Logout
                  </button>
                  <button 
                    onClick={refreshToken}
                    disabled={loading}
                    style={{ padding: '5px 10px' }}
                  >
                    Refresh Token
                  </button>
                </div>
              </div>
            ) : (
              <div>
                <div style={{ marginBottom: '10px' }}>
                  <div style={{ marginBottom: '5px' }}>
                    <label style={{ display: 'block', marginBottom: '5px' }}>Username:</label>
                    <input 
                      type="text" 
                      value={username} 
                      onChange={(e) => setUsername(e.target.value)}
                      style={{ width: '200px', padding: '5px' }}
                    />
                  </div>
                  <div style={{ marginBottom: '10px' }}>
                    <label style={{ display: 'block', marginBottom: '5px' }}>Password:</label>
                    <input 
                      type="password" 
                      value={password} 
                      onChange={(e) => setPassword(e.target.value)}
                      style={{ width: '200px', padding: '5px' }}
                    />
                  </div>
                </div>
                <button 
                  onClick={login}
                  disabled={loading}
                  style={{ padding: '5px 10px' }}
                >
                  Login
                </button>
              </div>
            )}
            {loginStatus && (
              <div style={{ marginTop: '10px', color: loginStatus.includes('failed') ? 'red' : 'green' }}>
                {loginStatus}
              </div>
            )}
          </div>
          
          {/* Repository Section */}
          <div style={{ marginBottom: '30px', padding: '15px', border: '1px solid #ddd', borderRadius: '5px' }}>
            <h2>Repositories</h2>
            <div style={{ marginBottom: '10px' }}>
              <button 
                onClick={getRepositories}
                disabled={loading || !authToken}
                style={{ padding: '5px 10px', marginRight: '10px' }}
              >
                Get Repositories
              </button>
              
              <div style={{ marginTop: '10px' }}>
                <label style={{ display: 'block', marginBottom: '5px' }}>Repository URL:</label>
                <div style={{ display: 'flex', gap: '10px' }}>
                  <input 
                    type="text" 
                    value={repoUrl} 
                    onChange={(e) => setRepoUrl(e.target.value)}
                    style={{ flex: 1, padding: '5px' }}
                  />
                  <button 
                    onClick={addRepository}
                    disabled={loading || !authToken}
                    style={{ padding: '5px 10px' }}
                  >
                    Add Repository
                  </button>
                </div>
              </div>
            </div>
            
            {repositories.length > 0 && (
              <div>
                <h3>Repository List</h3>
                <div style={{ marginBottom: '10px' }}>
                  {repositories.map((repo) => (
                    <div key={repo.id} style={{ marginBottom: '5px', padding: '5px', border: '1px solid #eee', borderRadius: '3px' }}>
                      <div><strong>{repo.name}</strong> ({repo.id})</div>
                      <div style={{ marginTop: '5px' }}>
                        <button 
                          onClick={() => getRepositoryDetails(repo.id)}
                          disabled={loading}
                          style={{ padding: '3px 8px', marginRight: '5px', fontSize: '0.8rem' }}
                        >
                          Details
                        </button>
                        <button 
                          onClick={() => startAnalysis(repo.id)}
                          disabled={loading}
                          style={{ padding: '3px 8px', marginRight: '5px', fontSize: '0.8rem' }}
                        >
                          Analyze
                        </button>
                        <button 
                          onClick={() => getVulnerabilities(repo.id)}
                          disabled={loading}
                          style={{ padding: '3px 8px', fontSize: '0.8rem' }}
                        >
                          Vulnerabilities
                        </button>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
          
          {/* Workflow Section */}
          <div style={{ marginBottom: '30px', padding: '15px', border: '1px solid #ddd', borderRadius: '5px' }}>
            <h2>Workflows</h2>
            <div style={{ display: 'flex', gap: '10px', marginBottom: '10px' }}>
              <button 
                onClick={getWorkflows}
                disabled={loading || !authToken}
                style={{ padding: '5px 10px' }}
              >
                Get Workflows
              </button>
              <button 
                onClick={getActiveWorkflows}
                disabled={loading || !authToken}
                style={{ padding: '5px 10px' }}
              >
                Get Active Workflows
              </button>
            </div>
            
            {activeWorkflows.length > 0 && (
              <div>
                <h3>Active Workflows</h3>
                <div>
                  {activeWorkflows.map((workflow) => (
                    <div key={workflow.id} style={{ marginBottom: '5px', padding: '5px', border: '1px solid #eee', borderRadius: '3px' }}>
                      <div><strong>{workflow.name}</strong> ({workflow.id})</div>
                      <div>Status: {workflow.status}</div>
                      <div>Progress: {workflow.progress}%</div>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
          
          {/* Chat Section */}
          <div style={{ marginBottom: '30px', padding: '15px', border: '1px solid #ddd', borderRadius: '5px' }}>
            <h2>Chat</h2>
            <div style={{ display: 'flex', gap: '10px', marginBottom: '10px' }}>
              <button 
                onClick={getChatConversations}
                disabled={loading || !authToken}
                style={{ padding: '5px 10px' }}
              >
                Get Conversations
              </button>
              <button 
                onClick={createConversation}
                disabled={loading || !authToken}
                style={{ padding: '5px 10px' }}
              >
                Create Conversation
              </button>
            </div>
            
            {conversations.length > 0 && (
              <div style={{ display: 'flex', gap: '20px' }}>
                <div style={{ width: '40%' }}>
                  <h3>Conversations</h3>
                  <div>
                    {conversations.map((conv) => (
                      <div 
                        key={conv.id} 
                        style={{ 
                          marginBottom: '5px', 
                          padding: '5px', 
                          border: '1px solid #eee', 
                          borderRadius: '3px',
                          backgroundColor: selectedConversationId === conv.id ? '#f0f8ff' : 'transparent',
                          cursor: 'pointer'
                        }}
                        onClick={() => {
                          setSelectedConversationId(conv.id);
                          getConversationMessages(conv.id);
                        }}
                      >
                        <div><strong>{conv.title}</strong></div>
                        <div>Created: {new Date(conv.createdAt).toLocaleString()}</div>
                      </div>
                    ))}
                  </div>
                </div>
                
                {selectedConversationId && (
                  <div style={{ width: '60%' }}>
                    <h3>Messages</h3>
                    <div style={{ marginBottom: '10px' }}>
                      <div style={{ marginBottom: '5px' }}>
                        <textarea
                          value={messageText}
                          onChange={(e) => setMessageText(e.target.value)}
                          style={{ width: '100%', padding: '5px', minHeight: '80px' }}
                          placeholder="Type your message..."
                        />
                      </div>
                      <button 
                        onClick={sendMessage}
                        disabled={loading || !messageText}
                        style={{ padding: '5px 10px' }}
                      >
                        Send Message
                      </button>
                    </div>
                    
                    <div style={{ maxHeight: '300px', overflowY: 'auto', border: '1px solid #eee', borderRadius: '5px', padding: '10px' }}>
                      {conversationMessages.length === 0 ? (
                        <div style={{ fontStyle: 'italic', color: '#888' }}>No messages yet</div>
                      ) : (
                        conversationMessages.map((msg) => (
                          <div 
                            key={msg.id} 
                            style={{ 
                              marginBottom: '10px', 
                              padding: '8px', 
                              borderRadius: '5px',
                              backgroundColor: msg.role === 'user' ? '#e6f7ff' : '#f0f0f0',
                              maxWidth: '80%',
                              marginLeft: msg.role === 'user' ? 'auto' : '0'
                            }}
                          >
                            <div style={{ fontWeight: 'bold', marginBottom: '3px' }}>
                              {msg.role === 'user' ? 'You' : 'Assistant'}
                            </div>
                            <div>{msg.content}</div>
                            {msg.timestamp && (
                              <div style={{ fontSize: '0.8rem', marginTop: '5px', color: '#888' }}>
                                {new Date(msg.timestamp).toLocaleTimeString()}
                              </div>
                            )}
                          </div>
                        ))
                      )}
                    </div>
                  </div>
                )}
              </div>
            )}
          </div>
          
          {/* Custom API Test */}
          <div style={{ marginBottom: '30px', padding: '15px', border: '1px solid #ddd', borderRadius: '5px' }}>
            <h2>Custom API Test</h2>
            <div style={{ marginBottom: '10px' }}>
              <input 
                type="text" 
                value={url} 
                onChange={(e) => setUrl(e.target.value)}
                style={{ width: '300px', marginRight: '10px', padding: '5px' }}
              />
              <button 
                onClick={testApi}
                disabled={loading}
                style={{ padding: '5px 10px' }}
              >
                {loading ? 'Testing...' : 'Test API'}
              </button>
            </div>
            
            <div style={{ marginTop: '10px' }}>
              <h3>Common API Routes:</h3>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: '5px', marginBottom: '10px' }}>
                <button onClick={() => setUrl('/health')}>Health Check</button>
                <button onClick={() => setUrl('/auth/me')}>Get Current User</button>
                <button onClick={() => setUrl('/auth/refresh')}>Refresh Token</button>
                <button onClick={() => setUrl('/repositories')}>Get Repositories</button>
                <button onClick={() => setUrl('/workflows')}>Get Workflows</button>
                <button onClick={() => setUrl('/chat/conversations')}>Get Conversations</button>
              </div>
            </div>
          </div>
        </div>
        
        <div style={{ width: '40%' }}>
          {/* Response Section */}
          <div style={{ position: 'sticky', top: '20px' }}>
            <div style={{ marginBottom: '20px' }}>
              <h2>API Response</h2>
              {error && (
                <div style={{ color: 'red', marginBottom: '10px', padding: '10px', border: '1px solid #ffcccc', borderRadius: '5px', backgroundColor: '#fff8f8' }}>
                  Error: {error}
                </div>
              )}
              
              {loading && (
                <div style={{ padding: '20px', textAlign: 'center' }}>
                  Loading...
                </div>
              )}
              
              {response && (
                <div>
                  <pre style={{ 
                    background: '#f5f5f5', 
                    padding: '10px', 
                    borderRadius: '5px', 
                    maxHeight: '400px', 
                    overflow: 'auto',
                    marginTop: '10px' 
                  }}>
                    {JSON.stringify(response, null, 2)}
                  </pre>
                </div>
              )}
            </div>
            
            {/* Event Stream Section */}
            <div>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <h2>Event Stream</h2>
                <label>
                  <input 
                    type="checkbox" 
                    checked={showEvents} 
                    onChange={(e) => setShowEvents(e.target.checked)}
                  />
                  Enable Events
                </label>
              </div>
              
              <div style={{ 
                border: '1px solid #ddd', 
                borderRadius: '5px', 
                maxHeight: '400px', 
                overflowY: 'auto',
                backgroundColor: '#f9f9f9',
                padding: showEvents ? '10px' : '0'
              }}>
                {!showEvents ? (
                  <div style={{ padding: '10px', textAlign: 'center', fontStyle: 'italic' }}>
                    Event stream disabled
                  </div>
                ) : events.length === 0 ? (
                  <div style={{ padding: '10px', textAlign: 'center', fontStyle: 'italic' }}>
                    No events received yet
                  </div>
                ) : (
                  events.map((event, index) => (
                    <div 
                      key={index} 
                      style={{
                        padding: '8px',
                        marginBottom: '5px',
                        backgroundColor: 'white',
                        borderRadius: '3px',
                        border: '1px solid #eee',
                        fontSize: '0.9rem'
                      }}
                    >
                      <div style={{ marginBottom: '3px' }}>
                        <span style={{ fontWeight: 'bold', marginRight: '5px' }}>Type:</span>
                        <span>{event.type}</span>
                      </div>
                      <div>
                        <pre style={{ margin: 0, padding: '5px', backgroundColor: '#f5f5f5', borderRadius: '3px', fontSize: '0.8rem' }}>
                          {JSON.stringify(event.data, null, 2)}
                        </pre>
                      </div>
                      <div style={{ marginTop: '3px', fontSize: '0.8rem', color: '#888' }}>
                        {new Date(event.timestamp || Date.now()).toLocaleTimeString()}
                      </div>
                    </div>
                  ))
                )}
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default ApiTestPage;
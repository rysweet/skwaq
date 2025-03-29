# Skwaq API Reference

This document provides a comprehensive reference for the Skwaq API, including endpoint descriptions, request/response formats, and example usage.

## Updated API (v2)

The API has been rebuilt with a simpler, more maintainable structure using Flask. The new API endpoints are detailed below. This API is designed to integrate directly with the TypeScript/React frontend.

### Base URL

```
http://localhost:5001/api
```

For production deployments, use HTTPS and an appropriate domain name.

### Authentication

The API uses JWT token authentication. Include a bearer token in the `Authorization` header:

```
Authorization: Bearer your-token
```

JWT tokens are obtained through the `/api/auth/login` endpoint and must be included with all API requests except for health checks and authentication endpoints.

### Response Format

All API responses use JSON format. Errors follow a consistent structure:

```json
{
  "error": "Error message"
}
```

### Health Check

```
GET /api/health
```

Check the service health status.

**Response:**

```json
{
  "status": "healthy"
}
```

## Authentication Endpoints

### Login

```
POST /api/auth/login
```

Obtain a JWT token for API access.

**Request:**
```json
{
  "username": "admin",
  "password": "admin"
}
```

**Response:**
```json
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "user": {
    "id": "user-001",
    "username": "admin",
    "roles": ["admin"]
  }
}
```

### Logout

```
POST /api/auth/logout
```

Invalidate the current JWT token.

**Response:**
```json
{
  "message": "Successfully logged out"
}
```

### Get Current User

```
GET /api/auth/me
```

Get information about the currently authenticated user.

**Response:**
```json
{
  "user": {
    "id": "user-001",
    "username": "admin",
    "roles": ["admin"]
  }
}
```

### Refresh Token

```
POST /api/auth/refresh
```

Refresh the JWT token.

**Response:**
```json
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "user": {
    "id": "user-001",
    "username": "admin",
    "roles": ["admin"]
  }
}
```

## Repository Management

### Get All Repositories

```
GET /api/repositories
```

Get a list of all repositories.

**Response:**
```json
[
  {
    "id": "repo-123",
    "name": "test-repo",
    "description": "Test repository",
    "status": "Analyzed",
    "vulnerabilities": 5,
    "lastAnalyzed": "2025-03-28T12:00:00Z",
    "url": "https://github.com/test/repo"
  },
  {
    "id": "repo-456",
    "name": "another-repo",
    "description": "Another test repository",
    "status": "Analyzing",
    "vulnerabilities": null,
    "lastAnalyzed": null,
    "url": "https://github.com/test/another-repo"
  }
]
```

### Get Repository by ID

```
GET /api/repositories/{repo_id}
```

Get details of a specific repository.

**Response:**
```json
{
  "id": "repo-123",
  "name": "test-repo",
  "description": "Test repository",
  "status": "Analyzed",
  "progress": 100,
  "vulnerabilities": 5,
  "lastAnalyzed": "2025-03-28T12:00:00Z",
  "fileCount": 100,
  "url": "https://github.com/test/repo"
}
```

### Add Repository

```
POST /api/repositories
```

Add a new repository for analysis.

**Request:**
```json
{
  "url": "https://github.com/test/new-repo",
  "options": {
    "deepAnalysis": true,
    "includeDependencies": false
  }
}
```

**Response:**
```json
{
  "id": "new-repo-123",
  "name": "new-repo",
  "description": "Repository from https://github.com/test/new-repo",
  "status": "Initializing",
  "progress": 0,
  "vulnerabilities": null,
  "lastAnalyzed": null,
  "url": "https://github.com/test/new-repo"
}
```

### Delete Repository

```
DELETE /api/repositories/{repo_id}
```

Delete a repository.

**Response:** (204 No Content)

### Get Repository Vulnerabilities

```
GET /api/repositories/{repo_id}/vulnerabilities
```

Get all vulnerabilities found in a repository.

**Response:**
```json
[
  {
    "id": "vuln1",
    "name": "SQL Injection",
    "type": "Injection",
    "severity": "High",
    "file": "src/auth.py",
    "line": 42,
    "description": "Unsanitized user input used in SQL query",
    "cweId": "CWE-89",
    "remediation": "Use parameterized queries or prepared statements"
  },
  {
    "id": "vuln2",
    "name": "Cross-Site Scripting",
    "type": "XSS",
    "severity": "Medium",
    "file": "src/templates/index.html",
    "line": 23,
    "description": "Unescaped user data rendered in HTML",
    "cweId": "CWE-79",
    "remediation": "Use context-aware escaping for user data"
  }
]
```

### Start Repository Analysis

```
POST /api/repositories/{repo_id}/analyze
```

Start analysis for a repository.

**Request:**
```json
{
  "deepAnalysis": true,
  "includeDependencies": false
}
```

**Response:**
```json
{
  "repository": {
    "id": "repo-123",
    "name": "test-repo",
    "status": "Analyzing",
    "progress": 0
  },
  "task": {
    "id": "task-repo-123",
    "status": "running",
    "progress": 0
  }
}
```

### Cancel Repository Analysis

```
POST /api/repositories/{repo_id}/cancel
```

Cancel ongoing repository analysis.

**Response:** (204 No Content)

### Get Analysis Status

```
GET /api/repositories/{repo_id}/analysis/status
```

Get the status of ongoing repository analysis.

**Response:**
```json
{
  "repoId": "repo-123",
  "status": "Analyzing",
  "analysis": {
    "taskId": "task-repo-123",
    "startTime": "2025-03-28T12:00:00Z",
    "status": "running",
    "progress": 50
  }
}
```

## Workflow Management

### Get All Workflows

```
GET /api/workflows
```

Get a list of all available workflow types.

**Response:**
```json
[
  {
    "id": "workflow-vuln-assess",
    "name": "Vulnerability Assessment",
    "description": "Assess a repository for common security vulnerabilities",
    "type": "vulnerability_assessment",
    "parameters": [
      {
        "name": "deepScan",
        "type": "boolean",
        "default": false,
        "description": "Perform a deep scan of the codebase"
      },
      {
        "name": "includeDependencies",
        "type": "boolean",
        "default": true,
        "description": "Include dependencies in the analysis"
      }
    ]
  },
  {
    "id": "workflow-guided-inquiry",
    "name": "Guided Inquiry",
    "description": "Interactive repository exploration with a focus on security",
    "type": "guided_inquiry",
    "parameters": [
      {
        "name": "prompt",
        "type": "string",
        "default": "",
        "description": "Initial prompt to guide the inquiry"
      }
    ]
  }
]
```

### Get Workflow by ID

```
GET /api/workflows/{workflow_id}
```

Get details of a specific workflow type.

**Response:**
```json
{
  "id": "workflow-vuln-assess",
  "name": "Vulnerability Assessment",
  "description": "Assess a repository for common security vulnerabilities",
  "type": "vulnerability_assessment",
  "parameters": [
    {
      "name": "deepScan",
      "type": "boolean",
      "default": false,
      "description": "Perform a deep scan of the codebase"
    },
    {
      "name": "includeDependencies",
      "type": "boolean",
      "default": true,
      "description": "Include dependencies in the analysis"
    }
  ]
}
```

### Get Repository Workflows

```
GET /api/workflows/repository/{repo_id}
```

Get all workflow executions for a specific repository.

**Response:**
```json
[
  {
    "id": "exec-123",
    "workflowType": "vulnerability_assessment",
    "workflowName": "Vulnerability Assessment",
    "repositoryId": "repo-123",
    "status": "running",
    "progress": 50,
    "parameters": {"deepScan": true},
    "startTime": "2025-03-28T12:00:00Z",
    "endTime": null,
    "resultsAvailable": false
  },
  {
    "id": "exec-456",
    "workflowType": "guided_inquiry",
    "workflowName": "Guided Inquiry",
    "repositoryId": "repo-123",
    "status": "completed",
    "progress": 100,
    "parameters": {"prompt": "find authentication issues"},
    "startTime": "2025-03-27T12:00:00Z",
    "endTime": "2025-03-27T12:15:00Z",
    "resultsAvailable": true
  }
]
```

### Get Workflow Execution

```
GET /api/workflows/execution/{execution_id}
```

Get details of a specific workflow execution.

**Response:**
```json
{
  "id": "exec-123",
  "workflowType": "vulnerability_assessment",
  "workflowName": "Vulnerability Assessment",
  "repositoryId": "repo-123",
  "status": "running",
  "progress": 50,
  "parameters": {"deepScan": true},
  "startTime": "2025-03-28T12:00:00Z",
  "endTime": null,
  "resultsAvailable": false
}
```

### Execute Workflow

```
POST /api/workflows/execute
```

Execute a workflow on a repository.

**Request:**
```json
{
  "workflowType": "vulnerability_assessment",
  "repositoryId": "repo-123",
  "parameters": {
    "deepScan": true,
    "includeDependencies": false
  }
}
```

**Response:**
```json
{
  "executionId": "exec-789",
  "workflowType": "vulnerability_assessment",
  "status": "queued",
  "repositoryId": "repo-123",
  "parameters": {
    "deepScan": true,
    "includeDependencies": false
  },
  "message": "Workflow vulnerability_assessment started for repository repo-123"
}
```

### Cancel Workflow Execution

```
POST /api/workflows/execution/{execution_id}/cancel
```

Cancel a workflow execution.

**Response:**
```json
{
  "id": "exec-123",
  "workflowType": "vulnerability_assessment",
  "status": "cancelled",
  "progress": 50,
  "repositoryId": "repo-123"
}
```

### Get Workflow Results

```
GET /api/workflows/execution/{execution_id}/results
```

Get results of a completed workflow execution.

**Response:**
```json
{
  "executionId": "exec-456",
  "status": "completed",
  "results": {
    "summary": "Workflow execution completed successfully",
    "findings": [
      {
        "id": "finding-001",
        "type": "vulnerability",
        "severity": "high",
        "title": "SQL Injection Vulnerability",
        "description": "Unsanitized user input used directly in SQL query",
        "location": "src/database.py:42",
        "remediation": "Use parameterized queries to prevent SQL injection"
      }
    ],
    "metrics": {
      "filesAnalyzed": 125,
      "linesOfCode": 15420,
      "analysisTime": 45.2,
      "findingsCount": 1
    }
  }
}
```

## Chat

### Get All Conversations

```
GET /api/chat/conversations
```

Get all chat conversations for the current user.

**Response:**
```json
[
  {
    "id": "conv-123",
    "title": "Test Conversation",
    "userId": "user-001",
    "createdAt": "2025-03-28T12:00:00Z",
    "updatedAt": "2025-03-28T12:15:00Z",
    "messageCount": 3,
    "lastMessageTime": "2025-03-28T12:05:10Z"
  }
]
```

### Get Conversation

```
GET /api/chat/conversations/{conversation_id}
```

Get details and messages for a specific chat conversation.

**Response:**
```json
{
  "id": "conv-123",
  "title": "Test Conversation",
  "userId": "user-001",
  "createdAt": "2025-03-28T12:00:00Z",
  "updatedAt": "2025-03-28T12:15:00Z",
  "context": {},
  "messages": [
    {
      "id": "msg-1",
      "conversationId": "conv-123",
      "userId": "system",
      "sender": "system",
      "content": "Welcome to the conversation",
      "timestamp": "2025-03-28T12:00:00Z"
    },
    {
      "id": "msg-2",
      "conversationId": "conv-123",
      "userId": "user-001",
      "sender": "user",
      "content": "Hello system",
      "timestamp": "2025-03-28T12:05:00Z"
    },
    {
      "id": "msg-3",
      "conversationId": "conv-123",
      "userId": "assistant",
      "sender": "assistant",
      "content": "Hello! How can I help you?",
      "timestamp": "2025-03-28T12:05:10Z"
    }
  ],
  "messageCount": 3
}
```

### Create Conversation

```
POST /api/chat/conversations
```

Create a new chat conversation.

**Request:**
```json
{
  "title": "New Conversation",
  "context": {}
}
```

**Response:**
```json
{
  "id": "conv-new",
  "title": "New Conversation",
  "userId": "user-001",
  "createdAt": "2025-03-28T13:00:00Z",
  "updatedAt": "2025-03-28T13:00:00Z",
  "context": {},
  "messages": [
    {
      "id": "msg-welcome",
      "conversationId": "conv-new",
      "userId": "system",
      "sender": "system",
      "content": "Hello! I'm your vulnerability research assistant. How can I help you today?",
      "timestamp": "2025-03-28T13:00:00Z"
    }
  ],
  "messageCount": 1
}
```

### Delete Conversation

```
DELETE /api/chat/conversations/{conversation_id}
```

Delete a chat conversation.

**Response:** (204 No Content)

### Get Messages

```
GET /api/chat/conversations/{conversation_id}/messages
```

Get all messages for a specific chat conversation.

**Response:**
```json
[
  {
    "id": "msg-1",
    "conversationId": "conv-123",
    "userId": "system",
    "sender": "system",
    "content": "Welcome to the conversation",
    "timestamp": "2025-03-28T12:00:00Z"
  },
  {
    "id": "msg-2",
    "conversationId": "conv-123",
    "userId": "user-001",
    "sender": "user",
    "content": "Hello system",
    "timestamp": "2025-03-28T12:05:00Z"
  },
  {
    "id": "msg-3",
    "conversationId": "conv-123",
    "userId": "assistant",
    "sender": "assistant",
    "content": "Hello! How can I help you?",
    "timestamp": "2025-03-28T12:05:10Z"
  }
]
```

### Send Message

```
POST /api/chat/conversations/{conversation_id}/messages
```

Send a new message in a chat conversation.

**Request:**
```json
{
  "content": "I need help with security analysis"
}
```

**Response:**
```json
{
  "id": "msg-4",
  "conversationId": "conv-123",
  "userId": "user-001",
  "sender": "user",
  "content": "I need help with security analysis",
  "timestamp": "2025-03-28T12:10:00Z"
}
```

## Real-time Events

The API supports real-time updates via Server-Sent Events (SSE).

### Connect to Event Stream

```
GET /api/events/{channel}/connect
```

Connect to a specific event channel for real-time updates.

**Supported Channels:**
- `repository` - Repository-related events
- `analysis` - Analysis-related events
- `chat` - Chat-related events
- `system` - System-related events
- `workflow` - Workflow-related events

The response is an SSE stream that provides real-time updates.

**Example Events:**
```
event: connection
data: {"connected": true, "channel": "repository", "clientId": "client-123"}

event: repository_added
data: {"id": "repo-123", "name": "test-repo", "status": "Initializing"}

event: workflow_progress
data: {"executionId": "exec-123", "status": "running", "progress": 50, "message": "Processing 50% complete"}

event: message_sent
data: {"conversationId": "conv-123", "messageId": "msg-4", "sender": "assistant", "content": "I can help you with security analysis!"}
```

## Error Codes

Common HTTP error codes returned by the API:

| Code | Description |
|------|-------------|
| 400 | Bad Request - Invalid input parameters |
| 401 | Unauthorized - Authentication required or failed |
| 403 | Forbidden - Insufficient permissions |
| 404 | Not Found - Resource not found |
| 409 | Conflict - Resource already exists |
| 500 | Internal Server Error - Server error |

## Examples

### Example 1: Authenticate and List Repositories

```bash
# Login to get a token
TOKEN=$(curl -s -X POST http://localhost:5001/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "admin"}' | jq -r '.token')

# List repositories
curl -s -X GET http://localhost:5001/api/repositories \
  -H "Authorization: Bearer $TOKEN"
```

### Example 2: Add a Repository and Start Analysis

```bash
# Add a repository
REPO_RESPONSE=$(curl -s -X POST http://localhost:5001/api/repositories \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "url": "https://github.com/test/new-repo",
    "options": {
      "deepAnalysis": true,
      "includeDependencies": false
    }
  }')

# Extract repository ID
REPO_ID=$(echo $REPO_RESPONSE | jq -r '.id')

# Start analysis
curl -s -X POST http://localhost:5001/api/repositories/$REPO_ID/analyze \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "deepAnalysis": true,
    "includeDependencies": false
  }'
```

### Example 3: Create a Chat Conversation

```bash
# Create a conversation
CONV_RESPONSE=$(curl -s -X POST http://localhost:5001/api/chat/conversations \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "title": "Security Analysis Session"
  }')

# Extract conversation ID
CONV_ID=$(echo $CONV_RESPONSE | jq -r '.id')

# Send a message
curl -s -X POST http://localhost:5001/api/chat/conversations/$CONV_ID/messages \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "content": "What are common security vulnerabilities in Python web applications?"
  }'
```

### Example 4: Monitor Events with Server-Sent Events

```javascript
// JavaScript example for connecting to SSE stream
const eventSource = new EventSource('http://localhost:5001/api/events/repository/connect', {
  headers: {
    'Authorization': `Bearer ${token}`
  },
  withCredentials: true
});

eventSource.addEventListener('connection', event => {
  const data = JSON.parse(event.data);
  console.log('Connected to event stream', data);
});

eventSource.addEventListener('repository_added', event => {
  const data = JSON.parse(event.data);
  console.log('Repository added', data);
});

eventSource.addEventListener('workflow_progress', event => {
  const data = JSON.parse(event.data);
  console.log('Workflow progress update', data);
});

eventSource.onerror = error => {
  console.error('Error in event stream', error);
  eventSource.close();
};
```
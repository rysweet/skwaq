# Frontend Integration Guide

This guide provides instructions for testing and verifying the integration between the TypeScript frontend and the new Flask API.

## Setup

1. Start the development environment:

```bash
./scripts/dev/run-dev.sh
```

This will start both the Flask API (port 5001) and the React frontend (port 3000).

2. Open your browser to the API test page:

```
http://localhost:3000/api-test
```

## Testing the API Integration

The API test page provides a comprehensive interface for testing all API endpoints. Use this page to verify the correct functionality of the integration between the frontend and backend.

### Authentication

1. **Login**: Enter username/password (default: admin/admin) and click "Login"
2. **Refresh Token**: Click "Refresh Token" to test token refresh
3. **Logout**: Click "Logout" to end the session

### Repository Management

1. **List Repositories**: Click "Get Repositories" to fetch all repositories
2. **Add Repository**: Enter a repository URL and click "Add Repository"
3. **Repository Details**: Click "Details" on a repository to view its properties
4. **Start Analysis**: Click "Analyze" on a repository to begin analysis
5. **View Vulnerabilities**: Click "Vulnerabilities" to view security findings

### Workflow Management

1. **List Workflows**: Click "Get Workflows" to see available workflows
2. **View Active Workflows**: Click "Get Active Workflows" to see running workflows

### Chat System

1. **List Conversations**: Click "Get Conversations" to view chat sessions
2. **Create Conversation**: Click "Create Conversation" to start a new chat
3. **View Messages**: Click on a conversation to see its messages
4. **Send Message**: Type a message and click "Send Message"

### Event Streaming

The right panel shows real-time events from the server. You can:

1. **Toggle Events**: Check/uncheck "Enable Events" to control SSE subscription
2. **Monitor Events**: Watch for real-time updates from all system activities

## Troubleshooting

### API Connection Issues

- Verify the API is running on port 5001
- Check browser console for CORS errors
- Ensure the API base URL is set correctly in the frontend

### Authentication Problems

- Check token expiration (default is 30 minutes)
- Verify token format in requests
- Check for proper token renewal

### Event Stream Issues

- Events require an authenticated session
- Some browsers limit SSE connections
- Check the server logs for connection errors

## API Endpoints Reference

### Authentication

- `POST /api/auth/login` - Authenticate and get a token
- `POST /api/auth/logout` - End the current session
- `GET /api/auth/me` - Get current user information
- `POST /api/auth/refresh` - Refresh authentication token

### Repositories

- `GET /api/repositories` - List all repositories
- `POST /api/repositories` - Add a new repository
- `GET /api/repositories/{id}` - Get repository details
- `DELETE /api/repositories/{id}` - Delete a repository
- `POST /api/repositories/{id}/analyze` - Start analysis
- `GET /api/repositories/{id}/vulnerabilities` - Get vulnerabilities
- `POST /api/repositories/{id}/cancel` - Cancel ongoing analysis

### Workflows

- `GET /api/workflows` - List available workflows
- `GET /api/workflows/active` - Get active workflows
- `POST /api/workflows/{id}/start` - Start a workflow
- `GET /api/workflows/{id}/status` - Get workflow status
- `GET /api/workflows/{id}/results` - Get workflow results
- `POST /api/workflows/{id}/stop` - Stop a workflow

### Chat

- `GET /api/chat/conversations` - List conversations
- `POST /api/chat/conversations` - Create a conversation
- `GET /api/chat/conversations/{id}` - Get conversation details
- `DELETE /api/chat/conversations/{id}` - Delete a conversation
- `GET /api/chat/conversations/{id}/messages` - Get messages
- `POST /api/chat/conversations/{id}/messages` - Send a message
- `POST /api/chat/conversations/{id}/stream` - Stream a response

### Events

- `GET /api/events/system` - Subscribe to system events
- `GET /api/events/repository` - Subscribe to repository events
- `GET /api/events/workflow` - Subscribe to workflow events
- `GET /api/events/chat` - Subscribe to chat events
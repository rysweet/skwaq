# API Specification

## Overview

This document specifies the REST API for the Skwaq Vulnerability Assessment Copilot. The API provides integration between the TypeScript frontend and the Python backend, enabling the frontend to access the same functionality available through the CLI.

## Requirements

The API must meet the following requirements:

1. Provide a RESTful interface that matches the expectations of the existing TypeScript frontend
2. Authenticate users using JWT tokens with bearer authentication
3. Return real data from the system (not mock data)
4. Provide real-time updates using Server-Sent Events (SSE)
5. Share code with the CLI where possible to maintain consistency
6. Support all operations needed by the frontend including:
   - Authentication (login, logout, token refresh)
   - Repository management (list, add, delete, analyze)
   - Workflow execution and monitoring
   - Chat functionality
   - Knowledge graph exploration
   - Events and real-time updates

## Authentication

The API uses JWT (JSON Web Token) for authentication with the following endpoints:

- `POST /api/auth/login`: Authenticate with username/password and receive a JWT token
- `POST /api/auth/logout`: Invalidate the current token
- `GET /api/auth/me`: Get current user information
- `POST /api/auth/refresh`: Refresh the JWT token

Authentication is enforced using a `login_required` decorator on protected endpoints. The JWT token is passed in the `Authorization` header using the Bearer scheme.

## API Endpoints

### Authentication Endpoints

#### Login

- **URL**: `/api/auth/login`
- **Method**: `POST`
- **Auth Required**: No
- **Request Body**:
  ```json
  {
    "username": "string",
    "password": "string"
  }
  ```
- **Response**:
  ```json
  {
    "token": "string",
    "user": {
      "id": "string",
      "username": "string",
      "roles": ["string"]
    }
  }
  ```

#### Logout

- **URL**: `/api/auth/logout`
- **Method**: `POST`
- **Auth Required**: Yes
- **Response**:
  ```json
  {
    "message": "Successfully logged out"
  }
  ```

#### Get Current User

- **URL**: `/api/auth/me`
- **Method**: `GET`
- **Auth Required**: Yes
- **Response**:
  ```json
  {
    "user": {
      "id": "string",
      "username": "string",
      "roles": ["string"]
    }
  }
  ```

#### Refresh Token

- **URL**: `/api/auth/refresh`
- **Method**: `POST`
- **Auth Required**: Yes
- **Response**:
  ```json
  {
    "token": "string",
    "user": {
      "id": "string",
      "username": "string",
      "roles": ["string"]
    }
  }
  ```

### Repository Endpoints

#### List Repositories

- **URL**: `/api/repositories`
- **Method**: `GET`
- **Auth Required**: Yes
- **Response**:
  ```json
  [
    {
      "id": "string",
      "name": "string",
      "description": "string",
      "status": "Analyzing | Analyzed | Failed",
      "vulnerabilities": "number | null",
      "lastAnalyzed": "string | null",
      "url": "string"
    }
  ]
  ```

#### Get Repository

- **URL**: `/api/repositories/{id}`
- **Method**: `GET`
- **Auth Required**: Yes
- **Response**:
  ```json
  {
    "id": "string",
    "name": "string",
    "description": "string",
    "status": "Analyzing | Analyzed | Failed",
    "progress": "number",
    "vulnerabilities": "number | null",
    "lastAnalyzed": "string | null",
    "fileCount": "number",
    "url": "string"
  }
  ```

#### Add Repository

- **URL**: `/api/repositories`
- **Method**: `POST`
- **Auth Required**: Yes
- **Request Body**:
  ```json
  {
    "url": "string",
    "options": {
      "deepAnalysis": "boolean",
      "includeDependencies": "boolean"
    }
  }
  ```
- **Response**:
  ```json
  {
    "id": "string",
    "name": "string",
    "description": "string",
    "status": "Initializing",
    "vulnerabilities": null,
    "lastAnalyzed": null,
    "url": "string"
  }
  ```

#### Analyze Repository

- **URL**: `/api/repositories/{id}/analyze`
- **Method**: `POST`
- **Auth Required**: Yes
- **Request Body**:
  ```json
  {
    "deepAnalysis": "boolean",
    "includeDependencies": "boolean"
  }
  ```
- **Response**:
  ```json
  {
    "repository": {
      "id": "string",
      "name": "string",
      "description": "string",
      "status": "Analyzing",
      "vulnerabilities": "number | null",
      "lastAnalyzed": "string | null",
      "url": "string"
    },
    "task": {
      "id": "string",
      "status": "running",
      "progress": 0
    }
  }
  ```

#### Delete Repository

- **URL**: `/api/repositories/{id}`
- **Method**: `DELETE`
- **Auth Required**: Yes
- **Response**: `204 No Content`

#### Get Repository Vulnerabilities

- **URL**: `/api/repositories/{id}/vulnerabilities`
- **Method**: `GET`
- **Auth Required**: Yes
- **Response**:
  ```json
  [
    {
      "id": "string",
      "name": "string",
      "type": "string",
      "severity": "string",
      "file": "string",
      "line": "number",
      "description": "string",
      "cweId": "string",
      "remediation": "string"
    }
  ]
  ```

#### Cancel Repository Analysis

- **URL**: `/api/repositories/{id}/cancel`
- **Method**: `POST`
- **Auth Required**: Yes
- **Response**: `204 No Content`

#### Get Analysis Status

- **URL**: `/api/repositories/{id}/analysis/status`
- **Method**: `GET`
- **Auth Required**: Yes
- **Response**:
  ```json
  {
    "repoId": "string",
    "status": "string",
    "analysis": {
      "taskId": "string",
      "startTime": "string",
      "status": "string",
      "progress": "number"
    }
  }
  ```

### Workflow Endpoints

#### Get Available Workflows

- **URL**: `/api/workflows`
- **Method**: `GET`
- **Auth Required**: Yes
- **Response**:
  ```json
  [
    {
      "id": "string",
      "name": "string",
      "description": "string",
      "parameters": [
        {
          "name": "string",
          "type": "string",
          "required": "boolean",
          "description": "string",
          "default": "any"
        }
      ]
    }
  ]
  ```

#### Get Available Tools

- **URL**: `/api/workflows/tools`
- **Method**: `GET`
- **Auth Required**: Yes
- **Response**:
  ```json
  [
    {
      "id": "string",
      "name": "string",
      "description": "string",
      "parameters": [
        {
          "name": "string",
          "type": "string",
          "required": "boolean",
          "description": "string"
        }
      ]
    }
  ]
  ```

#### Start Workflow

- **URL**: `/api/workflows/{workflowId}/start`
- **Method**: `POST`
- **Auth Required**: Yes
- **Request Body**:
  ```json
  {
    "repository_id": "string",
    "focus_areas": ["string"],
    "workflow_id": "string",
    "enable_persistence": "boolean",
    "repository_path": "string"
  }
  ```
- **Response**:
  ```json
  {
    "workflow_id": "string",
    "status": "pending"
  }
  ```

#### Get Workflow Status

- **URL**: `/api/workflows/{workflowId}/status`
- **Method**: `GET`
- **Auth Required**: Yes
- **Response**:
  ```json
  {
    "id": "string",
    "name": "string",
    "status": "pending | running | completed | failed",
    "progress": "number",
    "started_at": "string",
    "updated_at": "string",
    "completed_at": "string | null",
    "error": "string | null"
  }
  ```

#### Get Workflow Results

- **URL**: `/api/workflows/{workflowId}/results`
- **Method**: `GET`
- **Auth Required**: Yes
- **Response**:
  ```json
  [
    {
      "workflow_id": "string",
      "step_name": "string | null",
      "status": "string",
      "progress": "number",
      "data": "any",
      "errors": ["string"] | null
    }
  ]
  ```

#### Stop Workflow

- **URL**: `/api/workflows/{workflowId}/stop`
- **Method**: `POST`
- **Auth Required**: Yes
- **Response**:
  ```json
  {
    "status": "success",
    "message": "string"
  }
  ```

#### Get Active Workflows

- **URL**: `/api/workflows/active`
- **Method**: `GET`
- **Auth Required**: Yes
- **Response**:
  ```json
  [
    {
      "id": "string",
      "name": "string",
      "status": "pending | running | completed | failed",
      "progress": "number",
      "started_at": "string",
      "updated_at": "string"
    }
  ]
  ```

#### Get Workflow History

- **URL**: `/api/workflows/history`
- **Method**: `GET`
- **Auth Required**: Yes
- **Query Parameters**:
  - `limit`: Number of workflows to return (default: 10)
  - `offset`: Offset for pagination (default: 0)
- **Response**:
  ```json
  [
    {
      "id": "string",
      "name": "string",
      "status": "pending | running | completed | failed",
      "progress": "number",
      "started_at": "string",
      "updated_at": "string",
      "completed_at": "string | null"
    }
  ]
  ```

#### Invoke Tool

- **URL**: `/api/workflows/tools/{toolId}/invoke`
- **Method**: `POST`
- **Auth Required**: Yes
- **Request Body**: Parameters specific to the tool
- **Response**:
  ```json
  {
    "execution_id": "string"
  }
  ```

#### Get Tool Results

- **URL**: `/api/workflows/tools/executions/{executionId}`
- **Method**: `GET`
- **Auth Required**: Yes
- **Response**: Tool-specific result

### Chat Endpoints

#### Get Chat Sessions

- **URL**: `/api/chat/sessions`
- **Method**: `GET`
- **Auth Required**: Yes
- **Response**:
  ```json
  [
    {
      "id": "string",
      "title": "string",
      "messages": [
        {
          "id": "number",
          "role": "user | system",
          "content": "string",
          "timestamp": "string",
          "parentId": "number | null",
          "threadId": "number | null"
        }
      ],
      "createdAt": "string"
    }
  ]
  ```

#### Get Chat Session

- **URL**: `/api/chat/sessions/{id}`
- **Method**: `GET`
- **Auth Required**: Yes
- **Response**:
  ```json
  {
    "id": "string",
    "title": "string",
    "messages": [
      {
        "id": "number",
        "role": "user | system",
        "content": "string",
        "timestamp": "string",
        "parentId": "number | null",
        "threadId": "number | null"
      }
    ],
    "createdAt": "string"
  }
  ```

#### Create Chat Session

- **URL**: `/api/chat/sessions`
- **Method**: `POST`
- **Auth Required**: Yes
- **Request Body**:
  ```json
  {
    "title": "string"
  }
  ```
- **Response**:
  ```json
  {
    "id": "string",
    "title": "string",
    "messages": [],
    "createdAt": "string"
  }
  ```

#### Send Message

- **URL**: `/api/chat/sessions/{id}/messages`
- **Method**: `POST`
- **Auth Required**: Yes
- **Request Body**:
  ```json
  {
    "content": "string"
  }
  ```
- **Response**:
  ```json
  {
    "id": "number",
    "role": "user",
    "content": "string",
    "timestamp": "string"
  }
  ```

#### Delete Chat Session

- **URL**: `/api/chat/sessions/{id}`
- **Method**: `DELETE`
- **Auth Required**: Yes
- **Response**: `204 No Content`

#### Get Messages

- **URL**: `/api/chat/sessions/{id}/messages`
- **Method**: `GET`
- **Auth Required**: Yes
- **Response**:
  ```json
  [
    {
      "id": "number",
      "role": "user | system",
      "content": "string",
      "timestamp": "string",
      "parentId": "number | null",
      "threadId": "number | null"
    }
  ]
  ```

#### Stream Chat Response

- **URL**: `/api/chat/sessions/{id}/stream`
- **Method**: `POST`
- **Auth Required**: Yes
- **Request Body**:
  ```json
  {
    "content": "string"
  }
  ```
- **Response**: Server-Sent Events (SSE) stream

### Event Endpoints

#### Connect to Event Stream

- **URL**: `/api/events/{channel}/connect`
- **Method**: `GET`
- **Auth Required**: Yes
- **Response**: Server-Sent Events (SSE) stream
- **Channels**:
  - `repository`: Repository-related events
  - `analysis`: Analysis-related events
  - `chat`: Chat-related events
  - `system`: System-wide events

## Real-time Updates

The API provides real-time updates using Server-Sent Events (SSE). Clients can connect to event streams for specific channels and receive updates as they occur.

## Error Handling

The API uses standard HTTP status codes to indicate errors:

- 400: Bad Request - The request was malformed or invalid
- 401: Unauthorized - Authentication is required or failed
- 403: Forbidden - The authenticated user does not have permission
- 404: Not Found - The requested resource does not exist
- 409: Conflict - The request conflicts with the current state
- 500: Internal Server Error - An error occurred on the server

Error responses include a JSON object with details:

```json
{
  "error": "string",
  "message": "string"
}
```

## Data Models

### Repository

```json
{
  "id": "string",
  "name": "string",
  "description": "string",
  "status": "Analyzing | Analyzed | Failed",
  "vulnerabilities": "number | null",
  "lastAnalyzed": "string | null",
  "url": "string"
}
```

### Workflow

```json
{
  "id": "string",
  "name": "string",
  "status": "pending | running | completed | failed",
  "progress": "number",
  "started_at": "string",
  "updated_at": "string",
  "completed_at": "string | null",
  "error": "string | null"
}
```

### Chat Session

```json
{
  "id": "string",
  "title": "string",
  "messages": [
    {
      "id": "number",
      "role": "user | system",
      "content": "string",
      "timestamp": "string",
      "parentId": "number | null",
      "threadId": "number | null"
    }
  ],
  "createdAt": "string"
}
```

## Implementation Considerations

1. The API should use Flask as the web framework
2. Authentication should be implemented using JWT tokens
3. Database access should be abstracted through a data access layer
4. Code should be shared with CLI where possible
5. Asynchronous tasks should be handled appropriately
6. Proper error handling and logging should be implemented
7. Endpoints should be tested thoroughly
8. Documentation should be generated using OpenAPI/Swagger
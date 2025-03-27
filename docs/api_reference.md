# Skwaq API Reference

This document provides a comprehensive reference for the Skwaq API, including endpoint descriptions, request/response formats, and example usage.

## API Basics

### Base URL

```
http://localhost:8000/api/v1
```

For production deployments, use HTTPS and an appropriate domain name.

### Authentication

The API supports multiple authentication methods:

#### API Key Authentication

Include the API key in the `X-API-Key` header:

```
X-API-Key: your-api-key
```

#### Bearer Token Authentication

Include a bearer token in the `Authorization` header:

```
Authorization: Bearer your-token
```

### Response Format

All API responses use JSON format with the following structure:

```json
{
  "status": "success",
  "data": {
    // Response data specific to the endpoint
  },
  "message": "Optional human-readable message"
}
```

For error responses:

```json
{
  "status": "error",
  "error": {
    "code": "ERROR_CODE",
    "message": "Human-readable error message"
  }
}
```

### Pagination

For endpoints that return lists, pagination is supported with the following query parameters:

- `page`: Page number (1-based indexing)
- `per_page`: Number of items per page (default: 20, max: 100)

Example:

```
GET /api/v1/repositories?page=2&per_page=50
```

Paginated responses include metadata:

```json
{
  "status": "success",
  "data": [...],
  "pagination": {
    "page": 2,
    "per_page": 50,
    "total_items": 320,
    "total_pages": 7
  }
}
```

## Endpoints

### Health Check

```
GET /health
```

Check the service health status.

**Response:**

```json
{
  "status": "healthy",
  "components": {
    "api": "healthy",
    "database": "healthy",
    "openai": "healthy"
  },
  "version": "1.0.0"
}
```

### Repositories

#### List Repositories

```
GET /api/v1/repositories
```

List all ingested repositories.

**Query Parameters:**

- `page`: Page number
- `per_page`: Items per page
- `order_by`: Field to order by (default: "ingested_at")
- `order`: Order direction ("asc" or "desc")

**Response:**

```json
{
  "status": "success",
  "data": [
    {
      "id": 1,
      "name": "example-repo",
      "url": "https://github.com/example/repo",
      "path": "/local/path/to/repo",
      "ingested_at": "2025-01-15T14:30:00Z",
      "file_count": 250,
      "code_files": 120
    },
    ...
  ],
  "pagination": {
    "page": 1,
    "per_page": 20,
    "total_items": 5,
    "total_pages": 1
  }
}
```

#### Get Repository

```
GET /api/v1/repositories/{id}
```

Get details of a specific repository.

**Path Parameters:**

- `id`: Repository ID

**Response:**

```json
{
  "status": "success",
  "data": {
    "id": 1,
    "name": "example-repo",
    "url": "https://github.com/example/repo",
    "path": "/local/path/to/repo",
    "ingested_at": "2025-01-15T14:30:00Z",
    "file_count": 250,
    "code_files": 120,
    "languages": {
      "python": 80,
      "javascript": 30,
      "html": 10
    },
    "files": [
      {
        "path": "src/main.py",
        "language": "python",
        "size": 2048
      },
      ...
    ]
  }
}
```

#### Add Repository

```
POST /api/v1/repositories
```

Add a new repository.

**Request Body:**

```json
{
  "name": "example-repo",
  "path": "/local/path/to/repo",
  "include_patterns": ["**/*.py", "**/*.js"],
  "exclude_patterns": ["**/node_modules/**", "**/test/**"]
}
```

**Response:**

```json
{
  "status": "success",
  "data": {
    "id": 1,
    "name": "example-repo",
    "path": "/local/path/to/repo",
    "ingested_at": "2025-01-15T14:30:00Z"
  },
  "message": "Repository added successfully"
}
```

#### Add GitHub Repository

```
POST /api/v1/repositories/github
```

Add a repository from GitHub.

**Request Body:**

```json
{
  "url": "https://github.com/example/repo",
  "branch": "main",
  "token": "github-token",  // Optional
  "include_patterns": ["**/*.py", "**/*.js"],
  "exclude_patterns": ["**/node_modules/**", "**/test/**"]
}
```

**Response:**

```json
{
  "status": "success",
  "data": {
    "id": 2,
    "name": "repo",
    "url": "https://github.com/example/repo",
    "branch": "main",
    "ingested_at": "2025-01-15T14:35:00Z"
  },
  "message": "Repository added successfully"
}
```

#### Delete Repository

```
DELETE /api/v1/repositories/{id}
```

Delete a repository.

**Path Parameters:**

- `id`: Repository ID

**Response:**

```json
{
  "status": "success",
  "message": "Repository deleted successfully"
}
```

### Investigations

#### List Investigations

```
GET /api/v1/investigations
```

List all investigations.

**Query Parameters:**

- `page`: Page number
- `per_page`: Items per page
- `status`: Filter by status ("pending", "in_progress", "completed")
- `repository_id`: Filter by repository ID

**Response:**

```json
{
  "status": "success",
  "data": [
    {
      "id": "inv-12345",
      "repository_id": 1,
      "created_at": "2025-01-15T15:00:00Z",
      "updated_at": "2025-01-15T16:30:00Z",
      "status": "completed",
      "findings_count": 12
    },
    ...
  ],
  "pagination": {
    "page": 1,
    "per_page": 20,
    "total_items": 5,
    "total_pages": 1
  }
}
```

#### Get Investigation

```
GET /api/v1/investigations/{id}
```

Get details of a specific investigation.

**Path Parameters:**

- `id`: Investigation ID

**Response:**

```json
{
  "status": "success",
  "data": {
    "id": "inv-12345",
    "repository_id": 1,
    "repository_name": "example-repo",
    "created_at": "2025-01-15T15:00:00Z",
    "updated_at": "2025-01-15T16:30:00Z",
    "status": "completed",
    "findings": [
      {
        "id": "find-6789",
        "vulnerability_type": "SQL Injection",
        "description": "Potential SQL injection vulnerability in query construction",
        "file_path": "src/db/query.py",
        "line_number": 45,
        "severity": "high",
        "confidence": 0.85,
        "remediation": "Use parameterized queries instead of string concatenation"
      },
      ...
    ],
    "summary": {
      "risk_score": 78,
      "severity_distribution": {
        "critical": 2,
        "high": 5,
        "medium": 3,
        "low": 2
      }
    }
  }
}
```

#### Create Investigation

```
POST /api/v1/investigations
```

Create a new investigation.

**Request Body:**

```json
{
  "repository_id": 1,
  "focus_areas": ["SQL Injection", "XSS", "Authentication"]
}
```

**Response:**

```json
{
  "status": "success",
  "data": {
    "id": "inv-12345",
    "repository_id": 1,
    "created_at": "2025-01-15T15:00:00Z",
    "status": "pending"
  },
  "message": "Investigation created successfully"
}
```

#### Export Investigation

```
GET /api/v1/investigations/{id}/export
```

Export an investigation in the specified format.

**Path Parameters:**

- `id`: Investigation ID

**Query Parameters:**

- `format`: Export format ("json", "markdown", "html", default: "json")

**Response:**

For JSON format:
```json
{
  "status": "success",
  "data": {
    "id": "inv-12345",
    "repository_id": 1,
    "repository_name": "example-repo",
    "created_at": "2025-01-15T15:00:00Z",
    "updated_at": "2025-01-15T16:30:00Z",
    "findings": [
      ...
    ]
  }
}
```

For other formats, returns a file download.

#### Delete Investigation

```
DELETE /api/v1/investigations/{id}
```

Delete an investigation.

**Path Parameters:**

- `id`: Investigation ID

**Response:**

```json
{
  "status": "success",
  "message": "Investigation deleted successfully"
}
```

### Analysis

#### Analyze File

```
POST /api/v1/analyze/file
```

Analyze a file for vulnerabilities.

**Request Body:**

```json
{
  "file_path": "/path/to/file.py",
  "repository_id": 1,  // Optional
  "strategies": ["pattern_matching", "semantic_analysis", "ast_analysis"]
}
```

**Response:**

```json
{
  "status": "success",
  "data": {
    "file_path": "/path/to/file.py",
    "language": "python",
    "findings": [
      {
        "id": "find-6789",
        "vulnerability_type": "SQL Injection",
        "description": "Potential SQL injection vulnerability in query construction",
        "line_number": 45,
        "severity": "high",
        "confidence": 0.85,
        "remediation": "Use parameterized queries instead of string concatenation"
      },
      ...
    ]
  }
}
```

#### Run Security Tool

```
POST /api/v1/tools/run
```

Run a security tool on a repository.

**Request Body:**

```json
{
  "tool_id": "bandit",
  "repository_id": 1,
  "args": {
    "level": "high",
    "confidence": "medium"
  }
}
```

**Response:**

```json
{
  "status": "success",
  "data": {
    "tool_id": "bandit",
    "repository_id": 1,
    "findings": [
      {
        "id": "find-6789",
        "vulnerability_type": "SQL Injection",
        "description": "Potential SQL injection vulnerability in query construction",
        "file_path": "src/db/query.py",
        "line_number": 45,
        "severity": "high",
        "confidence": 0.85,
        "remediation": "Use parameterized queries instead of string concatenation"
      },
      ...
    ]
  }
}
```

### Knowledge

#### Ask Question

```
POST /api/v1/qa/ask
```

Ask a security-related question.

**Request Body:**

```json
{
  "question": "What is a SQL injection vulnerability?",
  "repository_id": 1  // Optional, for context
}
```

**Response:**

```json
{
  "status": "success",
  "data": {
    "question": "What is a SQL injection vulnerability?",
    "answer": "SQL injection is a type of security vulnerability that occurs when untrusted data is inserted into SQL queries without proper validation or sanitization...",
    "references": [
      {
        "title": "OWASP SQL Injection",
        "url": "https://owasp.org/www-community/attacks/SQL_Injection"
      }
    ]
  }
}
```

#### Get Knowledge Topic

```
GET /api/v1/knowledge/topics/{topic}
```

Get information about a security topic.

**Path Parameters:**

- `topic`: Topic name or ID

**Response:**

```json
{
  "status": "success",
  "data": {
    "id": "sql-injection",
    "name": "SQL Injection",
    "description": "SQL injection is a type of security vulnerability that occurs when untrusted data is inserted into SQL queries without proper validation or sanitization...",
    "cwe_id": "CWE-89",
    "examples": [
      {
        "language": "python",
        "vulnerable_code": "query = \"SELECT * FROM users WHERE username = '\" + username + \"'\"",
        "remediated_code": "query = \"SELECT * FROM users WHERE username = %s\"\ncursor.execute(query, (username,))"
      }
    ],
    "references": [
      {
        "title": "OWASP SQL Injection",
        "url": "https://owasp.org/www-community/attacks/SQL_Injection"
      }
    ]
  }
}
```

### System Management

#### Get System Status

```
GET /api/v1/system/status
```

Get system status information.

**Response:**

```json
{
  "status": "success",
  "data": {
    "version": "1.0.0",
    "uptime": 86400,  // seconds
    "components": {
      "api": "healthy",
      "database": "healthy",
      "openai": "healthy"
    },
    "resources": {
      "cpu_usage": 35.2,  // percentage
      "memory_usage": 2048,  // MB
      "disk_usage": 10240  // MB
    },
    "repositories": 5,
    "investigations": 12
  }
}
```

#### Run Database Check

```
POST /api/v1/system/check-database
```

Run a database integrity check.

**Response:**

```json
{
  "status": "success",
  "data": {
    "check_result": "passed",
    "details": {
      "connections": "ok",
      "schema": "ok",
      "indexes": "ok",
      "data_integrity": "ok"
    }
  },
  "message": "Database check completed successfully"
}
```

## Common Error Codes

| Code | Description |
|------|-------------|
| `UNAUTHORIZED` | Authentication failed |
| `FORBIDDEN` | Insufficient permissions |
| `NOT_FOUND` | Resource not found |
| `VALIDATION_ERROR` | Invalid request parameters |
| `INTERNAL_ERROR` | Server error |
| `CONNECTION_ERROR` | External service connection error |
| `RESOURCE_CONFLICT` | Resource already exists |

## API Versioning

The API version is specified in the URL path:

```
/api/v1/...
```

When new versions are released, they will be made available at `/api/v2/`, etc., while maintaining backward compatibility for a specified period.

## Rate Limiting

API rate limits are enforced to ensure service stability:

| Plan | Rate Limit |
|------|------------|
| Free | 60 requests per minute |
| Pro | 300 requests per minute |
| Enterprise | Customizable |

Rate limit headers are included in all responses:

```
X-RateLimit-Limit: 60
X-RateLimit-Remaining: 58
X-RateLimit-Reset: 1577836800
```

## Examples

### Example 1: Add and Analyze a Repository

```bash
# Add a GitHub repository
curl -X POST http://localhost:8000/api/v1/repositories/github \
  -H "Content-Type: application/json" \
  -H "X-API-Key: your-api-key" \
  -d '{
    "url": "https://github.com/example/repo",
    "branch": "main"
  }'

# Get the repository ID from the response
REPO_ID=1

# Create an investigation
curl -X POST http://localhost:8000/api/v1/investigations \
  -H "Content-Type: application/json" \
  -H "X-API-Key: your-api-key" \
  -d "{
    \"repository_id\": $REPO_ID,
    \"focus_areas\": [\"SQL Injection\", \"XSS\", \"Authentication\"]
  }"

# Get the investigation ID from the response
INV_ID="inv-12345"

# Get investigation status
curl -X GET http://localhost:8000/api/v1/investigations/$INV_ID \
  -H "X-API-Key: your-api-key"

# Export investigation results
curl -X GET http://localhost:8000/api/v1/investigations/$INV_ID/export?format=json \
  -H "X-API-Key: your-api-key" \
  -o investigation-results.json
```

### Example 2: Interactive Q&A Session

```bash
# Ask a question
curl -X POST http://localhost:8000/api/v1/qa/ask \
  -H "Content-Type: application/json" \
  -H "X-API-Key: your-api-key" \
  -d '{
    "question": "What is a SQL injection vulnerability?",
    "repository_id": 1
  }'

# Ask a follow-up question
curl -X POST http://localhost:8000/api/v1/qa/ask \
  -H "Content-Type: application/json" \
  -H "X-API-Key: your-api-key" \
  -d '{
    "question": "How can I prevent SQL injection in Python?",
    "repository_id": 1,
    "conversation_id": "conv-67890"
  }'
```

## Webhooks

Skwaq can send webhook notifications for various events:

### Configure Webhooks

```
POST /api/v1/webhooks
```

Configure a webhook endpoint.

**Request Body:**

```json
{
  "url": "https://example.com/webhook",
  "events": ["investigation.completed", "finding.new"],
  "secret": "webhook-secret"
}
```

**Response:**

```json
{
  "status": "success",
  "data": {
    "id": "whk-12345",
    "url": "https://example.com/webhook",
    "events": ["investigation.completed", "finding.new"]
  },
  "message": "Webhook configured successfully"
}
```

### Webhook Payloads

Example webhook payload for `investigation.completed`:

```json
{
  "event": "investigation.completed",
  "timestamp": "2025-01-15T16:30:00Z",
  "data": {
    "investigation_id": "inv-12345",
    "repository_id": 1,
    "repository_name": "example-repo",
    "findings_count": 12,
    "risk_score": 78
  }
}
```

Example webhook payload for `finding.new`:

```json
{
  "event": "finding.new",
  "timestamp": "2025-01-15T16:15:00Z",
  "data": {
    "finding_id": "find-6789",
    "investigation_id": "inv-12345",
    "vulnerability_type": "SQL Injection",
    "severity": "high",
    "file_path": "src/db/query.py",
    "line_number": 45
  }
}
```

## Further Resources

- [Full API Schema (OpenAPI)](./schema.json)
- [Authentication Guide](./authentication.md)
- [Webhook Integration Guide](./webhooks.md)
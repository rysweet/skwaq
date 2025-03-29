# API Implementation Plan

This document outlines the step-by-step plan for rebuilding the Flask API that serves the TypeScript frontend of the Skwaq Vulnerability Assessment Copilot.

## Overview

The goal is to create a clean, maintainable API that shares code with the CLI and properly integrates with the TypeScript frontend. The API will be implemented in phases, focusing on proper architecture, code reuse, and comprehensive testing.

## Phase 1: Preparation

1. **Remove existing API code and tests**
   - Remove the current `/skwaq/api` directory and associated tests
   - Create a new empty `/skwaq/api` directory with basic structure

2. **Identify shared code between CLI and API**
   - Review CLI command handlers to identify reusable business logic
   - Create new shared modules for code that will be used by both CLI and API
   - Move business logic from CLI command handlers to shared modules

3. **Setup basic Flask application**
   - Create minimal Flask application with CORS support
   - Setup basic middleware (authentication, logging, error handling)
   - Add health check endpoint
   - Create structure for blueprints and routes

4. **Implement authentication**
   - Create JWT-based authentication system
   - Implement login, logout, token refresh, and user info endpoints
   - Create decorators for route protection

## Phase 2: Core API Implementation

5. **Implement repository endpoints**
   - Create repository blueprint with routes
   - Implement listing repositories
   - Implement repository details, creation, and deletion
   - Implement repository analysis and status endpoints

6. **Implement workflow endpoints**
   - Create workflow blueprint with routes
   - Implement listing available workflows
   - Implement starting, stopping, and monitoring workflows
   - Implement workflow results endpoints

7. **Implement event system**
   - Create Server-Sent Events (SSE) system for real-time updates
   - Implement event publishing mechanism
   - Create channel-based event subscription system
   - Add connection endpoint for clients

8. **Implement chat endpoints**
   - Create chat blueprint with routes
   - Implement chat session management
   - Implement message sending and retrieval
   - Add streaming capability for real-time chat

9. **Implement knowledge graph endpoints**
   - Create knowledge graph blueprint with routes
   - Implement graph querying endpoints
   - Implement visualization data formatting

## Phase 3: Testing and Refinement

10. **Create unit tests**
    - Create tests for authentication
    - Create tests for repository endpoints
    - Create tests for workflow endpoints
    - Create tests for event system
    - Create tests for chat endpoints

11. **Create integration tests**
    - Create tests that verify API and database interaction
    - Create tests that verify event publishing
    - Create tests for workflow execution

12. **Documentation**
    - Add OpenAPI/Swagger documentation
    - Update API reference documentation
    - Create usage examples

13. **Performance optimization**
    - Profile API under load
    - Optimize database queries
    - Implement caching where appropriate
    - Add pagination for large result sets

## Implementation Details

### Directory Structure

```
/skwaq/api/
  __init__.py           # App factory and initialization
  app.py                # Flask application entry point
  middleware/
    __init__.py
    auth.py             # Authentication middleware
    cors.py             # CORS middleware
    error_handling.py   # Error handling middleware
    logging.py          # Logging middleware
  routes/
    __init__.py
    auth.py             # Authentication routes
    repositories.py     # Repository management routes
    workflows.py        # Workflow execution routes
    events.py           # Event streaming routes
    chat.py             # Chat functionality routes
    knowledge_graph.py  # Knowledge graph routes
  services/
    __init__.py
    auth_service.py     # Authentication business logic
    repository_service.py  # Repository business logic
    workflow_service.py    # Workflow business logic
    event_service.py       # Event management
    chat_service.py        # Chat business logic
    knowledge_graph_service.py  # Knowledge graph business logic
```

### Shared Code Structure

```
/skwaq/shared/
  __init__.py
  auth/
    __init__.py
    jwt_handler.py      # JWT token handling
    permissions.py      # Permission checking
  repository/
    __init__.py
    repository_manager.py  # Repository management
  workflow/
    __init__.py
    workflow_runner.py    # Workflow execution
  events/
    __init__.py
    event_dispatcher.py   # Event publishing
```

### Key Implementation Principles

1. **Separation of Concerns**
   - Routes handle HTTP requests and responses
   - Services contain business logic
   - Models contain data structures
   - Middleware handles cross-cutting concerns

2. **Code Reuse**
   - Shared modules for business logic
   - Common utilities for both CLI and API
   - DRY (Don't Repeat Yourself) principle

3. **Error Handling**
   - Consistent error responses
   - Proper status codes
   - Detailed error messages for debugging
   - Production-safe error messages for users

4. **Authentication & Authorization**
   - JWT-based authentication
   - Role-based authorization
   - Permission checking
   - Secure token handling

5. **Testing**
   - Unit tests for each endpoint
   - Integration tests for API interactions
   - Mocking external dependencies

6. **Documentation**
   - OpenAPI/Swagger specification
   - In-code docstrings
   - Examples and usage documentation

## Milestones and Timeline

1. **Phase 1: Preparation** (2 days)
   - Remove existing code
   - Set up shared modules
   - Create basic Flask app
   - Implement authentication

2. **Phase 2: Core API Implementation** (5 days)
   - Repository endpoints
   - Workflow endpoints
   - Event system
   - Chat endpoints
   - Knowledge graph endpoints

3. **Phase 3: Testing and Refinement** (3 days)
   - Unit tests
   - Integration tests
   - Documentation
   - Performance optimization

## Risks and Mitigations

1. **Risk**: Shared code changes might break CLI functionality
   - **Mitigation**: Comprehensive testing of CLI after shared code extraction

2. **Risk**: Authentication integration with frontend might be challenging
   - **Mitigation**: Early testing with frontend to validate JWT approach

3. **Risk**: Event-based real-time updates might be complex
   - **Mitigation**: Start with simple SSE implementation and iterate

4. **Risk**: Performance issues with large repositories or workflows
   - **Mitigation**: Implement pagination and optimize database queries

5. **Risk**: Database access layer might require significant refactoring
   - **Mitigation**: Create clear abstractions and test thoroughly

## Conclusion

This implementation plan provides a structured approach to rebuilding the API for the Skwaq Vulnerability Assessment Copilot. By following this plan, we will create a clean, maintainable API that properly integrates with the TypeScript frontend while sharing code with the CLI.
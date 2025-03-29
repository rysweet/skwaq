"""Tests for the workflow routes."""

import pytest
import json
from unittest.mock import patch, MagicMock
import time

from skwaq.api import create_app
from skwaq.api.services import workflow_service


@pytest.fixture
def app():
    """Create and configure a Flask app for testing."""
    app = create_app({
        'TESTING': True,
        'JWT_SECRET': 'test-jwt-secret',
        'JWT_ALGORITHM': 'HS256',
    })
    yield app


@pytest.fixture
def client(app):
    """A test client for the app."""
    return app.test_client()


@pytest.fixture
def auth_token(client):
    """Get authentication token for testing."""
    response = client.post(
        '/api/auth/login',
        json={'username': 'admin', 'password': 'admin'}
    )
    data = json.loads(response.data)
    return data['token']


# Mock workflow data
MOCK_WORKFLOWS = [
    {
        "id": "workflow-vuln-assess",
        "name": "Vulnerability Assessment",
        "description": "Assess a repository for common security vulnerabilities",
        "type": "vulnerability_assessment",
        "parameters": [
            {
                "name": "deepScan",
                "type": "boolean",
                "default": False,
                "description": "Perform a deep scan of the codebase"
            },
            {
                "name": "includeDependencies",
                "type": "boolean",
                "default": True,
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

# Mock execution data
MOCK_EXECUTION = {
    "id": "exec-123",
    "workflowType": "vulnerability_assessment",
    "workflowName": "Vulnerability Assessment",
    "repositoryId": "repo-123",
    "status": "running",
    "progress": 50,
    "parameters": {"deepScan": True},
    "startTime": "2025-03-28T12:00:00Z",
    "endTime": None,
    "resultsAvailable": False
}

MOCK_EXECUTION_COMPLETED = {
    "id": "exec-456",
    "workflowType": "vulnerability_assessment",
    "workflowName": "Vulnerability Assessment",
    "repositoryId": "repo-123",
    "status": "completed",
    "progress": 100,
    "parameters": {"deepScan": True},
    "startTime": "2025-03-28T12:00:00Z",
    "endTime": "2025-03-28T12:15:00Z",
    "resultsAvailable": True
}

MOCK_WORKFLOW_RESULTS = {
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

MOCK_REPOSITORY = {
    "id": "repo-123",
    "name": "test-repo",
    "description": "Test repository",
    "status": "Analyzed",
    "progress": 100,
    "vulnerabilities": 5,
    "lastAnalyzed": "2025-03-28T12:00:00Z",
    "fileCount": 100,
    "url": "https://github.com/test/repo",
}


@patch('skwaq.api.services.workflow_service.get_all_workflows')
def test_get_workflows(mock_get, client, auth_token):
    """Test getting all workflows."""
    # Setup the mock
    mock_get.return_value = MOCK_WORKFLOWS
    
    # Call the route
    with patch('skwaq.api.routes.workflows.asyncio.run', return_value=MOCK_WORKFLOWS):
        response = client.get(
            '/api/workflows',
            headers={'Authorization': f'Bearer {auth_token}'}
        )
    
    # Check the response
    assert response.status_code == 200
    data = json.loads(response.data)
    assert isinstance(data, list)
    assert len(data) == 2
    assert data[0]['id'] == 'workflow-vuln-assess'
    assert data[1]['id'] == 'workflow-guided-inquiry'


@patch('skwaq.api.services.workflow_service.get_workflow_by_id')
def test_get_workflow(mock_get, client, auth_token):
    """Test getting a workflow by ID."""
    # Setup the mock
    mock_get.return_value = MOCK_WORKFLOWS[0]
    
    # Call the route
    with patch('skwaq.api.routes.workflows.asyncio.run', return_value=MOCK_WORKFLOWS[0]):
        response = client.get(
            '/api/workflows/workflow-vuln-assess',
            headers={'Authorization': f'Bearer {auth_token}'}
        )
    
    # Check the response
    assert response.status_code == 200
    data = json.loads(response.data)
    assert data['id'] == 'workflow-vuln-assess'
    assert data['name'] == 'Vulnerability Assessment'


@patch('skwaq.api.services.workflow_service.get_workflow_by_id')
def test_get_workflow_not_found(mock_get, client, auth_token):
    """Test getting a workflow that doesn't exist."""
    # Configure mock to return None
    mock_get.return_value = None
    
    # Call the route
    with patch('skwaq.api.routes.workflows.asyncio.run', return_value=None):
        response = client.get(
            '/api/workflows/nonexistent',
            headers={'Authorization': f'Bearer {auth_token}'}
        )
    
    # Check the response
    assert response.status_code == 404
    data = json.loads(response.data)
    assert 'error' in data


@patch('skwaq.api.services.workflow_service.get_repository_workflows')
def test_get_repository_workflows(mock_get, client, auth_token):
    """Test getting workflows for a repository."""
    # Setup the mock
    mock_get.return_value = [MOCK_EXECUTION, MOCK_EXECUTION_COMPLETED]
    
    # Call the route
    with patch('skwaq.api.routes.workflows.asyncio.run', return_value=[MOCK_EXECUTION, MOCK_EXECUTION_COMPLETED]):
        response = client.get(
            '/api/workflows/repository/repo-123',
            headers={'Authorization': f'Bearer {auth_token}'}
        )
    
    # Check the response
    assert response.status_code == 200
    data = json.loads(response.data)
    assert isinstance(data, list)
    assert len(data) == 2
    assert data[0]['id'] == 'exec-123'
    assert data[1]['id'] == 'exec-456'


@patch('skwaq.api.services.workflow_service.get_execution_by_id')
def test_get_workflow_execution(mock_get, client, auth_token):
    """Test getting a workflow execution by ID."""
    # Setup the mock
    mock_get.return_value = MOCK_EXECUTION
    
    # Call the route
    with patch('skwaq.api.routes.workflows.asyncio.run', return_value=MOCK_EXECUTION):
        response = client.get(
            '/api/workflows/execution/exec-123',
            headers={'Authorization': f'Bearer {auth_token}'}
        )
    
    # Check the response
    assert response.status_code == 200
    data = json.loads(response.data)
    assert data['id'] == 'exec-123'
    assert data['status'] == 'running'
    assert data['progress'] == 50


@patch('skwaq.api.services.workflow_service.get_execution_by_id')
def test_get_workflow_execution_not_found(mock_get, client, auth_token):
    """Test getting a workflow execution that doesn't exist."""
    # Configure mock to return None
    mock_get.return_value = None
    
    # Call the route
    with patch('skwaq.api.routes.workflows.asyncio.run', return_value=None):
        response = client.get(
            '/api/workflows/execution/nonexistent',
            headers={'Authorization': f'Bearer {auth_token}'}
        )
    
    # Check the response
    assert response.status_code == 404
    data = json.loads(response.data)
    assert 'error' in data


@patch('skwaq.api.services.workflow_service.get_execution_by_id')
@patch('skwaq.api.services.workflow_service.cancel_workflow_execution')
def test_cancel_workflow_execution(mock_cancel, mock_get, client, auth_token):
    """Test cancelling a workflow execution."""
    # Setup the mocks
    execution = MOCK_EXECUTION.copy()
    execution_cancelled = execution.copy()
    execution_cancelled['status'] = 'cancelled'
    
    mock_get.return_value = execution
    mock_cancel.return_value = True
    
    # Call the route
    with patch('skwaq.api.routes.workflows.asyncio.run', side_effect=[execution, True, execution_cancelled]):
        response = client.post(
            '/api/workflows/execution/exec-123/cancel',
            headers={'Authorization': f'Bearer {auth_token}'}
        )
    
    # Check the response
    assert response.status_code == 200
    data = json.loads(response.data)
    assert data['status'] == 'cancelled'


@patch('skwaq.api.services.workflow_service.get_execution_by_id')
def test_cancel_workflow_execution_already_completed(mock_get, client, auth_token):
    """Test cancelling a workflow execution that's already completed."""
    # Setup the mock to return a completed execution
    mock_get.return_value = MOCK_EXECUTION_COMPLETED
    
    # Call the route
    with patch('skwaq.api.routes.workflows.asyncio.run', return_value=MOCK_EXECUTION_COMPLETED):
        response = client.post(
            '/api/workflows/execution/exec-456/cancel',
            headers={'Authorization': f'Bearer {auth_token}'}
        )
    
    # Check the response
    assert response.status_code == 400
    data = json.loads(response.data)
    assert 'error' in data


@patch('skwaq.api.services.workflow_service.get_execution_by_id')
@patch('skwaq.api.services.workflow_service.get_workflow_results')
def test_get_workflow_results(mock_results, mock_get, client, auth_token):
    """Test getting workflow results."""
    # Setup the mocks
    mock_get.return_value = MOCK_EXECUTION_COMPLETED
    mock_results.return_value = MOCK_WORKFLOW_RESULTS
    
    # Call the route
    with patch('skwaq.api.routes.workflows.asyncio.run', side_effect=[MOCK_EXECUTION_COMPLETED, MOCK_WORKFLOW_RESULTS]):
        response = client.get(
            '/api/workflows/execution/exec-456/results',
            headers={'Authorization': f'Bearer {auth_token}'}
        )
    
    # Check the response
    assert response.status_code == 200
    data = json.loads(response.data)
    assert data['executionId'] == 'exec-456'
    assert data['status'] == 'completed'
    assert 'results' in data
    assert data['results']['findings'][0]['id'] == 'finding-001'


@patch('skwaq.api.services.workflow_service.get_execution_by_id')
def test_get_workflow_results_not_completed(mock_get, client, auth_token):
    """Test getting workflow results for an execution that's not completed."""
    # Setup the mock to return a running execution
    mock_get.return_value = MOCK_EXECUTION
    
    # Call the route
    with patch('skwaq.api.routes.workflows.asyncio.run', return_value=MOCK_EXECUTION):
        response = client.get(
            '/api/workflows/execution/exec-123/results',
            headers={'Authorization': f'Bearer {auth_token}'}
        )
    
    # Check the response
    assert response.status_code == 400
    data = json.loads(response.data)
    assert 'error' in data


@patch('skwaq.api.services.repository_service.get_repository_by_id')
@patch('skwaq.api.services.workflow_service.get_workflow_by_type')
@patch('skwaq.api.services.workflow_service.execute_workflow')
def test_execute_workflow(mock_execute, mock_workflow, mock_repo, client, auth_token):
    """Test executing a workflow."""
    # Setup the mocks
    mock_repo.return_value = MOCK_REPOSITORY
    mock_workflow.return_value = MOCK_WORKFLOWS[0]
    mock_execute.return_value = True
    
    # Call the route
    with patch('skwaq.api.routes.workflows.asyncio.run', side_effect=[MOCK_REPOSITORY, MOCK_WORKFLOWS[0], True]):
        response = client.post(
            '/api/workflows/execute',
            headers={'Authorization': f'Bearer {auth_token}'},
            json={
                'workflowType': 'vulnerability_assessment',
                'repositoryId': 'repo-123',
                'parameters': {
                    'deepScan': True
                }
            }
        )
    
    # Check the response
    assert response.status_code == 201
    data = json.loads(response.data)
    assert data['workflowType'] == 'vulnerability_assessment'
    assert data['repositoryId'] == 'repo-123'
    assert data['status'] == 'queued'
    assert 'executionId' in data


def test_execute_workflow_missing_data(client, auth_token):
    """Test executing a workflow with missing data."""
    # Test missing workflow type
    response = client.post(
        '/api/workflows/execute',
        headers={'Authorization': f'Bearer {auth_token}'},
        json={
            'repositoryId': 'repo-123'
        }
    )
    assert response.status_code == 400
    data = json.loads(response.data)
    assert 'error' in data
    
    # Test missing repository ID
    response = client.post(
        '/api/workflows/execute',
        headers={'Authorization': f'Bearer {auth_token}'},
        json={
            'workflowType': 'vulnerability_assessment'
        }
    )
    assert response.status_code == 400
    data = json.loads(response.data)
    assert 'error' in data


@patch('skwaq.api.services.repository_service.get_repository_by_id')
def test_execute_workflow_repository_not_found(mock_repo, client, auth_token):
    """Test executing a workflow with a repository that doesn't exist."""
    # Setup the mock
    mock_repo.return_value = None
    
    # Call the route
    with patch('skwaq.api.routes.workflows.asyncio.run', return_value=None):
        response = client.post(
            '/api/workflows/execute',
            headers={'Authorization': f'Bearer {auth_token}'},
            json={
                'workflowType': 'vulnerability_assessment',
                'repositoryId': 'nonexistent'
            }
        )
    
    # Check the response
    assert response.status_code == 404
    data = json.loads(response.data)
    assert 'error' in data


@patch('skwaq.api.services.repository_service.get_repository_by_id')
@patch('skwaq.api.services.workflow_service.get_workflow_by_type')
def test_execute_workflow_type_not_found(mock_workflow, mock_repo, client, auth_token):
    """Test executing a workflow with a type that doesn't exist."""
    # Setup the mocks
    mock_repo.return_value = MOCK_REPOSITORY
    mock_workflow.return_value = None
    
    # Call the route
    with patch('skwaq.api.routes.workflows.asyncio.run', side_effect=[MOCK_REPOSITORY, None]):
        response = client.post(
            '/api/workflows/execute',
            headers={'Authorization': f'Bearer {auth_token}'},
            json={
                'workflowType': 'nonexistent',
                'repositoryId': 'repo-123'
            }
        )
    
    # Check the response
    assert response.status_code == 404
    data = json.loads(response.data)
    assert 'error' in data
# Skwaq Testing

## Test Structure

- `unit/`: Unit tests for individual components
- `integration/`: Integration tests for multiple components working together

## Running Tests

- Run all tests: `pytest`
- Run specific test file: `pytest tests/path/to/test_file.py`
- Run specific test: `pytest tests/path/to/test_file.py::TestClass::test_function`
- Get coverage report: `pytest --cov=skwaq`

## API Testing

### Unit Testing API Endpoints

For unit testing API endpoints, we recommend using Flask's test client:

```python
def test_api_endpoint(client):
    """Test an API endpoint using Flask's test client."""
    response = client.get('/api/endpoint')
    assert response.status_code == 200
    # Test response data
```

### Integration Testing with Real Components

For integration testing with real components (e.g., Neo4j database), you can:

1. Create a test fixture that sets up the necessary test data in the database
2. Use the Flask test client to test the API endpoint
3. Clean up the test data after the test

```python
def test_with_real_db(client, neo4j_connection):
    """Test using the real database."""
    # Set up test data
    # ...
    
    # Test API endpoint
    response = client.get('/api/endpoint')
    assert response.status_code == 200
    
    # Clean up test data
    # ...
```

### Manual Testing with Curl

For manual testing, you can use curl:

```bash
# Test the healthcheck endpoint
curl http://localhost:5000/api/healthcheck

# Get all investigations
curl http://localhost:5000/api/investigations

# Get a specific investigation
curl http://localhost:5000/api/investigations/{id}

# Create a new investigation
curl -X POST http://localhost:5000/api/investigations \
  -H "Content-Type: application/json" \
  -d '{"title":"Test Investigation","repository_id":"repo-123","description":"Test"}'
```

## Testing Considerations

1. **Authentication**: For tests that require authentication, you can:
   - Disable authentication for testing
   - Mock the authentication middleware
   - Create a test user and authenticate

2. **Database Tests**: For tests that interact with the database:
   - Use a separate test database
   - Create unique test IDs for test data
   - Always clean up test data after tests

3. **Performance Tests**: For testing performance, consider:
   - Using benchmarks to measure response times
   - Testing with large datasets
   - Testing concurrent requests

## Test Fixtures

- `client`: Flask test client
- `neo4j_connection`: Connection to Neo4j database
- `mock_connector`: Mock Neo4j connector
- `create_test_investigation`: Creates a test investigation in the database
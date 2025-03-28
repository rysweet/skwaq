# Integration Tests

This directory contains integration tests that verify Skwaq's integration with external systems like Neo4j, Azure OpenAI, and GitHub.

## Running Integration Tests

### Standard Integration Tests

Most integration tests can be run with pytest:

```bash
# Run all integration tests
pytest tests/integration/

# Run specific integration test modules
pytest tests/integration/ingestion/test_ingestion_integration.py

# Run a specific test
pytest tests/integration/ingestion/test_ingestion_integration.py::test_neo4j_direct_query
```

### OpenAI Integration Tests

The standard test infrastructure mocks external dependencies to ensure tests run reliably without real API calls. However, this means OpenAI integration tests won't connect to the real API when run with pytest.

To test actual OpenAI integration, run the direct tests:

```bash
# Test Azure OpenAI integration with direct API calls
python -m tests.integration.ingestion.test_azure_openai_direct
```

This requires proper Azure OpenAI credentials in your environment variables or `.env` file:

```
# Azure OpenAI Configuration
AZURE_OPENAI_ENDPOINT=https://your-endpoint.openai.azure.com
AZURE_OPENAI_API_VERSION=2025-03-01-preview

# Bearer Token Authentication for Azure OpenAI
AZURE_OPENAI_USE_ENTRA_ID=true
AZURE_OPENAI_AUTH_METHOD=bearer_token
AZURE_OPENAI_TOKEN_SCOPE=https://cognitiveservices.azure.com/.default

# Model Configuration
AZURE_OPENAI_MODEL_DEPLOYMENTS={"chat":"your-deployment-name"}
```

## Test Structure

### Neo4j Integration Tests

Tests in `test_ingestion_integration.py` verify Neo4j integration:
- `test_neo4j_basic_operations`: Basic operations like node creation and querying
- `test_neo4j_direct_query`: Direct graph database queries
- `test_repository_direct_creation`: Repository management operations

### OpenAI Integration Tests

#### Basic API Testing

Tests in `test_azure_openai_direct.py` verify Azure OpenAI API integration:
- `test_azure_openai_direct`: Makes a direct call to Azure OpenAI API

#### LLM Code Summarization Testing

Tests in `test_llm_summarization.py` verify the LLM-based code summarization functionality:
- `test_llm_summarizer_integration`: Tests the full LLM summarization pipeline, including:
  - Reading and processing multiple source code files
  - Generating code summaries using Azure OpenAI
  - Storing summaries in the Neo4j database
  - Creating proper relationships between files and summaries

These tests validate several acceptance criteria from the Ingestion specification:
- Successfully generating summaries of code using the LLM
- Storing summaries in the Neo4j database
- Tracking the total files processed
- Tracking the time taken for the LLM to generate summaries
- Creating proper relationships between code files and summaries

## Running Integration Tests with Real External Services

The standard test infrastructure mocks external dependencies to ensure tests run reliably without real API calls during automated testing. However, you may want to run tests with real external services during development or to verify actual integration.

To run the integration tests with real external services, use the following commands:

### For Azure OpenAI integration:

Run the basic API test:
```bash
python -m tests.integration.ingestion.test_azure_openai_direct
```

Run the full LLM code summarization test:
```bash
python -m tests.integration.ingestion.test_llm_summarization
```

Note: The `pytest` command won't work properly for these tests because it activates the mocking infrastructure. You need to run the Python modules directly.

All tests use Azure AD authentication with managed identity by default, which is the recommended authentication method for Azure-hosted deployments.
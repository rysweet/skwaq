# Workflow Integration Tests

This directory contains integration tests for the workflow modules in the Skwaq project.

## Running the Tests

To run the workflow integration tests:

```bash
# Run all workflow integration tests
pytest tests/integration/workflows/

# Run a specific test file
pytest tests/integration/workflows/test_sources_and_sinks_integration.py

# Run a specific test
pytest tests/integration/workflows/test_sources_and_sinks_integration.py::test_sources_and_sinks_workflow_integration
```

## Test Requirements

These tests require:

1. A running Neo4j database instance
2. OpenAI API credentials (or Azure OpenAI credentials)
3. Proper environment variables set up

## Environment Setup

Create a `.env` file in the root of the project with the following variables:

```
# Neo4j Configuration
NEO4J_URI=bolt://localhost:7687
NEO4J_USER=neo4j
NEO4J_PASSWORD=password
NEO4J_DATABASE=neo4j

# OpenAI Configuration (Standard OpenAI)
OPENAI_API_KEY=your-api-key
OPENAI_ORG_ID=your-org-id

# OR Azure OpenAI Configuration
AZURE_OPENAI_API_KEY=your-azure-api-key
AZURE_OPENAI_ENDPOINT=https://your-resource.openai.azure.com/
AZURE_OPENAI_API_VERSION=2023-07-01-preview

# If using Azure Entra ID (Azure AD) Authentication
AZURE_OPENAI_USE_ENTRA_ID=true
AZURE_TENANT_ID=your-tenant-id
AZURE_CLIENT_ID=your-client-id
AZURE_CLIENT_SECRET=your-client-secret

# Model deployments mapping for Azure OpenAI (JSON format)
AZURE_OPENAI_MODEL_DEPLOYMENTS={"gpt-4": "your-gpt4-deployment", "gpt-3.5-turbo": "your-gpt35-deployment"}
```

## Test Organization

- `test_sources_and_sinks_integration.py`: Tests for the Sources and Sinks workflow, including:
  - Testing Neo4j integration for storing analysis results
  - Testing OpenAI integration for analyzing code
  - Testing end-to-end workflow execution
"""OpenAI integration tests for the ingestion module.

These tests verify integration with OpenAI for code summarization and client functionality.
They support both standard OpenAI and Azure OpenAI configurations.

Notes:
    - Tests are marked with @pytest.mark.openai to allow skipping them when credentials
      are not available
    - The tests use the openai_api_credentials fixture to get credentials from environment variables
    - If using Azure OpenAI, the endpoint must be provided in the config
"""

import os
import pytest
from unittest.mock import patch
import asyncio
from typing import Dict, Any, List, Optional, Union

from skwaq.core.openai_client import OpenAIClient, get_openai_client
from skwaq.ingestion.summarizers.llm_summarizer import LLMSummarizer
from skwaq.utils.config import Config


@pytest.fixture
def test_file():
    """Test file fixture factory for summarization.

    Returns:
        Factory function to create test file objects
    """

    class _TestFile:
        def __init__(self, path: str, content: str, language: str = "python"):
            """Initialize the test file.

            Args:
                path: File path
                content: File content
                language: File language
            """
            self.path = path
            self.content = content
            self.language = language

        def read_text(self) -> str:
            """Read the file content.

            Returns:
                File content
            """
            return self.content

    return _TestFile


@pytest.fixture
def test_file_system(test_file):
    """Test filesystem fixture factory for summarization tests.

    Args:
        test_file: The test file fixture

    Returns:
        Factory function to create test filesystem objects
    """

    class _TestFileSystem:
        def __init__(self, files: Dict[str, Any]):
            """Initialize the test filesystem.

            Args:
                files: Dictionary of file path to test file
            """
            self.files = files

        def get_file_content(self, path: str) -> str:
            """Get content of a file.

            Args:
                path: Path to the file

            Returns:
                File content as string
            """
            if path in self.files:
                return self.files[path].content
            raise FileNotFoundError(f"File not found: {path}")

        def get_file_language(self, path: str) -> str:
            """Get language of a file.

            Args:
                path: Path to the file

            Returns:
                File language
            """
            if path in self.files:
                return self.files[path].language
            raise FileNotFoundError(f"File not found: {path}")

    return _TestFileSystem


@pytest.mark.openai
@pytest.mark.integration
@pytest.mark.asyncio
async def test_openai_client_direct_completion(openai_api_credentials: Dict[str, str]):
    """Test direct completion with OpenAI API.

    This test verifies that the OpenAI client can connect to the API and
    generate completions.

    Args:
        openai_api_credentials: OpenAI API credentials fixture
    """
    # Create a config with required parameters
    config = Config(
        openai_api_key=openai_api_credentials.get("api_key", ""),
        openai_org_id=openai_api_credentials.get(
            "org_id", ""
        ),  # Use empty string if org_id not provided
    )

    # Set up configuration based on API type
    if openai_api_credentials.get("api_type") == "azure":
        openai_config = {
            "api_type": "azure",
            "endpoint": openai_api_credentials.get("api_base"),
            "api_version": openai_api_credentials.get("api_version"),
        }

        # Add model deployments if available
        if openai_api_credentials.get("model_deployments"):
            openai_config["model_deployments"] = openai_api_credentials.get(
                "model_deployments"
            )

        # Add Entra ID configuration if using it
        if openai_api_credentials.get("use_entra_id"):
            openai_config["use_entra_id"] = True

            if openai_api_credentials.get("auth_method") == "bearer_token":
                openai_config["auth_method"] = "bearer_token"
                if openai_api_credentials.get("token_scope"):
                    openai_config["token_scope"] = openai_api_credentials.get(
                        "token_scope"
                    )
            else:
                # Standard Entra ID authentication with client credentials
                if openai_api_credentials.get("tenant_id"):
                    openai_config["tenant_id"] = openai_api_credentials.get("tenant_id")
                if openai_api_credentials.get("client_id"):
                    openai_config["client_id"] = openai_api_credentials.get("client_id")
                if openai_api_credentials.get("client_secret"):
                    openai_config["client_secret"] = openai_api_credentials.get(
                        "client_secret"
                    )

        config.openai = openai_config

    # Create a client
    client = OpenAIClient(config, async_mode=True)

    # Test a simple completion
    prompt = "Generate a one-sentence summary of this Python function: def add(a, b): return a + b"
    response = await client.get_completion(prompt, temperature=0.0)

    # Verify we got a sensible response
    assert response and len(response) > 0, "No response from OpenAI API"
    assert (
        "add" in response.lower() or "sum" in response.lower()
    ), "Response doesn't mention function purpose"

    print(f"OpenAI response: {response}")


@pytest.mark.openai
@pytest.mark.integration
@pytest.mark.asyncio
async def test_llm_summarizer_with_real_client(
    openai_api_credentials: Dict[str, str],
    temp_repo_dir: str,
    test_file,
    test_file_system,
):
    """Test the LLMSummarizer with a real OpenAI client.

    Args:
        openai_api_credentials: OpenAI API credentials fixture
        temp_repo_dir: Temporary repository directory fixture
        test_file: Test file factory fixture
        test_file_system: Test file system factory fixture
    """
    # Create a config with required parameters
    config = Config(
        openai_api_key=openai_api_credentials.get("api_key", ""),
        openai_org_id=openai_api_credentials.get(
            "org_id", ""
        ),  # Use empty string if org_id not provided
    )

    # Set up configuration based on API type
    if openai_api_credentials.get("api_type") == "azure":
        openai_config = {
            "api_type": "azure",
            "endpoint": openai_api_credentials.get("api_base"),
            "api_version": openai_api_credentials.get("api_version"),
        }

        # Add model deployments if available
        if openai_api_credentials.get("model_deployments"):
            openai_config["model_deployments"] = openai_api_credentials.get(
                "model_deployments"
            )

        # Add Entra ID configuration if using it
        if openai_api_credentials.get("use_entra_id"):
            openai_config["use_entra_id"] = True

            if openai_api_credentials.get("auth_method") == "bearer_token":
                openai_config["auth_method"] = "bearer_token"
                if openai_api_credentials.get("token_scope"):
                    openai_config["token_scope"] = openai_api_credentials.get(
                        "token_scope"
                    )
            else:
                # Standard Entra ID authentication with client credentials
                if openai_api_credentials.get("tenant_id"):
                    openai_config["tenant_id"] = openai_api_credentials.get("tenant_id")
                if openai_api_credentials.get("client_id"):
                    openai_config["client_id"] = openai_api_credentials.get("client_id")
                if openai_api_credentials.get("client_secret"):
                    openai_config["client_secret"] = openai_api_credentials.get(
                        "client_secret"
                    )

        config.openai = openai_config

    # Create a client
    client = OpenAIClient(config, async_mode=True)

    # Create test files with simpler content for faster processing
    TestFile = test_file  # Get the actual TestFile class from the fixture
    files = {
        f"{temp_repo_dir}/sample.py": TestFile(
            path=f"{temp_repo_dir}/sample.py",
            content="def hello():\n    return 'Hello, world!'\n",
            language="python",
        )
    }

    # Create test filesystem
    TestFileSystem = (
        test_file_system  # Get the actual TestFileSystem class from the fixture
    )
    fs = TestFileSystem(files)

    # Create the summarizer
    summarizer = LLMSummarizer()
    summarizer.configure(model_client=client, max_parallel=1)

    # Create a list of file nodes (similar to what the ingestion process would provide)
    file_nodes = [
        {"file_id": 1, "path": f"{temp_repo_dir}/sample.py", "language": "python"}
    ]

    # Run the summarization
    repo_node_id = 100  # Fake repository node ID
    result = await summarizer.summarize_files(file_nodes, fs, repo_node_id)

    # Verify the result
    assert result, "No result from summarizer"
    assert "files_processed" in result, "No files_processed in result"
    assert result["files_processed"] > 0, "No files were processed"
    assert "stats" in result, "No stats in result"
    assert "summaries_generated" in result["stats"], "No summaries_generated in stats"
    assert result["stats"]["summaries_generated"] > 0, "No summaries were generated"

    # Print the result
    print(f"Summarization result: {result}")


@pytest.mark.openai
@pytest.mark.integration
@pytest.mark.asyncio
async def test_openai_client_registry():
    """Test the OpenAI client registry.

    This test verifies that the OpenAI client registry works correctly
    and returns the same client for the same registry key.
    """
    from skwaq.core.openai_client import reset_client_registry, get_openai_client

    # Reset the registry
    reset_client_registry()

    # Create a test config with all required parameters
    config = Config(openai_api_key="test-key", openai_org_id="test-org")

    # We need to set this to OpenAI instead of Azure to avoid endpoint requirement
    # or provide a fake Azure endpoint
    config.openai = {
        "api_type": "openai",  # Use OpenAI API type to avoid Azure endpoint requirement
    }

    # Alternatively, we could have provided Azure endpoint:
    # config.openai = {
    #     "api_type": "azure",
    #     "endpoint": "https://test-endpoint.openai.azure.com/",
    # }

    # Get a client with a specific registry key
    client1 = get_openai_client(config, registry_key="test-client")

    # Get another client with the same registry key
    client2 = get_openai_client(config, registry_key="test-client")

    # Get a client with a different registry key
    client3 = get_openai_client(config, registry_key="other-client")

    # Verify that client1 and client2 are the same object
    assert (
        client1 is client2
    ), "Client registry did not return the same client for the same key"

    # Verify that client1 and client3 are different objects
    assert (
        client1 is not client3
    ), "Client registry returned the same client for different keys"

    # Reset the registry
    reset_client_registry()

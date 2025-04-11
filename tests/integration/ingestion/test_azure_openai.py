"""Azure OpenAI integration tests.

These tests verify integration with Azure OpenAI using real API calls.
They require proper Azure OpenAI credentials in the environment or .env file.

IMPORTANT: These tests will fail if run with the standard pytest configuration
because the global test infrastructure mocks external dependencies.
Run these tests directly with:

python -m tests.integration.ingestion.test_azure_openai
"""

import os
import json
import asyncio
import pytest
from typing import Dict, Any, List, Optional

try:
    from dotenv import load_dotenv, find_dotenv

    HAS_DOTENV = True
except ImportError:
    HAS_DOTENV = False

# Load environment variables
if HAS_DOTENV:
    dotenv_path = find_dotenv()
    if dotenv_path:
        print(f"Loading configuration from .env file: {dotenv_path}")
        load_dotenv(dotenv_path)

# Import the actual modules we need
from skwaq.utils.config import Config
from skwaq.core.openai_client import OpenAIClient


async def test_azure_openai_direct_completion():
    """Test direct completion with Azure OpenAI API.

    This test verifies direct connectivity to Azure OpenAI
    with Entra ID authentication.
    """
    # Get configuration from environment
    endpoint = os.environ.get("AZURE_OPENAI_ENDPOINT")
    api_version = os.environ.get("AZURE_OPENAI_API_VERSION", "2023-05-15")
    use_entra_id = os.environ.get("AZURE_OPENAI_USE_ENTRA_ID", "").lower() in (
        "true",
        "yes",
        "1",
        "y",
    )
    auth_method = os.environ.get("AZURE_OPENAI_AUTH_METHOD", "")
    token_scope = os.environ.get("AZURE_OPENAI_TOKEN_SCOPE", "")

    # Get model deployments
    model_deployments_str = os.environ.get("AZURE_OPENAI_MODEL_DEPLOYMENTS", "{}")
    try:
        model_deployments = json.loads(model_deployments_str)
    except json.JSONDecodeError:
        model_deployments = {"chat": "o1"}  # Default to o1 model

    # Skip if no endpoint
    if not endpoint:
        print("Azure OpenAI endpoint not configured, skipping test")
        return

    # Create a config
    config = Config(openai_api_key="", openai_org_id="")

    # Set Azure configuration
    openai_config = {
        "api_type": "azure",
        "endpoint": endpoint,
        "api_version": api_version,
        "model_deployments": model_deployments,
    }

    # Add Entra ID authentication if enabled
    if use_entra_id:
        openai_config["use_entra_id"] = True

        if auth_method == "bearer_token":
            openai_config["auth_method"] = "bearer_token"
            if token_scope:
                openai_config["token_scope"] = token_scope
        else:
            # Standard Entra ID with managed identity or client credentials
            tenant_id = os.environ.get("AZURE_TENANT_ID", "")
            client_id = os.environ.get("AZURE_CLIENT_ID", "")
            client_secret = os.environ.get("AZURE_CLIENT_SECRET", "")

            if tenant_id:
                openai_config["tenant_id"] = tenant_id
            if client_id:
                openai_config["client_id"] = client_id
            if client_secret:
                openai_config["client_secret"] = client_secret

    config.openai = openai_config

    # Print config for debugging (without sensitive values)
    safe_config = dict(openai_config)
    if "client_secret" in safe_config:
        safe_config["client_secret"] = "***"
    print(f"Using OpenAI configuration: {safe_config}")

    # Create a client
    client = OpenAIClient(config, async_mode=True)

    # Test a simple completion
    prompt = "Generate a one-sentence summary of this Python function: def add(a, b): return a + b"
    response = await client.get_completion(prompt, temperature=0.0)

    # Verify we got a sensible response
    assert response and len(response) > 0, "No response from Azure OpenAI API"
    assert (
        "add" in response.lower() or "sum" in response.lower()
    ), "Response doesn't mention function purpose"

    print(f"Azure OpenAI response: {response}")
    print("Azure OpenAI integration test succeeded!")


# Main function to run the test directly
if __name__ == "__main__":
    asyncio.run(test_azure_openai_direct_completion())

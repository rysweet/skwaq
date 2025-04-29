"""Azure OpenAI direct integration tests.

These tests verify direct integration with Azure OpenAI using the OpenAI Python SDK
without going through the autogen-core layer that's causing test issues.
"""

import asyncio
import json
import os
import sys

from azure.identity import DefaultAzureCredential

try:
    from dotenv import find_dotenv, load_dotenv

    HAS_DOTENV = True
except ImportError:
    HAS_DOTENV = False

# Load environment variables
if HAS_DOTENV:
    dotenv_path = find_dotenv()
    if dotenv_path:
        print(f"Loading configuration from .env file: {dotenv_path}")
        load_dotenv(dotenv_path)

# Check for OpenAI package
try:
    import openai

    HAS_OPENAI = True
except ImportError:
    HAS_OPENAI = False
    print("OpenAI package not installed. Install with: pip install openai")
    sys.exit(1)


async def test_azure_openai_direct():
    """Test direct connection to Azure OpenAI using the OpenAI Python SDK."""
    # Get configuration from environment
    endpoint = os.environ.get("AZURE_OPENAI_ENDPOINT")
    api_version = os.environ.get("AZURE_OPENAI_API_VERSION", "2023-05-15")
    use_entra_id = os.environ.get("AZURE_OPENAI_USE_ENTRA_ID", "").lower() in (
        "true",
        "yes",
        "1",
        "y",
    )

    # Get model deployments
    model_deployments_str = os.environ.get("AZURE_OPENAI_MODEL_DEPLOYMENTS", "{}")
    try:
        model_deployments = json.loads(model_deployments_str)
        deployment_name = model_deployments.get("chat", "o1")
    except json.JSONDecodeError:
        deployment_name = "o1"  # Default

    # Skip if no endpoint
    if not endpoint:
        print("Azure OpenAI endpoint not configured, skipping test")
        return

    # Set up authentication
    if use_entra_id:
        # Get token scope from environment or use default
        token_scope = os.environ.get(
            "AZURE_OPENAI_TOKEN_SCOPE", "https://cognitiveservices.azure.com/.default"
        )
        print(f"Using Azure AD authentication with scope: {token_scope}")

        # Create Azure credential
        azure_credential = DefaultAzureCredential()

        # Configure the client with Azure AD authentication
        client = openai.AsyncAzureOpenAI(
            api_version=api_version,
            azure_endpoint=endpoint,
            azure_ad_token_provider=lambda: azure_credential.get_token(
                token_scope
            ).token,
        )
    else:
        # Use API key authentication
        api_key = os.environ.get("AZURE_OPENAI_API_KEY")
        if not api_key:
            print("Azure OpenAI API key not configured, skipping test")
            return

        # Configure the client with API key authentication
        client = openai.AsyncAzureOpenAI(
            api_version=api_version,
            azure_endpoint=endpoint,
            api_key=api_key,
        )
        print("Using API key authentication")

    # Create a test prompt
    messages = [
        {
            "role": "system",
            "content": "You are a helpful assistant that explains code.",
        },
        {
            "role": "user",
            "content": "What does this function do? def add(a, b): return a + b",
        },
    ]

    try:
        # Make the API call
        print(f"Making API call to Azure OpenAI deployment: {deployment_name}")

        # Try without temperature if model doesn't support it
        try:
            response = await client.chat.completions.create(
                model=deployment_name,
                messages=messages,
                temperature=0.0,
            )
        except Exception as e:
            if "temperature" in str(e):
                print("Temperature parameter not supported, trying without it")
                response = await client.chat.completions.create(
                    model=deployment_name,
                    messages=messages,
                )
            else:
                raise

        # Print the response
        result = response.choices[0].message.content
        print(f"Azure OpenAI response: {result}")

        # Validate the response
        assert result and len(result) > 0, "No response from Azure OpenAI API"
        assert (
            "add" in result.lower() or "sum" in result.lower()
        ), "Response doesn't mention function purpose"

        print("Azure OpenAI direct integration test succeeded!")
        return True

    except Exception as e:
        print(f"Error calling Azure OpenAI API: {str(e)}")
        return False


# Main function to run the test directly
if __name__ == "__main__":
    result = asyncio.run(test_azure_openai_direct())
    if not result:
        sys.exit(1)

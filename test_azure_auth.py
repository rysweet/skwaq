#!/usr/bin/env python3
"""Test script for Azure OpenAI authentication and environment setup."""

import os
import json
import asyncio
from skwaq.core.openai_client import get_openai_client, test_openai_connection
from skwaq.utils.config import get_config, Config

async def test_authentication():
    """Test Azure OpenAI authentication."""
    print("Testing Azure OpenAI Authentication")
    print("---------------------------------")
    
    # Get configuration
    config = get_config()
    
    # Check .env file
    print("Checking for .env file:")
    env_path = os.path.join(os.getcwd(), ".env")
    if os.path.exists(env_path):
        print(f"  ✓ .env file found at {env_path}")
        with open(env_path, 'r') as f:
            env_content = f.read()
            if "AZURE_OPENAI_KEY" in env_content:
                print("  ✓ AZURE_OPENAI_KEY found in .env")
            else:
                print("  ✗ AZURE_OPENAI_KEY not found in .env")
            if "AZURE_OPENAI_ENDPOINT" in env_content:
                print("  ✓ AZURE_OPENAI_ENDPOINT found in .env")
            else:
                print("  ✗ AZURE_OPENAI_ENDPOINT not found in .env")
    else:
        print(f"  ✗ .env file not found at {env_path}")
    
    # Check config values
    print("\nChecking OpenAI configuration:")
    openai_config = config.get("openai", {})
    api_type = openai_config.get("api_type", "")
    endpoint = openai_config.get("endpoint", "")
    api_version = openai_config.get("api_version", "")
    use_entra_id = openai_config.get("use_entra_id", False)
    
    print(f"  API Type: {api_type}")
    print(f"  Endpoint: {endpoint}")
    print(f"  API Version: {api_version}")
    print(f"  Using Entra ID: {use_entra_id}")
    
    if use_entra_id:
        auth_method = openai_config.get("auth_method", "")
        token_scope = openai_config.get("token_scope", "")
        tenant_id = openai_config.get("tenant_id", "")
        
        print(f"  Auth Method: {auth_method}")
        print(f"  Token Scope: {token_scope}")
        print(f"  Tenant ID: {tenant_id}")
    
    # Check Azure OpenAI connection
    print("\nTesting OpenAI connection:")
    try:
        is_connected = await test_openai_connection()
        if is_connected:
            print("  ✓ Successfully connected to Azure OpenAI")
        else:
            print("  ✗ Failed to connect to Azure OpenAI")
    except Exception as e:
        print(f"  ✗ Error testing connection: {str(e)}")
    
    # Try a simple prompt
    print("\nTesting simple prompt:")
    try:
        client = get_openai_client(async_mode=True)
        prompt = "Return only 'OK' to verify this connection is working."
        response = await client.get_completion(prompt, temperature=0.0)
        print(f"  Response: {response}")
    except Exception as e:
        print(f"  ✗ Error with prompt: {str(e)}")

async def main():
    """Run tests."""
    await test_authentication()

if __name__ == "__main__":
    asyncio.run(main())
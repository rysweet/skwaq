#!/usr/bin/env python3
"""Test script for Azure OpenAI integration.

This script tests the direct Azure OpenAI integration using the official OpenAI SDK.
"""

import asyncio
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger("test_azure_openai")

from skwaq.core.openai_client import get_openai_client

# Import the necessary modules
from skwaq.utils.config import get_config


async def test_azure_openai_integration():
    """Test the Azure OpenAI integration with the modern SDK."""
    logger.info("Testing Azure OpenAI integration with modern SDK...")

    try:
        # Get configuration
        config = get_config()

        # Create client
        client = get_openai_client(config, async_mode=True)

        # Create a simple test message
        messages = [
            {"role": "system", "content": "You are a helpful assistant."},
            {"role": "user", "content": "What is the capital of France?"},
        ]

        # Call the chat_completion method
        logger.info("Calling chat_completion...")
        response = await client.chat_completion(messages=messages, temperature=0.7)

        # Check the response format
        logger.info(f"Response type: {type(response)}")
        logger.info(
            f"Response keys: {response.keys() if isinstance(response, dict) else 'Not a dict'}"
        )

        # Print the content
        if isinstance(response, dict) and "content" in response:
            logger.info(f"Content: {response['content'][:100]}...")
            logger.info("✅ Test passed: Response has content key")
            return True
        else:
            logger.error("❌ Test failed: Response missing content key")
            return False

    except Exception as e:
        logger.error(f"Error in test: {e}")
        import traceback

        traceback.print_exc()
        return False


async def test_completion():
    """Test the get_completion method."""
    logger.info("Testing get_completion method...")

    try:
        # Get configuration
        config = get_config()

        # Create client
        client = get_openai_client(config, async_mode=True)

        # Create a simple test message
        prompt = "What is the capital of Italy?"

        # Call the get_completion method
        logger.info("Calling get_completion...")
        response = await client.get_completion(prompt=prompt, temperature=0.7)

        # Check the response format
        logger.info(f"Response type: {type(response)}")
        logger.info(f"Response preview: {response[:100]}...")

        # Verify we got an actual response
        if response and len(response) > 20:
            logger.info("✅ Test passed: Got completion response")
            return True
        else:
            logger.error("❌ Test failed: Response too short or empty")
            return False

    except Exception as e:
        logger.error(f"Error in test: {e}")
        import traceback

        traceback.print_exc()
        return False


async def run_all_tests():
    """Run all tests in sequence."""
    logger.info("Starting Azure OpenAI integration tests...")

    # Run tests
    chat_test = await test_azure_openai_integration()
    completion_test = await test_completion()

    # Report results
    logger.info(f"Chat completion test: {'✅ PASSED' if chat_test else '❌ FAILED'}")
    logger.info(f"Get completion test: {'✅ PASSED' if completion_test else '❌ FAILED'}")

    return chat_test and completion_test


if __name__ == "__main__":
    result = asyncio.run(run_all_tests())
    # Exit with appropriate code
    import sys

    sys.exit(0 if result else 1)

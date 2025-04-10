#!/usr/bin/env python3
"""Test script for LLM integration.

This script tests the integration between the OpenAIClient and the LLMAnalyzer
to verify that our fix for the ChatCompletionClient issue works correctly.
"""

import sys
import asyncio
import logging
from typing import Dict, Any

# Configure logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger("test_llm_integration")

# Import the necessary modules
from skwaq.utils.config import Config, get_config
from skwaq.core.openai_client import OpenAIClient, get_openai_client


async def test_chat_completion() -> None:
    """Test the chat_completion method with the real API."""
    logger.info("Testing chat_completion with real API...")

    # Get configuration
    config = get_config()

    try:
        # Create client
        client = get_openai_client(config, async_mode=True)

        # Create a simple test message
        messages = [
            {"role": "system", "content": "You are a helpful assistant."},
            {
                "role": "user",
                "content": "Say hello and identify what type of response you're returning.",
            },
        ]

        # Call the chat_completion method
        logger.info("Calling chat_completion...")
        response = await client.chat_completion(messages=messages, temperature=0.7)

        # Check the response format
        logger.info(f"Response type: {type(response)}")
        logger.info(
            f"Response keys: {response.keys() if isinstance(response, dict) else 'Not a dict'}"
        )

        # Verify the response has a content field
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


async def test_llm_analyzer_simulation() -> None:
    """Simulate how LLMAnalyzer would use the response."""
    logger.info("Simulating LLMAnalyzer usage pattern...")

    # Get configuration
    config = get_config()

    try:
        # Create client
        client = get_openai_client(config, async_mode=True)

        # Create a test message similar to the LLMAnalyzer
        messages = [
            {
                "role": "system",
                "content": "Identify if this function is a source of data.",
            },
            {
                "role": "user",
                "content": "Function example() { return getUserInput(); }",
            },
        ]

        # Call the chat_completion method
        logger.info("Calling chat_completion...")
        response = await client.chat_completion(messages=messages, temperature=0.2)

        # Simulate LLMAnalyzer processing
        logger.info("Simulating LLMAnalyzer processing...")

        # This is the key line that was failing - get content from response
        content = response.get("content", "")

        logger.info(f"Content retrieved: {content[:100]}...")

        # Simulate further LLMAnalyzer processing
        source_indicators = [
            "is a source",
            "acts as a source",
            "functions as a source",
        ]

        is_source = any(indicator in content.lower() for indicator in source_indicators)
        logger.info(f"Is source: {is_source}")

        logger.info("✅ Test passed: LLMAnalyzer simulation successful")
        return True

    except Exception as e:
        logger.error(f"Error in test: {e}")
        import traceback

        traceback.print_exc()
        return False


async def run_all_tests() -> None:
    """Run all tests in sequence."""
    logger.info("Starting LLM integration tests...")

    # Run tests
    chat_test = await test_chat_completion()
    analyzer_test = await test_llm_analyzer_simulation()

    # Report results
    if chat_test and analyzer_test:
        logger.info("✅ All tests passed!")
        sys.exit(0)
    else:
        logger.error("❌ Some tests failed!")
        sys.exit(1)


if __name__ == "__main__":
    # Run the tests asynchronously
    asyncio.run(run_all_tests())

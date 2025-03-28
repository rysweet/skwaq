#!/usr/bin/env python3
"""Test script for autogen compatibility.

This script tests that the autogen_core.ChatCompletionClient is correctly patched.
"""

import sys
import asyncio
import logging
from typing import Dict, Any

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")
logger = logging.getLogger("test_autogen_compat")

# First, run the patch
import autogen_patch

# Now test that we can import and use ChatCompletionClient
def test_chat_completion_client_exists():
    """Test that ChatCompletionClient exists in autogen_core."""
    import autogen_core
    
    # Check that ChatCompletionClient is available
    logger.info(f"Testing if ChatCompletionClient exists in autogen_core")
    assert hasattr(autogen_core, "ChatCompletionClient"), "ChatCompletionClient does not exist in autogen_core"
    
    # Create an instance
    client = autogen_core.ChatCompletionClient(
        config_list=[{"model": "gpt-4", "api_key": "test-key"}],
        is_async=True
    )
    
    logger.info(f"Successfully created ChatCompletionClient instance")
    return True

async def test_generate():
    """Test the generate method of ChatCompletionClient."""
    import autogen_core
    
    client = autogen_core.ChatCompletionClient(
        config_list=[{"model": "gpt-4", "api_key": "test-key"}],
        is_async=True
    )
    
    # Test that we can call generate (this will return a mock response)
    messages = [{"role": "user", "content": "Hello"}]
    response = await client.generate(messages=messages)
    
    # Verify the response structure
    logger.info(f"Response type: {type(response)}")
    logger.info(f"Has choices: {hasattr(response, 'choices')}")
    
    # Check that we can access message content
    message = response.choices[0].message
    logger.info(f"Message type: {type(message)}")
    logger.info(f"Message content: {message.get('content', 'No content')}")
    
    return True

async def run_tests():
    """Run all tests."""
    tests_passed = []
    
    # Test 1: ChatCompletionClient exists
    try:
        test_result = test_chat_completion_client_exists()
        tests_passed.append(test_result)
        logger.info(f"Test 1 - ChatCompletionClient exists: {'✅ PASSED' if test_result else '❌ FAILED'}")
    except Exception as e:
        logger.error(f"Test 1 failed with error: {e}")
        tests_passed.append(False)
    
    # Test 2: generate method works
    try:
        test_result = await test_generate()
        tests_passed.append(test_result)
        logger.info(f"Test 2 - generate method works: {'✅ PASSED' if test_result else '❌ FAILED'}")
    except Exception as e:
        logger.error(f"Test 2 failed with error: {e}")
        tests_passed.append(False)
    
    # Final result
    all_passed = all(tests_passed)
    logger.info(f"Test result: {all_passed}")
    return 0 if all_passed else 1

if __name__ == "__main__":
    exit_code = asyncio.run(run_tests())
    sys.exit(exit_code)
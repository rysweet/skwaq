#!/usr/bin/env python
"""Script to run tests with appropriate mocking for dependencies.

This script allows running tests without requiring all external dependencies to be installed.
It automatically mocks certain problematic imports.
"""

import sys
import os
import importlib
import unittest
import pytest
from unittest.mock import MagicMock, patch


def setup_mocks():
    """Set up mocks for external dependencies."""
    # List of modules to mock
    mock_modules = [
        "autogen_core",
        "autogen_core.agent",
        "autogen_core.event",
        "autogen_core.code_utils",
        "autogen_core.memory",
        "autogen.core",
        "github",
        "git",
    ]
    
    # Create mocks for all these modules
    sys.modules.update((mod_name, MagicMock()) for mod_name in mock_modules)
    
    # Make sure commonly used classes from these modules are available
    sys.modules["github"].Github = MagicMock()
    sys.modules["github"].GithubException = type("GithubException", (Exception,), {})
    sys.modules["github"].Auth = MagicMock()
    sys.modules["git"].Repo = MagicMock()
    sys.modules["git"].GitCommandError = type("GitCommandError", (Exception,), {})
    
    # Set up autogen_core modules
    agent_mock = MagicMock()
    event_mock = MagicMock()
    code_utils_mock = MagicMock()
    memory_mock = MagicMock()
    
    sys.modules["autogen_core"].agent = agent_mock
    sys.modules["autogen_core"].event = event_mock
    sys.modules["autogen_core"].code_utils = code_utils_mock
    sys.modules["autogen_core"].memory = memory_mock
    
    # Set up common classes
    sys.modules["autogen_core"].agent.Agent = type("Agent", (), {})
    sys.modules["autogen_core"].agent.ChatAgent = type("ChatAgent", (), {})
    sys.modules["autogen_core"].event.BaseEvent = type("BaseEvent", (), {"__init__": lambda self, **kwargs: None})
    sys.modules["autogen_core"].event.Event = type("Event", (), {})
    sys.modules["autogen_core"].event.EventHook = type("EventHook", (), {})
    sys.modules["autogen_core"].memory.MemoryRecord = type("MemoryRecord", (), {})
    
    # Set up autogen.core
    sys.modules["autogen.core"].chat_complete_tokens = MagicMock()


def run_tests():
    """Run all tests or specified tests."""
    # Set up mocks first
    setup_mocks()
    
    # Get arguments from command line
    args = sys.argv[1:] if len(sys.argv) > 1 else ["tests/"]
    
    # Construct pytest arguments
    pytest_args = [
        "-v",                # Verbose
        "--no-header",       # No header
        "--tb=native",       # Native traceback style
    ] + args
    
    # Run pytest
    result = pytest.main(pytest_args)
    
    # Return the exit code
    return result


if __name__ == "__main__":
    sys.exit(run_tests())
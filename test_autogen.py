"""Test script for autogen-core integration."""

import os
import sys
import logging

# Configure basic logging
logging.basicConfig(level=logging.INFO)

# Add the project root to the path so imports work correctly
project_root = os.path.dirname(os.path.abspath(__file__))
if project_root not in sys.path:
    sys.path.insert(0, project_root)


def test_autogen_core():
    """Test basic autogen-core functionality."""
    print("Testing autogen-core integration...")

    try:
        import autogen_core

        print(f"Autogen-core version: {autogen_core.__version__}")

        # Test creating a basic agent
        from autogen_core import Agent, BaseAgent

        # Check Agent implementation details
        agent_methods = [method for method in dir(Agent) if not method.startswith("_")]
        print(f"Agent methods: {', '.join(agent_methods)}")

        # Create a simple agent
        agent = Agent(name="TestAgent")
        print(f"Successfully created agent: {agent.name}")

        # Check event system
        from autogen_core import event

        print(f"Event system available: {event is not None}")

        print("All autogen_core core tests passed!")
        return True
    except Exception as e:
        print(f"Error testing autogen-core: {e}")
        import traceback

        traceback.print_exc()
        return False


def test_skwaq_integration():
    """Test integration with our codebase."""
    print("\nTesting Skwaq integration with autogen-core...")

    try:
        # Import our agent integration
        from skwaq.agents.autogen_integration import (
            AutogenAgentAdapter,
            AutogenGroupChatAdapter,
        )

        # Create adapter
        adapter = AutogenAgentAdapter(
            name="TestAgent", system_message="You are a test agent.", model="gpt-4"
        )
        print(f"Successfully created adapter: {adapter.name}")

        print("Skwaq integration tests passed!")
        return True
    except Exception as e:
        print(f"Error testing Skwaq integration: {e}")
        import traceback

        traceback.print_exc()
        return False


if __name__ == "__main__":
    core_success = test_autogen_core()
    skwaq_success = test_skwaq_integration()
    sys.exit(0 if core_success and skwaq_success else 1)

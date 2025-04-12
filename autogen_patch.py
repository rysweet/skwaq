"""Patch script for autogen_core compatibility.

This script patches Python's import system to redirect imports from
autogen_core.agent, autogen_core.event, etc. to our compatibility module.
"""

import logging
import os
import sys
import types

# Configure logging first
logger = logging.getLogger(__name__)

# Modify Python path before any relative imports
project_root = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, project_root)

# Now import the modules after path is set up
import autogen_core
from skwaq.agents.autogen_compat import (
    ChatCompletionClient,
    GroupChat,
    __version__,
    agent,
    code_utils,
    event,
    memory,
)


# Define proxy modules
class AutogenProxy(types.ModuleType):
    """Proxy for the autogen_core module."""

    def __init__(self):
        """Initialize the proxy."""
        super().__init__("autogen_core")
        self.__dict__.update(autogen_core.__dict__)

        # Add our GroupChat class
        self.GroupChat = GroupChat

        # Add ChatCompletionClient class
        self.ChatCompletionClient = ChatCompletionClient

        # Add our submodules
        self.agent = agent
        self.event = event
        self.code_utils = code_utils
        self.memory = memory


# Create the proxy
autogen_proxy = AutogenProxy()

# Register the proxy
sys.modules["autogen_core"] = autogen_proxy
sys.modules["autogen_core.agent"] = agent
sys.modules["autogen_core.event"] = event
sys.modules["autogen_core.code_utils"] = code_utils
sys.modules["autogen_core.memory"] = memory

print(f"Patched autogen_core ({__version__}) with compatibility layer")


def test_patch():
    """Test that the patch is working."""
    try:
        import autogen_core.agent
        import autogen_core.event

        agent = autogen_core.agent.ChatAgent(
            name="TestAgent",
            system_message="You are a helpful assistant.",
            llm_config={"model": "gpt-3.5-turbo"},
        )
        print(f"Created agent: {agent.name}")

        return True
    except Exception as e:
        print(f"Patch test failed: {e}")
        return False


if __name__ == "__main__":
    success = test_patch()
    sys.exit(0 if success else 1)

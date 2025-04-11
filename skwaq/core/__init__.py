"""Core module for Skwaq vulnerability assessment copilot.

This module contains core functionality for the Skwaq vulnerability assessment copilot,
including OpenAI client, release management, installation, and documentation tools.
"""

# Import the main modules to make them available via the package
from .release_manager import get_release_manager, ReleaseManager
from .installation import InstallationManager
from .documentation import DocumentationManager

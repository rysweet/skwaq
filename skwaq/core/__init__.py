"""Core module for Skwaq vulnerability assessment copilot.

This module contains core functionality for the Skwaq vulnerability assessment copilot,
including OpenAI client, release management, installation, and documentation tools.
"""

from .documentation import DocumentationManager
from .installation import InstallationManager

# Import the main modules to make them available via the package
from .release_manager import ReleaseManager, get_release_manager

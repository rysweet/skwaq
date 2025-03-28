"""Skwaq - Vulnerability Assessment Copilot.

A multiagent AI system for discovering security vulnerabilities in codebases.
"""

__version__ = "0.1.0"

# Provide a direct entry point for the CLI
def main():
    """Run the Skwaq CLI."""
    from skwaq.cli.refactored_main import run
    run()

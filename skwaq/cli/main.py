"""Main entry point for the Skwaq CLI.

This module provides the main entry point for the Skwaq CLI application.
It is a thin wrapper around the refactored implementation to maintain
backward compatibility with existing code.
"""

import sys
import asyncio
from typing import Optional, List, Dict, Any, Type

# Import from the refactored implementation
from .refactored_main import main as refactored_main
from .refactored_main import run as refactored_run
from .refactored_main import COMMAND_HANDLERS
from .commands.base import CommandHandler
from .ui.console import console, error, print_banner


# Re-export symbols for backward compatibility
# NOTE: main must be a regular function, not a coroutine, for entry point use
def main():
    """Run the CLI application synchronously."""
    try:
        return asyncio.run(refactored_main())
    except KeyboardInterrupt:
        console.print("\n[yellow]Operation cancelled by user.[/yellow]")
        return 130
    except Exception as e:
        error(f"An unexpected error occurred: {str(e)}")
        console.print_exception(show_locals=False)
        return 1


run = refactored_run
command_handlers = COMMAND_HANDLERS


# These functions are deprecated and will be removed in a future version
def create_parser(*args, **kwargs):
    """Create a parser (deprecated, use parser.base.create_parser instead)."""
    from .parser.base import create_parser as new_create_parser

    return new_create_parser(*args, **kwargs)


def register_parsers(*args, **kwargs):
    """Register parsers (deprecated, use parser.commands.register_all_parsers instead)."""
    from .parser.commands import register_all_parsers

    return register_all_parsers(*args, **kwargs)


def handle_command(*args, **kwargs):
    """Handle a command (deprecated, use appropriate CommandHandler instead)."""
    error("handle_command is deprecated. Use appropriate CommandHandler instead.")
    return 1


# For backward compatibility with entry points
if __name__ == "__main__":
    run()

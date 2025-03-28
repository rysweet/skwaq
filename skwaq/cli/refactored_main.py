"""Main entry point for the Skwaq CLI.

This module provides the main entry point for the Skwaq CLI application.
It handles command-line argument parsing and dispatches to the appropriate
command handlers.
"""

import sys
import asyncio
import argparse
from typing import Dict, Optional, Type, List, Any

from .parser.base import create_parser
from .parser.commands import register_all_parsers
from .ui.console import console, error, print_banner
from .commands.base import CommandHandler

from .commands.repository_commands import RepositoryCommandHandler
from .commands.system_commands import VersionCommandHandler, GuiCommandHandler
from .commands.workflow_commands import (
    QACommandHandler,
    GuidedInquiryCommandHandler,
    ToolCommandHandler,
    VulnerabilityResearchCommandHandler,
    InvestigationCommandHandler,  # Moved from investigation_commands.py
)
from .commands.ingest_commands import IngestCommandHandler
from .commands.config_commands import ConfigCommandHandler

# Map of commands to their handler classes
COMMAND_HANDLERS: Dict[str, Type[CommandHandler]] = {
    "repo": RepositoryCommandHandler,
    "investigations": InvestigationCommandHandler,
    "version": VersionCommandHandler,
    "gui": GuiCommandHandler,
    "qa": QACommandHandler,
    "inquiry": GuidedInquiryCommandHandler,
    "tool": ToolCommandHandler,
    "research": VulnerabilityResearchCommandHandler,
    "ingest": IngestCommandHandler,
    "config": ConfigCommandHandler,
}

async def main(args: Optional[List[str]] = None) -> int:
    """Run the Skwaq CLI.
    
    Args:
        args: Command-line arguments (defaults to sys.argv[1:])
        
    Returns:
        Exit code (0 for success, non-zero for errors)
    """
    # Create and configure the argument parser
    parser = create_parser()
    register_all_parsers(parser)
    
    # Parse arguments
    parsed_args = parser.parse_args(args)
    
    # If --version flag is set, show version and exit
    if hasattr(parsed_args, 'version') and parsed_args.version:
        version_handler = VersionCommandHandler(parsed_args)
        return await version_handler.handle()
    
    # Show banner for non-json output
    if not (hasattr(parsed_args, 'output') and parsed_args.output == "json"):
        print_banner()
    
    # Check if a command was specified
    if not hasattr(parsed_args, 'command') or not parsed_args.command:
        error("No command specified. Use --help to see available commands.")
        return 1
    
    # Get the handler for the specified command
    handler_class = COMMAND_HANDLERS.get(parsed_args.command)
    
    if not handler_class:
        error(f"Unknown command: {parsed_args.command}")
        return 1
    
    # Create and run the handler
    handler = handler_class(parsed_args)
    return await handler.handle()

def run() -> None:
    """Run the CLI application."""
    try:
        # Run the async main function
        exit_code = asyncio.run(main())
        sys.exit(exit_code)
    except KeyboardInterrupt:
        # Handle Ctrl+C gracefully
        console.print("\n[yellow]Operation cancelled by user.[/yellow]")
        sys.exit(130)
    except Exception as e:
        # Handle unexpected errors
        error(f"An unexpected error occurred: {str(e)}")
        console.print_exception(show_locals=False)
        sys.exit(1)

if __name__ == "__main__":
    run()
"""Main entry point for the Skwaq CLI.

This module provides the main entry point for the Skwaq CLI application.
"""

import asyncio
import sys
from typing import Dict, List, Optional, Type

from .. import __version__
from .commands.base import CommandHandler
from .commands.config_commands import ConfigCommandHandler
from .commands.ingest_commands import IngestCommandHandler
from .commands.repository_commands import RepositoryCommandHandler
from .commands.system_commands import GuiCommandHandler, ServiceCommandHandler, VersionCommandHandler
from .commands.workflow_commands import (
    GuidedInquiryCommandHandler,
    InvestigationCommandHandler,
    QACommandHandler,
    SourcesAndSinksCommandHandler,
    ToolCommandHandler,
    VulnerabilityResearchCommandHandler,
)
from .parser.base import create_parser
from .parser.commands import register_all_parsers
from .ui.console import console, error, print_banner

# Map of commands to their handler classes
COMMAND_HANDLERS: Dict[str, Type[CommandHandler]] = {
    "repo": RepositoryCommandHandler,
    "investigations": InvestigationCommandHandler,
    "version": VersionCommandHandler,
    "gui": GuiCommandHandler,
    "service": ServiceCommandHandler,
    "qa": QACommandHandler,
    "inquiry": GuidedInquiryCommandHandler,
    "tool": ToolCommandHandler,
    "research": VulnerabilityResearchCommandHandler,
    "sources-and-sinks": SourcesAndSinksCommandHandler,
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
    # Get CLI arguments
    if args is None:
        args = sys.argv[1:]

    # Check if help is requested and show banner
    if not args or "-h" in args or "--help" in args:
        print_banner(version=__version__)

    # Create and configure the argument parser
    parser = create_parser()
    register_all_parsers(parser)

    # Parse arguments
    parsed_args = parser.parse_args(args)

    # If --version flag is set, show version and exit
    if hasattr(parsed_args, "version") and parsed_args.version:
        version_handler = VersionCommandHandler(parsed_args)
        return await version_handler.handle()

    # Show banner for non-json output and non-help commands
    show_banner = not hasattr(parsed_args, "output") or parsed_args.output != "json"

    # Only show banner for normal commands (not help or version)
    help_requested = len(args) > 0 and (
        args[0] == "-h" or args[0] == "--help" or args[0] == "--version"
    )
    if show_banner and not help_requested:
        print_banner(version=__version__)

    # Check if a command was specified
    if not hasattr(parsed_args, "command") or not parsed_args.command:
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


# For backward compatibility with entry points
if __name__ == "__main__":
    run()
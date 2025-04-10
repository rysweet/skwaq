"""Base parser for the Skwaq CLI."""

import argparse
import sys
import io
from typing import Optional, Callable, Dict, Any, List, Union, Tuple

from ..ui.console import print_banner


# We'll handle banner printing directly, so no need for a custom formatter


class SkwaqArgumentParser:
    """Argument parser for the Skwaq CLI.

    This class handles the creation and configuration of the command-line
    argument parser for the Skwaq vulnerability assessment tool.
    """

    def __init__(
        self, description: str = "Skwaq Vulnerability Assessment Tool"
    ) -> None:
        """Initialize the argument parser.

        Args:
            description: Description of the CLI tool
        """
        self.parser = argparse.ArgumentParser(description=description)
        self.subparsers = self.parser.add_subparsers(
            dest="command", help="Available commands"
        )
        self.command_parsers: Dict[str, argparse.ArgumentParser] = {}

    def create_command_parser(
        self, name: str, help_text: str, **kwargs: Any
    ) -> argparse.ArgumentParser:
        """Create a new command parser.

        Args:
            name: Command name
            help_text: Help text for the command
            **kwargs: Additional arguments for add_parser

        Returns:
            Command parser
        """
        parser = self.subparsers.add_parser(name, help=help_text, **kwargs)
        self.command_parsers[name] = parser
        return parser

    def get_command_parser(self, name: str) -> Optional[argparse.ArgumentParser]:
        """Get a command parser by name.

        Args:
            name: Command name

        Returns:
            Command parser or None if not found
        """
        return self.command_parsers.get(name)

    def parse_args(self, args: Optional[List[str]] = None) -> argparse.Namespace:
        """Parse command-line arguments.

        Args:
            args: Command-line arguments to parse (defaults to sys.argv[1:])

        Returns:
            Parsed arguments
        """
        if args is None:
            args = sys.argv[1:]

        # If no arguments provided, show help (only in non-test environments)
        if not args and "pytest" not in sys.modules:
            # Banner is printed by the main function
            self.parser.print_help()
            sys.exit(0)

        # Process the arguments
        return self.parser.parse_args(args)


def create_parser() -> SkwaqArgumentParser:
    """Create the main Skwaq CLI parser.

    Returns:
        Configured argument parser
    """
    parser = SkwaqArgumentParser(description="Skwaq - Vulnerability Assessment Tool")

    # Add global arguments
    parser.parser.add_argument(
        "--verbose", "-v", action="store_true", help="Enable verbose output"
    )

    parser.parser.add_argument(
        "--quiet", "-q", action="store_true", help="Suppress non-error output"
    )

    parser.parser.add_argument(
        "--no-color", action="store_true", help="Disable colored output"
    )

    parser.parser.add_argument(
        "--version", action="store_true", help="Show version information and exit"
    )

    return parser

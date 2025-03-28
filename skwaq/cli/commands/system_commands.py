"""System-level commands for the Skwaq CLI."""

import argparse
import os
import sys
import subprocess
import webbrowser
from pathlib import Path
from typing import Dict, Optional

from ..ui.console import console, success, error, info, print_banner
from ..ui.progress import create_status_indicator
from .base import CommandHandler, handle_command_error


class VersionCommandHandler(CommandHandler):
    """Handler for the version command."""

    @handle_command_error
    async def handle(self) -> int:
        """Handle the version command.

        Returns:
            Exit code (0 for success, non-zero for errors)
        """
        # Import version from package or determine from git
        try:
            from ... import __version__
        except ImportError:
            __version__ = self._get_version_from_git()

        print_banner(include_version=True, version=__version__)

        # Display additional system information
        info("System Information:")
        console.print(f"  Python: [cyan]{sys.version.split()[0]}[/cyan]")
        console.print(f"  Platform: [cyan]{sys.platform}[/cyan]")

        # Display configuration status
        try:
            from ...utils.config import get_config

            config = get_config()
            has_openai_key = bool(config.get("openai.api_key"))
            console.print(
                f"  API Configuration: [{'green' if has_openai_key else 'red'}]{'Configured' if has_openai_key else 'Not Configured'}[/{'green' if has_openai_key else 'red'}]"
            )
        except Exception:
            console.print("  API Configuration: [red]Error loading configuration[/red]")

        return 0

    def _get_version_from_git(self) -> str:
        """Get the version from git if available.

        Returns:
            Version string
        """
        try:
            # Try to get version from git
            result = subprocess.run(
                ["git", "describe", "--tags", "--always"],
                capture_output=True,
                text=True,
                check=False,
            )

            if result.returncode == 0:
                return result.stdout.strip()
            else:
                return "1.0.0-dev"
        except Exception:
            return "1.0.0-dev"


class GuiCommandHandler(CommandHandler):
    """Handler for the GUI command."""

    @handle_command_error
    async def handle(self) -> int:
        """Handle the GUI command.

        Returns:
            Exit code (0 for success, non-zero for errors)
        """
        port = self.args.port
        host = self.args.host
        no_browser = self.args.no_browser

        # Check if required packages are installed
        try:
            import flask
        except ImportError:
            error("Flask is not installed. The GUI requires Flask to run.")
            info("Install required packages with: pip install flask flask-cors")
            return 1

        # Launch GUI
        with create_status_indicator(
            f"[bold blue]Starting GUI server on {host}:{port}...", spinner="dots"
        ) as status:
            # Import here to avoid circular imports
            try:
                from ...gui.server import create_app, start_server

                # Create Flask app
                app = create_app()

                # Start server in a separate thread
                server_thread = start_server(app, host=host, port=port)

                status.update(f"[bold green]GUI server started on {host}:{port}!")

                # Open browser if requested
                if not no_browser:
                    webbrowser.open(f"http://{host}:{port}")
                    console.print(
                        f"Opening browser to [link=http://{host}:{port}]http://{host}:{port}[/link]"
                    )

                # Print instructions
                console.print()
                console.print(
                    f"GUI is running at [link=http://{host}:{port}]http://{host}:{port}[/link]"
                )
                console.print("Press Ctrl+C to stop the server")

                # Keep the main thread running
                try:
                    while True:
                        import time

                        time.sleep(1)
                except KeyboardInterrupt:
                    console.print("\n[yellow]Shutting down GUI server...[/yellow]")
                    # Cleanup will happen automatically when the process exits

                return 0

            except Exception as e:
                status.update("[bold red]Failed to start GUI server!")
                error(f"Failed to start GUI server: {str(e)}")
                return 1

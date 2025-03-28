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
        no_browser = self.args.no_browser

        # Find the run_gui.sh script
        script_path = Path(__file__).resolve().parents[3] / "scripts" / "dev" / "run_gui.sh"
        
        if not script_path.exists():
            error(f"GUI script not found at {script_path}")
            return 1

        # Launch GUI
        with create_status_indicator(
            "[bold blue]Starting GUI frontend...", spinner="dots"
        ) as status:
            try:
                # Default React port is 3000
                port = 3000
                host = "localhost"
                
                status.update("[bold green]Launching GUI frontend...")
                
                # Use subprocess to run the shell script
                # We don't wait for it to complete because npm start runs continuously
                process = subprocess.Popen(
                    [str(script_path)],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True
                )
                
                # Wait a moment for the server to start
                import time
                time.sleep(2)
                
                # Open browser if requested
                if not no_browser:
                    url = f"http://{host}:{port}"
                    status.update(f"[bold green]Opening browser to {url}")
                    webbrowser.open(url)
                
                # Print instructions
                console.print()
                console.print(
                    f"GUI is starting and will be available at [link=http://{host}:{port}]http://{host}:{port}[/link]"
                )
                console.print("The React development server will open a browser window automatically")
                console.print("Press Ctrl+C in the terminal where the server is running to stop it")
                
                # Return immediately so user can continue using CLI
                return 0
                
            except Exception as e:
                status.update("[bold red]Failed to start GUI!")
                error(f"Failed to start GUI: {str(e)}")
                return 1

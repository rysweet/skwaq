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
                # We'll log the output for diagnostic purposes
                process = subprocess.Popen(
                    [str(script_path)],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    bufsize=1,  # Line buffered
                )
                
                # Add a listener for the script output
                import threading
                
                def log_output(stream, prefix):
                    for line in stream:
                        if "Installing" in line or "Starting" in line or "Error" in line:
                            if "Error" in line:
                                error(f"{line.strip()}")
                            else:
                                info(f"{line.strip()}")
                
                # Start threads to handle stdout and stderr
                stdout_thread = threading.Thread(
                    target=log_output, args=(process.stdout, "OUT")
                )
                stderr_thread = threading.Thread(
                    target=log_output, args=(process.stderr, "ERR")
                )
                stdout_thread.daemon = True
                stderr_thread.daemon = True
                stdout_thread.start()
                stderr_thread.start()
                
                # Wait for the React app to begin starting
                import time
                import socket
                
                # Function to check if port is in use (server is running)
                def is_port_in_use(port, host='localhost'):
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                        try:
                            s.settimeout(0.5)
                            s.connect((host, port))
                            return True
                        except (socket.error, socket.timeout):
                            return False
                
                # Wait for server to start (up to 60 seconds)
                max_wait_time = 60  # seconds
                start_time = time.time()
                server_started = False
                
                while time.time() - start_time < max_wait_time:
                    if is_port_in_use(port):
                        server_started = True
                        break
                    time.sleep(1)
                    status.update(f"[bold blue]Waiting for GUI server to start ({int(time.time() - start_time)}s)...")
                
                if not server_started:
                    status.update(f"[bold yellow]Server not detected within {max_wait_time} seconds, but it might still be starting...")
                    info("The GUI server appears to be starting but may take longer to initialize")
                else:
                    status.update(f"[bold green]GUI server detected running on port {port}!")
                
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

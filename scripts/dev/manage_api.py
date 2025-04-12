#!/usr/bin/env python3
"""Manage the Skwaq API server for development and testing."""

import argparse
import logging
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler()],
)
logger = logging.getLogger(__name__)

# Get the root directory of the project
ROOT_DIR = Path(__file__).parent.parent.parent
PID_FILE = ROOT_DIR / "api_server.pid"
API_SCRIPT = ROOT_DIR / "scripts" / "dev" / "run_api.py"
TEST_API_SCRIPT = ROOT_DIR / "scripts" / "dev" / "run_test_api.py"


def start_server(host="localhost", port=5000, debug=False, test_mode=False):
    """Start the API server.

    Args:
        host: Host to bind to
        port: Port to bind to
        debug: Whether to run in debug mode
        test_mode: Whether to run in test mode with authentication disabled
    """
    if is_running():
        logger.info("API server is already running")
        return

    # Select the appropriate script
    script = TEST_API_SCRIPT if test_mode else API_SCRIPT

    # Start the API server as a subprocess
    cmd = [
        sys.executable,
        str(script),
        f"--host={host}",
        f"--port={port}",
        f"--pid-file={PID_FILE}",
    ]

    if debug:
        cmd.append("--debug")

    logger.info(
        f"Starting {'TEST' if test_mode else 'API'} server with command: {' '.join(cmd)}"
    )

    # Use subprocess.Popen to start the server in the background
    process = subprocess.Popen(
        cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True
    )

    # Wait a bit to make sure it starts up
    time.sleep(2)

    # Check if the process is still running
    if process.poll() is None:
        logger.info(
            f"{'TEST' if test_mode else 'API'} server started with PID {process.pid}"
        )
        return True
    else:
        stdout, stderr = process.communicate()
        logger.error(
            f"Failed to start {'TEST' if test_mode else 'API'} server. Error: {stderr}"
        )
        return False


def stop_server():
    """Stop the API server."""
    if not is_running():
        logger.info("API server is not running")
        return True

    try:
        with open(PID_FILE, "r") as f:
            pid = int(f.read().strip())

        logger.info(f"Stopping API server with PID {pid}")
        os.kill(pid, signal.SIGTERM)

        # Wait for it to stop
        for _ in range(5):  # Wait up to 5 seconds
            time.sleep(1)
            try:
                # Check if process still exists
                os.kill(pid, 0)
            except OSError:
                # Process has stopped
                logger.info("API server stopped successfully")
                # Remove PID file if it still exists
                if PID_FILE.exists():
                    PID_FILE.unlink()
                return True

        # If we get here, the process didn't stop gracefully
        logger.warning("API server didn't stop gracefully, forcing termination...")
        os.kill(pid, signal.SIGKILL)
        if PID_FILE.exists():
            PID_FILE.unlink()
        return True

    except Exception as e:
        logger.error(f"Error stopping API server: {e}")
        # Clean up PID file if it exists
        if PID_FILE.exists():
            PID_FILE.unlink()
        return False


def is_running():
    """Check if the API server is running."""
    if not PID_FILE.exists():
        return False

    try:
        with open(PID_FILE, "r") as f:
            pid = int(f.read().strip())

        # Check if process with this PID exists
        try:
            os.kill(pid, 0)
            return True
        except OSError:
            # Process doesn't exist
            PID_FILE.unlink()
            return False

    except Exception:
        return False


def restart_server(host="localhost", port=5000, debug=False, test_mode=False):
    """Restart the API server."""
    stop_server()
    return start_server(host, port, debug, test_mode)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Manage the Skwaq API server for development and testing"
    )
    subparsers = parser.add_subparsers(dest="command", help="Command to execute")

    # Start command
    start_parser = subparsers.add_parser("start", help="Start the API server")
    start_parser.add_argument("--host", default="localhost", help="Host to bind to")
    start_parser.add_argument("--port", type=int, default=5000, help="Port to bind to")
    start_parser.add_argument("--debug", action="store_true", help="Run in debug mode")
    start_parser.add_argument(
        "--test",
        action="store_true",
        help="Run in test mode with authentication disabled",
    )

    # Stop command
    stop_parser = subparsers.add_parser("stop", help="Stop the API server")

    # Restart command
    restart_parser = subparsers.add_parser("restart", help="Restart the API server")
    restart_parser.add_argument("--host", default="localhost", help="Host to bind to")
    restart_parser.add_argument(
        "--port", type=int, default=5000, help="Port to bind to"
    )
    restart_parser.add_argument(
        "--debug", action="store_true", help="Run in debug mode"
    )
    restart_parser.add_argument(
        "--test",
        action="store_true",
        help="Run in test mode with authentication disabled",
    )

    # Status command
    status_parser = subparsers.add_parser(
        "status", help="Check if the API server is running"
    )

    args = parser.parse_args()

    if args.command == "start":
        start_server(args.host, args.port, args.debug, getattr(args, "test", False))
    elif args.command == "stop":
        stop_server()
    elif args.command == "restart":
        restart_server(args.host, args.port, args.debug, getattr(args, "test", False))
    elif args.command == "status":
        if is_running():
            logger.info("API server is running")
        else:
            logger.info("API server is not running")
    else:
        parser.print_help()

#!/usr/bin/env python3
"""Run the Skwaq API server for development."""

import os
import sys
import argparse
import signal
import logging

# Add parent directory to path so we can import skwaq modules
sys.path.append(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
)

from skwaq.api import create_app

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Flag to track if we're supposed to be running
running = True

def signal_handler(sig, frame):
    """Handle termination signals gracefully."""
    global running
    logger.info(f"Received signal {sig}. Shutting down API server...")
    running = False
    sys.exit(0)

if __name__ == "__main__":
    # Register signal handlers
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    parser = argparse.ArgumentParser(
        description="Run the Skwaq API server for development"
    )
    parser.add_argument(
        "--host", default="127.0.0.1", help="Host to bind to (default: 127.0.0.1)"
    )
    parser.add_argument(
        "--port", type=int, default=5000, help="Port to bind to (default: 5000)"
    )
    parser.add_argument("--debug", action="store_true", help="Run in debug mode")
    parser.add_argument("--pid-file", help="File to write PID to")

    args = parser.parse_args()

    # Write PID to file if requested
    if args.pid_file:
        with open(args.pid_file, 'w') as f:
            f.write(str(os.getpid()))
        logger.info(f"PID {os.getpid()} written to {args.pid_file}")

    if args.debug:
        logger.info("Running in debug mode")

    # Create Flask app
    app = create_app()

    logger.info(f"Starting API server at http://{args.host}:{args.port}")
    try:
        app.run(host=args.host, port=args.port, debug=args.debug)
    except KeyboardInterrupt:
        logger.info("API server stopped by keyboard interrupt")
    except Exception as e:
        logger.error(f"API server error: {e}")
    finally:
        # Remove PID file if it exists
        if args.pid_file and os.path.exists(args.pid_file):
            os.remove(args.pid_file)
        logger.info("API server shutdown complete")

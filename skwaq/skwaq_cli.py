#!/usr/bin/env python3
"""Entry point script for the Skwaq vulnerability assessment copilot."""

import logging
import sys

# Configure logging before importing anything else
# This will suppress warnings from blarify_integration during CLI startup
logging.getLogger("skwaq.code_analysis.blarify_integration").setLevel(logging.ERROR)

from skwaq.cli.main import run
from skwaq.utils.logging import setup_logging

if __name__ == "__main__":
    # Set up the main logger
    setup_logging(module_name="skwaq.cli", level=logging.INFO)
    
    # Keep blarify integration warnings at ERROR level to avoid spamming users
    logging.getLogger("skwaq.code_analysis.blarify_integration").setLevel(logging.ERROR)
    
    # Run the main CLI function (run() handles the async execution)
    run()

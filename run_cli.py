#!/usr/bin/env python3
"""
Direct wrapper script to run the Skwaq CLI.
This bypasses the package entry point system.
"""

import sys
from skwaq.cli.refactored_main import run

if __name__ == "__main__":
    run()

#!/usr/bin/env python3
"""
A test script to ensure the CLI works correctly.
"""

import asyncio
import sys

from skwaq.cli.refactored_main import main as refactored_main


def fixed_main():
    """Run the CLI application synchronously."""
    try:
        return asyncio.run(refactored_main())
    except KeyboardInterrupt:
        print("\nOperation cancelled by user.")
        return 130
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(fixed_main())

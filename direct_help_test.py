#!/usr/bin/env python3
"""
Direct test for banner display with help.
This script calls the CLI directly with the --help flag.
"""

import subprocess
import sys

# Run the skwaq CLI with --help directly
subprocess.run([sys.executable, "-m", "skwaq", "--help"])
print("Help command completed.")

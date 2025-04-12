#!/usr/bin/env python
"""
Development script to run the Flask API server.
"""

import logging
import os
import sys

# Add the project root to the path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

from skwaq.api.app import create_app
from skwaq.utils.logging import setup_logging

# Setup logging
setup_logging(level=logging.DEBUG)

# Create the Flask app
app = create_app()

if __name__ == "__main__":
    # Run the server in debug mode
    app.run(host="0.0.0.0", port=5001, debug=True)

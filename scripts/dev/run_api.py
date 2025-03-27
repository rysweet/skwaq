#!/usr/bin/env python3
"""Run the Skwaq API server for development."""

import os
import sys
import argparse

# Add parent directory to path so we can import skwaq modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from skwaq.api.app import app

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Run the Skwaq API server for development')
    parser.add_argument('--host', default='127.0.0.1', help='Host to bind to (default: 127.0.0.1)')
    parser.add_argument('--port', type=int, default=5000, help='Port to bind to (default: 5000)')
    parser.add_argument('--debug', action='store_true', help='Run in debug mode')
    
    args = parser.parse_args()
    
    if args.debug:
        print("Running in debug mode")
    
    print(f"Starting API server at http://{args.host}:{args.port}")
    app.run(host=args.host, port=args.port, debug=args.debug)
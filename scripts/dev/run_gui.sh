#!/bin/bash
# Script to run the Skwaq frontend GUI

# Set the directory to the script's location
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PROJECT_ROOT="$( cd "$SCRIPT_DIR/../.." && pwd )"
FRONTEND_DIR="$PROJECT_ROOT/skwaq/frontend"

# Check if npm is installed
if ! command -v npm &> /dev/null; then
    echo "Error: npm is not installed. Please install npm to run the GUI."
    exit 1
fi

# Check if the frontend directory exists
if [ ! -d "$FRONTEND_DIR" ]; then
    echo "Error: Frontend directory not found at $FRONTEND_DIR"
    exit 1
fi

# Check if node_modules directory exists, if not run npm install
if [ ! -d "$FRONTEND_DIR/node_modules" ]; then
    echo "Installing dependencies..."
    (cd "$FRONTEND_DIR" && npm install)
    
    # Check if install was successful
    if [ $? -ne 0 ]; then
        echo "Error: Failed to install dependencies. Please run 'npm install' in $FRONTEND_DIR"
        exit 1
    fi
fi

# Start the React development server
echo "Starting Skwaq frontend GUI..."
(cd "$FRONTEND_DIR" && npm start)
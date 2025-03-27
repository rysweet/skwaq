#!/bin/bash
# Script to run both the React frontend and Flask backend for development

# Default backend port
BACKEND_PORT=5000

# Parse command-line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --port)
            BACKEND_PORT="$2"
            shift 2
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Start Flask backend
start_backend() {
    echo "Starting Flask backend..."
    cd "$(dirname "$0")/../../"
    
    # Activate virtualenv if it exists
    if [ -d ".venv" ]; then
        source .venv/bin/activate
    fi
    
    # Run Flask with hot reload
    FLASK_APP=skwaq/api/app.py FLASK_ENV=development python -m flask run --host=0.0.0.0 --port=${BACKEND_PORT} &
    BACKEND_PID=$!
    echo "Backend started with PID: $BACKEND_PID on port ${BACKEND_PORT}"
}

# Start React frontend
start_frontend() {
    echo "Starting React frontend..."
    cd "$(dirname "$0")/../../skwaq/frontend"
    
    # Set API URL for React development using the specified backend port
    export REACT_APP_API_URL=http://localhost:${BACKEND_PORT}/api

    # Run npm start
    npm start &
    FRONTEND_PID=$!
    echo "Frontend started with PID: $FRONTEND_PID (connecting to backend on port ${BACKEND_PORT})"
}

# Clean up on exit
cleanup() {
    echo "Stopping development servers..."
    [ -n "$FRONTEND_PID" ] && kill $FRONTEND_PID
    [ -n "$BACKEND_PID" ] && kill $BACKEND_PID
    exit 0
}

# Set up cleanup on script exit
trap cleanup EXIT

# Start both servers
start_backend
start_frontend

echo "Development environment is running!"
echo "Backend: http://localhost:${BACKEND_PORT}"
echo "Frontend: http://localhost:3000"
echo "Press Ctrl+C to stop."

# Wait for user to press Ctrl+C
wait
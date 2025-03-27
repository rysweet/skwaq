#!/bin/bash
# Script to run both the React frontend and Flask backend for development

# Start Flask backend
start_backend() {
    echo "Starting Flask backend..."
    cd "$(dirname "$0")/../../"
    
    # Activate virtualenv if it exists
    if [ -d ".venv" ]; then
        source .venv/bin/activate
    fi
    
    # Run Flask with hot reload
    FLASK_APP=skwaq/api/app.py FLASK_ENV=development python -m flask run --host=0.0.0.0 --port=5000 &
    BACKEND_PID=$!
    echo "Backend started with PID: $BACKEND_PID"
}

# Start React frontend
start_frontend() {
    echo "Starting React frontend..."
    cd "$(dirname "$0")/../../skwaq/frontend"
    
    # Set API URL for React development
    export REACT_APP_API_URL=http://localhost:5000/api

    # Run npm start
    npm start &
    FRONTEND_PID=$!
    echo "Frontend started with PID: $FRONTEND_PID"
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
echo "Backend: http://localhost:5000"
echo "Frontend: http://localhost:3000"
echo "Press Ctrl+C to stop."

# Wait for user to press Ctrl+C
wait
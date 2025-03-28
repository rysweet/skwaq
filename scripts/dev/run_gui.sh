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

# Install or update dependencies
echo "Installing/updating dependencies..."
cd "$FRONTEND_DIR"

# Install missing dependencies
echo "Installing missing dependencies..."
npm install --save react-markdown react-syntax-highlighter remark-gfm file-saver

# Fix api export issue
if grep -q "export default api;" "$FRONTEND_DIR/src/services/api.ts"; then
    echo "Fixing API export..."
    # Create a backup
    cp "$FRONTEND_DIR/src/services/api.ts" "$FRONTEND_DIR/src/services/api.ts.bak"
    # Modify the export
    sed -i.bak 's/export default api;/export default api;\nexport { api };/' "$FRONTEND_DIR/src/services/api.ts"
fi

# Fix useRealTimeEvents export issue
if grep -q "export { useRealTimeEvents" "$FRONTEND_DIR/src/hooks/useRealTimeEvents.ts"; then
    echo "Fixing useRealTimeEvents export..."
    # Create a backup
    cp "$FRONTEND_DIR/src/hooks/useRealTimeEvents.ts" "$FRONTEND_DIR/src/hooks/useRealTimeEvents.ts.bak"
    # Modify the export to include default
    sed -i.bak 's/export { useRealTimeEvents/export { useRealTimeEvents as default, useRealTimeEvents/' "$FRONTEND_DIR/src/hooks/useRealTimeEvents.ts"
fi

# Fix ChatInterface to handle optional parentId
if grep -q "if (msg.parentId)" "$FRONTEND_DIR/src/components/ChatInterface.tsx"; then
    echo "Fixing ChatInterface.tsx..."
    # Create a backup
    cp "$FRONTEND_DIR/src/components/ChatInterface.tsx" "$FRONTEND_DIR/src/components/ChatInterface.tsx.bak"
    # Update type to include optional parentId
    sed -i.bak 's/interface ChatMessage {/interface ChatMessage {\n  parentId?: string;/' "$FRONTEND_DIR/src/services/chatService.ts"
fi

# Start the React development server
echo "Starting Skwaq frontend GUI..."
npm start
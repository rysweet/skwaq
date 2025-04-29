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
npm install --save-dev @types/file-saver

# Create type definitions file if it doesn't exist
if [ ! -d "$FRONTEND_DIR/src/types" ]; then
    echo "Creating types directory..."
    mkdir -p "$FRONTEND_DIR/src/types"
fi

if [ ! -f "$FRONTEND_DIR/src/types/modules.d.ts" ]; then
    echo "Creating type definitions for modules..."
    cat > "$FRONTEND_DIR/src/types/modules.d.ts" << 'EOF'
// Type declarations for modules without their own types

declare module 'react-markdown' {
  import React from 'react';
  
  interface ReactMarkdownProps {
    children: string;
    remarkPlugins?: any[];
    components?: Record<string, React.ComponentType<any>>;
  }
  
  const ReactMarkdown: React.FC<ReactMarkdownProps>;
  export default ReactMarkdown;
}

declare module 'remark-gfm' {
  const remarkGfm: any;
  export default remarkGfm;
}

declare module 'react-syntax-highlighter/dist/esm/styles/prism' {
  export const tomorrow: any;
}

declare module 'react-syntax-highlighter' {
  interface SyntaxHighlighterProps {
    style?: any;
    language?: string;
    PreTag?: string;
    children: string;
    showLineNumbers?: boolean;
    [key: string]: any;
  }
  
  export const Prism: React.FC<SyntaxHighlighterProps>;
}

declare module 'file-saver' {
  export function saveAs(data: Blob | File | string, filename?: string, options?: { type?: string }): void;
}
EOF
fi

# Define simple fix_file function that works on MacOS and Linux
fix_file() {
    local file="$1"
    local find="$2"
    local replace="$3"
    
    if [ ! -f "$file" ]; then
        echo "Warning: File $file doesn't exist, skipping fix"
        return
    fi
    
    # Create backup
    cp "$file" "${file}.bak"
    
    # Write changes to temp file
    awk -v find="$find" -v replace="$replace" '{
        gsub(find, replace);
        print;
    }' "$file" > "${file}.tmp"
    
    # Replace original file
    mv "${file}.tmp" "$file"
    echo "Fixed $file"
}

# Fix api export issue
if [ -f "$FRONTEND_DIR/src/services/api.ts" ] && grep -q "export default api;" "$FRONTEND_DIR/src/services/api.ts"; then
    echo "Fixing API export..."
    # Create a new file with the fixed content
    fix_file "$FRONTEND_DIR/src/services/api.ts" "export default api;" "export default api;\nexport { api };"
fi

# Fix useRealTimeEvents export issue
if [ -f "$FRONTEND_DIR/src/hooks/useRealTimeEvents.ts" ] && grep -q "export { useRealTimeEvents" "$FRONTEND_DIR/src/hooks/useRealTimeEvents.ts"; then
    echo "Fixing useRealTimeEvents export..."
    fix_file "$FRONTEND_DIR/src/hooks/useRealTimeEvents.ts" "export { useRealTimeEvents" "export { useRealTimeEvents as default, useRealTimeEvents"
fi

# Fix ChatInterface to handle optional parentId
if [ -f "$FRONTEND_DIR/src/components/ChatInterface.tsx" ] && grep -q "if (msg.parentId)" "$FRONTEND_DIR/src/components/ChatInterface.tsx"; then
    if [ -f "$FRONTEND_DIR/src/services/chatService.ts" ]; then
        echo "Fixing ChatMessage interface..."
        # Check if the file already has parentId defined
        if ! grep -q "parentId?: string;" "$FRONTEND_DIR/src/services/chatService.ts"; then
            fix_file "$FRONTEND_DIR/src/services/chatService.ts" "interface ChatMessage {" "interface ChatMessage {\n  parentId?: string;"
        fi
    else
        echo "Warning: chatService.ts not found, can't fix ChatMessage interface"
    fi
fi

# Create basic implementations for missing files if needed
if [ ! -f "$FRONTEND_DIR/src/services/api.ts" ]; then
    echo "Creating missing api.ts file..."
    mkdir -p "$FRONTEND_DIR/src/services"
    cat > "$FRONTEND_DIR/src/services/api.ts" << 'EOF'
// Simple API client
const api = {
  get: async (url: string) => {
    const response = await fetch(url);
    if (!response.ok) {
      throw new Error(`HTTP error! status: ${response.status}`);
    }
    return response.json();
  },
  post: async (url: string, data: any) => {
    const response = await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(data),
    });
    if (!response.ok) {
      throw new Error(`HTTP error! status: ${response.status}`);
    }
    return response.json();
  }
};

export default api;
export { api };
EOF
fi

# Start the React development server
echo "Starting Skwaq frontend GUI..."
npm start
#!/usr/bin/env python3
"""Simple HTTP server that serves the CLI-generated investigation visualization JSON."""

import os
import sys
import json
import argparse
from http.server import HTTPServer, BaseHTTPRequestHandler
import re
import datetime
import neo4j.time

# Add the project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Custom JSON encoder for Neo4j DateTime objects
class CustomJSONEncoder(json.JSONEncoder):
    """Custom JSON encoder to handle Neo4j data types."""
    
    def default(self, obj):
        if isinstance(obj, neo4j.time.DateTime):
            return obj.to_native().isoformat()
        if isinstance(obj, datetime.datetime):
            return obj.isoformat()
        return super().default(obj)

class DirectJSONHandler(BaseHTTPRequestHandler):
    """HTTP request handler for serving CLI-generated visualization JSON."""
    
    def __init__(self, *args, json_file=None, **kwargs):
        self.json_file = json_file
        super().__init__(*args, **kwargs)
    
    def do_GET(self):
        """Handle HTTP GET requests."""
        # Simple CORS headers to allow requests from any origin
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.end_headers()
        
        # If path is /api/health, return a simple health check
        if self.path == '/api/health':
            self.wfile.write(json.dumps({"status": "ok"}).encode())
            return
            
        # Match the visualization endpoint pattern
        match = re.match(r'/api/investigations/([^/]+)/visualization', self.path)
        if match:
            investigation_id = match.group(1)
            print(f"Received request for investigation: {investigation_id}")
            
            try:
                # Read the json file
                with open(self.json_file, 'r') as f:
                    data = json.load(f)
                
                # Write the JSON response
                self.wfile.write(json.dumps(data).encode())
                print(f"Served JSON data with {len(data.get('nodes', []))} nodes and {len(data.get('links', []))} links")
            except Exception as e:
                print(f"Error serving JSON: {e}")
                self.wfile.write(json.dumps({"error": str(e)}).encode())
        else:
            # For all other requests, return a simple message
            self.wfile.write(json.dumps({"message": "Use the /api/investigations/{id}/visualization endpoint"}).encode())
    
    def do_OPTIONS(self):
        """Handle HTTP OPTIONS requests (for CORS)."""
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.end_headers()

def main():
    """Main function to run the server."""
    parser = argparse.ArgumentParser(description="Serve CLI-generated investigation visualization JSON")
    parser.add_argument("json_file", help="Path to the JSON file to serve")
    parser.add_argument("--port", type=int, default=5001, help="HTTP server port")
    
    args = parser.parse_args()
    
    # Verify the JSON file exists and is valid
    try:
        with open(args.json_file, 'r') as f:
            data = json.load(f)
            print(f"Loaded JSON file with {len(data.get('nodes', []))} nodes and {len(data.get('links', []))} links")
    except Exception as e:
        print(f"Error loading JSON file: {e}")
        sys.exit(1)
    
    # Create a custom handler that includes the JSON file path
    def handler(*args, **kwargs):
        return DirectJSONHandler(*args, json_file=args.json_file, **kwargs)
    
    # Start the server
    server_address = ('', args.port)
    httpd = HTTPServer(server_address, handler)
    print(f"Starting HTTP server on port {args.port}...")
    print(f"Serving JSON data from {args.json_file}")
    print(f"Use http://localhost:{args.port}/api/investigations/any-id/visualization to access the data")
    
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("Server stopped by user")
    
if __name__ == "__main__":
    main()
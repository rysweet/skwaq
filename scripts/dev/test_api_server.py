#!/usr/bin/env python3
"""Run the Skwaq API server with authentication disabled for integration testing."""

import os
import sys
import argparse
import signal
import logging
import time
import atexit
import subprocess
from threading import Thread

# Add parent directory to path so we can import skwaq modules
sys.path.append(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
)

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger(__name__)

# Function to modify auth.py temporarily for testing
def disable_auth_temporarily():
    """Temporarily modify the auth module to bypass authentication."""
    auth_file = os.path.join(
        os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
        "skwaq", "api", "auth.py"
    )
    
    # Create a backup of the original file
    backup_file = auth_file + ".bak"
    if not os.path.exists(backup_file):
        with open(auth_file, 'r') as f:
            original_content = f.read()
        
        with open(backup_file, 'w') as f:
            f.write(original_content)
            logger.info(f"Created backup of auth.py at {backup_file}")
    
    # Modify the login_required decorator to bypass authentication
    with open(auth_file, 'r') as f:
        content = f.read()
    
    # Look for the login_required decorator definition
    if "def login_required" in content:
        # Find the decorator function
        decorator_start = content.find("def login_required")
        decorator_end = content.find("return cast(F, decorated_function)", decorator_start)
        
        if decorator_start > 0 and decorator_end > 0:
            # Extract the function signature
            func_sig_end = content.find(":", decorator_start)
            function_signature = content[decorator_start:func_sig_end+1]
            
            # Create a simplified version that just passes through
            simplified_decorator = f"""
{function_signature}
    \"\"\"Decorator to require authentication for an endpoint.
    
    This is a test version that bypasses authentication.
    \"\"\"
    def decorated_function(*args: Any, **kwargs: Any) -> Any:
        # For testing, set default user credentials
        g.user_id = "test-user"
        g.username = "testuser"
        g.roles = ["admin"]
        return f(*args, **kwargs)
        
    return cast(F, decorated_function)
"""
            
            # Replace the original implementation with the simplified one
            new_content = content[:decorator_start] + simplified_decorator + content[decorator_end + len("return cast(F, decorated_function)") + 1:]
            
            with open(auth_file, 'w') as f:
                f.write(new_content)
                logger.info("Modified auth.py to bypass authentication for testing")
    else:
        logger.warning("Could not find login_required decorator in auth.py")

# Function to restore the original auth file
def restore_auth_file():
    """Restore the original auth.py file."""
    auth_file = os.path.join(
        os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
        "skwaq", "api", "auth.py"
    )
    backup_file = auth_file + ".bak"
    
    if os.path.exists(backup_file):
        with open(backup_file, 'r') as f:
            original_content = f.read()
        
        with open(auth_file, 'w') as f:
            f.write(original_content)
            logger.info("Restored original auth.py from backup")
        
        os.remove(backup_file)
        logger.info("Removed backup file")
    else:
        logger.warning("No backup file found for auth.py")

# Flag to track if we're supposed to be running
running = True
server_process = None

def signal_handler(sig, frame):
    """Handle termination signals gracefully."""
    global running, server_process
    logger.info(f"Received signal {sig}. Shutting down API server...")
    running = False
    
    if server_process:
        try:
            server_process.terminate()
            server_process.wait(timeout=5)
        except:
            server_process.kill()
        
    restore_auth_file()
    sys.exit(0)

def run_server(host, port, debug=False):
    """Run the API server in a separate process."""
    global server_process
    
    # Import the Flask app
    from skwaq.api.app import app
    
    # Create a command to run the server in a separate process
    cmd = [
        sys.executable,
        "-c",
        f"import sys; sys.path.append('{os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))}'); from skwaq.api.app import app; app.run(host='{host}', port={port}, debug={str(debug).lower()})"
    ]
    
    # Start the server process
    server_process = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        universal_newlines=True
    )
    
    # Print output from the server process
    def print_output():
        for line in server_process.stdout:
            print(f"[Server] {line.strip()}")
    
    def print_errors():
        for line in server_process.stderr:
            print(f"[Server Error] {line.strip()}")
    
    output_thread = Thread(target=print_output)
    output_thread.daemon = True
    output_thread.start()
    
    error_thread = Thread(target=print_errors)
    error_thread.daemon = True
    error_thread.start()
    
    return server_process

if __name__ == "__main__":
    # Register signal handlers
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    parser = argparse.ArgumentParser(
        description="Run the Skwaq API server with authentication disabled for testing"
    )
    parser.add_argument(
        "--host", default="localhost", help="Host to bind to (default: localhost)"
    )
    parser.add_argument(
        "--port", type=int, default=5000, help="Port to bind to (default: 5000)"
    )
    parser.add_argument("--debug", action="store_true", help="Run in debug mode")
    
    args = parser.parse_args()
    
    # Register cleanup function to ensure we restore auth.py
    atexit.register(restore_auth_file)
    
    try:
        # Disable authentication for testing
        disable_auth_temporarily()
        
        # The endpoints also need auth decorators removed
        logger.info(f"Starting API server at http://{args.host}:{args.port}")
        server_proc = run_server(args.host, args.port, args.debug)
        
        # Wait for server to start
        time.sleep(2)
        
        # Keep the server running until interrupted
        try:
            while server_proc.poll() is None:
                time.sleep(1)
        except KeyboardInterrupt:
            signal_handler(signal.SIGINT, None)
    
    finally:
        # Make sure to restore the auth file
        restore_auth_file()
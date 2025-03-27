#!/usr/bin/env python3
"""Run the Skwaq development environment with both API and frontend."""

import os
import sys
import argparse
import subprocess
import signal
import time
from threading import Thread

# Add parent directory to path so we can import skwaq modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

# Define process managers
processes = []


def run_api(host, port, debug):
    """Run the API server."""
    api_cmd = [
        sys.executable,
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "run_api.py"),
        "--host", host,
        "--port", str(port)
    ]
    
    if debug:
        api_cmd.append("--debug")
    
    print(f"\033[1;34m[API]\033[0m Starting API server at http://{host}:{port}")
    api_process = subprocess.Popen(
        api_cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        universal_newlines=True,
        bufsize=1
    )
    
    processes.append(api_process)
    return api_process


def run_frontend(port, api_port):
    """Run the frontend development server."""
    frontend_dir = os.path.abspath(os.path.join(
        os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
        "skwaq", "frontend"
    ))
    
    # Set environment variables for frontend
    env = os.environ.copy()
    env["REACT_APP_API_URL"] = f"http://localhost:{api_port}/api"
    env["PORT"] = str(port)
    
    print(f"\033[1;32m[FRONTEND]\033[0m Starting frontend server at http://localhost:{port}")
    frontend_process = subprocess.Popen(
        ["npm", "start"],
        cwd=frontend_dir,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        universal_newlines=True,
        bufsize=1
    )
    
    processes.append(frontend_process)
    return frontend_process


def print_process_output(process, prefix):
    """Print process output with a prefix."""
    for line in iter(process.stdout.readline, ""):
        if not line:
            break
        if prefix == "[API]":
            print(f"\033[1;34m{prefix}\033[0m {line.rstrip()}")
        else:
            print(f"\033[1;32m{prefix}\033[0m {line.rstrip()}")


def cleanup():
    """Clean up all processes."""
    print("\nShutting down...")
    for process in processes:
        if process.poll() is None:
            try:
                process.terminate()
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
            except:
                pass


def main():
    """Main function."""
    parser = argparse.ArgumentParser(description='Run the Skwaq development environment')
    parser.add_argument('--api-host', default='127.0.0.1', help='API host (default: 127.0.0.1)')
    parser.add_argument('--api-port', type=int, default=5000, help='API port (default: 5000)')
    parser.add_argument('--frontend-port', type=int, default=3000, help='Frontend port (default: 3000)')
    parser.add_argument('--debug', action='store_true', help='Run in debug mode')
    
    args = parser.parse_args()
    
    try:
        # Start API server
        api_process = run_api(args.api_host, args.api_port, args.debug)
        api_thread = Thread(target=print_process_output, args=(api_process, "[API]"))
        api_thread.daemon = True
        api_thread.start()
        
        # Wait a moment for API to start
        time.sleep(2)
        
        # Start frontend server
        frontend_process = run_frontend(args.frontend_port, args.api_port)
        frontend_thread = Thread(target=print_process_output, args=(frontend_process, "[FRONTEND]"))
        frontend_thread.daemon = True
        frontend_thread.start()
        
        # Wait for processes to complete or user interrupt
        while True:
            if api_process.poll() is not None:
                print("\033[1;31m[ERROR]\033[0m API server exited unexpectedly")
                break
                
            if frontend_process.poll() is not None:
                print("\033[1;31m[ERROR]\033[0m Frontend server exited unexpectedly")
                break
                
            time.sleep(0.5)
            
    except KeyboardInterrupt:
        print("\nUser interrupted")
    finally:
        cleanup()


if __name__ == '__main__':
    # Set up signal handlers
    signal.signal(signal.SIGINT, lambda signum, frame: sys.exit(0))
    signal.signal(signal.SIGTERM, lambda signum, frame: sys.exit(0))
    
    main()
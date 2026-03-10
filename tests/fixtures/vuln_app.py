"""Deliberately vulnerable Python application for testing source analysis.

DO NOT deploy this code. It contains intentional security vulnerabilities
for testing skwaq's multi-language source code analysis.
"""

import os
import pickle
import subprocess
import sqlite3
import yaml


def handle_request(request):
    """Handle an HTTP request with multiple vulnerabilities."""
    # Source: HTTP input
    name = request.args.get("name")
    query = request.args.get("query")
    data = request.data

    # Vulnerability 1: SQL Injection via string concatenation
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE name = '" + name + "'")

    # Vulnerability 2: Command Injection via os.system
    os.system("echo " + name)

    # Vulnerability 3: Code Injection via eval
    result = eval(query)

    # Vulnerability 4: Code Injection via exec
    exec(data)

    return result


def load_user_data(file_path):
    """Load user data from a file with deserialization vulnerability."""
    # Source: File read
    with open(file_path, "rb") as f:
        raw = f.read()

    # Vulnerability 5: Unsafe deserialization via pickle
    user = pickle.loads(raw)

    # Vulnerability 6: Unsafe YAML loading
    config = yaml.load(raw)

    return user, config


def run_command(user_input):
    """Run a command based on user input."""
    # Source: User input
    cmd = input("Enter command: ")

    # Vulnerability 7: Command injection via subprocess
    subprocess.call(cmd, shell=True)
    subprocess.Popen(cmd, shell=True)

    # Vulnerability 8: Dynamic import
    module = __import__(user_input)

    return module


def get_env_config():
    """Read configuration from environment."""
    # Source: Environment variables
    secret = os.environ.get("SECRET_KEY")
    db_url = os.environ.get("DATABASE_URL")

    # Vulnerability 9: SQL injection via environment variable
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM config WHERE key = '" + db_url + "'")

    return secret


def write_output(data, path):
    """Write data to a file."""
    # Sink: File write
    with open(path, "w") as f:
        f.write(data)

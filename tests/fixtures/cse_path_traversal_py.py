"""CWE-22: Path Traversal in Python
Constructs file paths from user input without sanitization."""

import os
import sys

UPLOAD_DIR = "/var/www/uploads"
CONFIG_DIR = "/etc/myapp"


def serve_file(filename):
    """Path traversal: no validation of '..' in filename."""
    filepath = os.path.join(UPLOAD_DIR, filename)
    with open(filepath, "r") as f:
        return f.read()


def read_config(name):
    """Path traversal via string concatenation."""
    path = CONFIG_DIR + "/" + name + ".conf"
    with open(path, "r") as f:
        return f.read()


def save_upload(filename, content):
    """Path traversal: user controls filename."""
    dest = os.path.join(UPLOAD_DIR, filename)
    with open(dest, "w") as f:
        f.write(content)


def download(base_dir, user_path):
    """Path traversal: no canonicalization."""
    full_path = base_dir + "/" + user_path
    if not os.path.exists(full_path):
        return None
    with open(full_path, "rb") as f:
        return f.read()


def main():
    if len(sys.argv) < 2:
        return
    print(serve_file(sys.argv[1]))


if __name__ == "__main__":
    main()

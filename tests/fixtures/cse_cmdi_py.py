"""CWE-78: OS Command Injection in Python
Passes user input to shell commands via subprocess and os.system."""

import os
import subprocess
import sys


def ping_host(hostname):
    """Command injection via os.system."""
    os.system(f"ping -c 1 {hostname}")


def get_file_info(filename):
    """Command injection via subprocess with shell=True."""
    result = subprocess.run(
        f"file {filename}", shell=True, capture_output=True, text=True
    )
    return result.stdout


def compress(path):
    """Command injection via os.popen."""
    stream = os.popen(f"tar czf /tmp/backup.tar.gz {path}")
    return stream.read()


def whois_lookup(domain):
    """Command injection via subprocess.Popen with shell."""
    proc = subprocess.Popen(
        f"whois {domain}", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )
    stdout, _ = proc.communicate()
    return stdout.decode()


def main():
    if len(sys.argv) < 2:
        print("Usage: script.py <host>")
        return
    ping_host(sys.argv[1])
    if len(sys.argv) > 2:
        print(get_file_info(sys.argv[2]))


if __name__ == "__main__":
    main()

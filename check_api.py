#!/usr/bin/env python3
"""Simple script to check the API health status."""

import requests
import sys

def check_health():
    """Check the health status of the API."""
    try:
        response = requests.get("http://localhost:5001/api/health")
        data = response.json()
        print(f"API Health Status: {data}")
        return True
    except Exception as e:
        print(f"Error connecting to API: {e}")
        return False

if __name__ == "__main__":
    if check_health():
        sys.exit(0)
    else:
        sys.exit(1)
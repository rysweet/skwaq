#!/usr/bin/env python3
"""Simple test script for the service commands."""

import sys
import os
from pathlib import Path

# Add project root to path
project_root = Path(__file__).resolve().parents[2]
sys.path.append(str(project_root))

from skwaq.shared.service_manager import ServiceManager, ServiceType, ServiceStatus

def main():
    """Test the ServiceManager directly."""
    print("Testing ServiceManager...")
    
    service_manager = ServiceManager()
    
    # Check the status of all services
    print("\nChecking service status:")
    for service_type in ServiceType:
        status = service_manager.check_service_status(service_type)
        service = service_manager.services[service_type]
        print(f"  {service.name}: {status.value}")
    
    # Test service URL
    print("\nService URLs:")
    for service_type in ServiceType:
        service = service_manager.services[service_type]
        print(f"  {service.name}: {service.url}")
    
    # Test Docker status
    print("\nChecking Docker status:")
    import subprocess
    try:
        result = subprocess.run(
            ["docker", "info"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        if result.returncode == 0:
            print("  Docker is running")
        else:
            print("  Docker is not running or not available")
            print(f"  Error: {result.stderr}")
    except Exception as e:
        print(f"  Error checking Docker: {str(e)}")
    
    # Check Neo4j container status
    print("\nChecking Neo4j container status:")
    try:
        result = subprocess.run(
            ["docker", "ps", "--filter", "name=neo4j", "--format", "{{.Names}}"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        if "neo4j" in result.stdout:
            print("  Neo4j container is running")
        else:
            print("  Neo4j container is not running")
    except Exception as e:
        print(f"  Error checking Neo4j container: {str(e)}")
    
    print("\nTest complete.")

if __name__ == "__main__":
    main()
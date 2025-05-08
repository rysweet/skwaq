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
    
    # Test service status commands
    print("\nService URLs:")
    for service_type in ServiceType:
        service = service_manager.services[service_type]
        print(f"  {service.name}: {service.url}")
    
    print("\nTest complete.")

if __name__ == "__main__":
    main()
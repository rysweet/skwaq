"""Service management utilities for the Skwaq project."""

import os
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union

import requests

from ..utils.logging import get_logger

logger = get_logger(__name__)


class ServiceType(Enum):
    """Types of services that can be managed."""

    DATABASE = "database"
    API = "api"
    GUI = "gui"


class ServiceStatus(Enum):
    """Status of a service."""

    RUNNING = "running"
    STOPPED = "stopped"
    STARTING = "starting"
    ERROR = "error"
    UNKNOWN = "unknown"


@dataclass
class ServiceInfo:
    """Information about a service."""

    name: str
    type: ServiceType
    status: ServiceStatus = ServiceStatus.UNKNOWN
    process: Optional[subprocess.Popen] = None
    url: Optional[str] = None
    port: Optional[int] = None
    health_check_url: Optional[str] = None
    startup_script: Optional[Path] = None
    process_pid: Optional[int] = None
    log_file: Optional[Path] = None
    stdout_thread: Optional[threading.Thread] = None
    stderr_thread: Optional[threading.Thread] = None


class ServiceManager:
    """Service manager for Skwaq."""

    def __init__(self):
        """Initialize the service manager."""
        self.services: Dict[ServiceType, ServiceInfo] = {}
        self.project_root: Path = Path(__file__).resolve().parents[2]
        self._initialize_services()

    def _initialize_services(self) -> None:
        """Initialize service information."""
        # Initialize database service (Neo4j)
        self.services[ServiceType.DATABASE] = ServiceInfo(
            name="Neo4j Database",
            type=ServiceType.DATABASE,
            url="bolt://localhost:7687",
            port=7687,
            health_check_url="http://localhost:7474",
            startup_script=self.project_root / "scripts" / "db" / "ensure_neo4j.py",
        )

        # Initialize API service
        self.services[ServiceType.API] = ServiceInfo(
            name="Skwaq API",
            type=ServiceType.API,
            url="http://localhost:5001",
            port=5001,
            health_check_url="http://localhost:5001/api/health",
            startup_script=self.project_root / "scripts" / "dev" / "run_api.py",
        )

        # Initialize GUI service
        self.services[ServiceType.GUI] = ServiceInfo(
            name="Skwaq GUI",
            type=ServiceType.GUI,
            url="http://localhost:3000",
            port=3000,
            health_check_url="http://localhost:3000",
            startup_script=self.project_root / "scripts" / "dev" / "run_gui.sh",
        )

    def check_service_status(self, service_type: ServiceType) -> ServiceStatus:
        """Check the status of a service.

        Args:
            service_type: The type of service to check.

        Returns:
            The status of the service.
        """
        service = self.services[service_type]

        # Special case for database service (Neo4j)
        if service_type == ServiceType.DATABASE:
            # Check if Neo4j container is running using Docker
            try:
                result = subprocess.run(
                    ["docker", "ps", "--filter", "name=neo4j", "--format", "{{.Names}}"],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    check=False,
                )
                if "neo4j" in result.stdout:
                    # Container is running, now check if the database is actually responsive
                    if service.port:
                        import socket
                        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                            sock.settimeout(1)
                            result = sock.connect_ex(("localhost", service.port))
                            if result == 0:  # Port is open
                                return ServiceStatus.RUNNING
                            else:
                                return ServiceStatus.STARTING  # Container running but port not open yet
                    return ServiceStatus.RUNNING  # Container running, no port specified
                else:
                    return ServiceStatus.STOPPED
            except Exception:
                logger.exception("Error checking Neo4j container status")
                return ServiceStatus.UNKNOWN

        # Check if we're tracking a running process
        if service.process and service.process.poll() is None:
            # Process is running, but let's also check health endpoint if available
            if service.health_check_url:
                try:
                    response = requests.get(service.health_check_url, timeout=2)
                    if response.status_code < 400:
                        return ServiceStatus.RUNNING
                    else:
                        return ServiceStatus.ERROR
                except requests.exceptions.RequestException:
                    # Even if the process is running, if we can't connect to the health check,
                    # we'll consider it as starting (might still be initializing)
                    return ServiceStatus.STARTING
            # If no health check URL, just assume it's running if the process is active
            return ServiceStatus.RUNNING

        # If we get here, either we're not tracking a process or the process has stopped
        # Let's check if something else might be running on the port
        if service.port:
            import socket

            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(1)
                result = sock.connect_ex(("localhost", service.port))
                if result == 0:  # Port is open
                    # Something is running on the port, but we're not tracking it
                    return ServiceStatus.RUNNING

        # If we get here, nothing is running on the port
        return ServiceStatus.STOPPED

    def check_all_services(self) -> Dict[ServiceType, ServiceStatus]:
        """Check the status of all services.

        Returns:
            A dictionary mapping service types to their status.
        """
        return {
            service_type: self.check_service_status(service_type)
            for service_type in self.services
        }

    def start_service(
        self, service_type: ServiceType, wait_for_start: bool = True, timeout: int = 60
    ) -> Tuple[bool, str]:
        """Start a service.

        Args:
            service_type: The type of service to start.
            wait_for_start: Whether to wait for the service to start.
            timeout: Maximum time to wait for the service to start (in seconds).

        Returns:
            A tuple of (success, message).
        """
        service = self.services[service_type]
        current_status = self.check_service_status(service_type)

        if current_status == ServiceStatus.RUNNING:
            return True, f"{service.name} is already running"

        # Create log directory if it doesn't exist
        log_dir = self.project_root / "logs"
        log_dir.mkdir(exist_ok=True)
        
        # Set up log file
        service.log_file = log_dir / f"{service_type.value}.log"
        
        # Different starting procedures for different service types
        if service_type == ServiceType.DATABASE:
            return self._start_database_service(service, wait_for_start, timeout)
        elif service_type == ServiceType.API:
            return self._start_api_service(service, wait_for_start, timeout)
        elif service_type == ServiceType.GUI:
            return self._start_gui_service(service, wait_for_start, timeout)
        else:
            return False, f"Unknown service type: {service_type}"

    def _start_database_service(
        self, service: ServiceInfo, wait_for_start: bool, timeout: int
    ) -> Tuple[bool, str]:
        """Start the database service.

        Args:
            service: Service information.
            wait_for_start: Whether to wait for the service to start.
            timeout: Maximum time to wait for the service to start (in seconds).

        Returns:
            A tuple of (success, message).
        """
        try:
            # Use ensure_neo4j.py script to start the Neo4j container
            logger.info(f"Starting {service.name} using {service.startup_script}")
            
            with open(service.log_file, "w") as log_file:
                process = subprocess.Popen(
                    [sys.executable, str(service.startup_script)],
                    stdout=log_file,
                    stderr=subprocess.STDOUT,
                    text=True,
                )
            
            # Wait for the process to complete (this script should start Neo4j and exit)
            process.wait()
            
            if process.returncode != 0:
                return False, f"Failed to start {service.name}"
            
            # Check if Neo4j is now running
            if wait_for_start:
                start_time = time.time()
                while time.time() - start_time < timeout:
                    status = self.check_service_status(ServiceType.DATABASE)
                    if status == ServiceStatus.RUNNING:
                        return True, f"Successfully started {service.name}"
                    time.sleep(1)
                
                return False, f"Timed out waiting for {service.name} to start"
            
            return True, f"Started {service.name}"
            
        except Exception as e:
            logger.error(f"Error starting {service.name}: {e}")
            return False, f"Error starting {service.name}: {str(e)}"

    def _start_api_service(
        self, service: ServiceInfo, wait_for_start: bool, timeout: int
    ) -> Tuple[bool, str]:
        """Start the API service.

        Args:
            service: Service information.
            wait_for_start: Whether to wait for the service to start.
            timeout: Maximum time to wait for the service to start (in seconds).

        Returns:
            A tuple of (success, message).
        """
        try:
            # Check if database is running first
            db_status = self.check_service_status(ServiceType.DATABASE)
            if db_status != ServiceStatus.RUNNING:
                # Try to start the database
                success, message = self.start_service(ServiceType.DATABASE, True, timeout)
                if not success:
                    return False, f"Failed to start database service: {message}"
            
            # Now start the API service
            logger.info(f"Starting {service.name} using {service.startup_script}")
            
            # Open log file
            log_file = open(service.log_file, "w")
            
            # Use the run_api.py script to start the API server
            process = subprocess.Popen(
                [sys.executable, str(service.startup_script)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,  # Line buffered
            )
            
            service.process = process
            service.process_pid = process.pid
            
            # Set up threads to log output
            def log_output(stream, log_file):
                for line in stream:
                    log_file.write(f"{line}\n")
                    log_file.flush()
                    if "Running on" in line:
                        logger.info(f"API server started: {line.strip()}")
            
            stdout_thread = threading.Thread(
                target=log_output, args=(process.stdout, log_file)
            )
            stderr_thread = threading.Thread(
                target=log_output, args=(process.stderr, log_file)
            )
            
            stdout_thread.daemon = True
            stderr_thread.daemon = True
            stdout_thread.start()
            stderr_thread.start()
            
            service.stdout_thread = stdout_thread
            service.stderr_thread = stderr_thread
            
            if wait_for_start:
                # Wait for the API to become available
                start_time = time.time()
                while time.time() - start_time < timeout:
                    # Check if process is still running
                    if process.poll() is not None:
                        log_file.close()
                        return False, f"API process terminated unexpectedly with code {process.returncode}"
                    
                    # Check if API is responding
                    try:
                        response = requests.get(service.health_check_url, timeout=1)
                        if response.status_code < 400:
                            logger.info(f"API server is responding at {service.health_check_url}")
                            return True, f"Successfully started {service.name}"
                    except requests.exceptions.RequestException:
                        pass
                    
                    time.sleep(1)
                
                # If we get here, we timed out waiting for the API to start
                log_file.close()
                return False, f"Timed out waiting for {service.name} to start"
            
            return True, f"Started {service.name}"
            
        except Exception as e:
            logger.error(f"Error starting {service.name}: {e}")
            return False, f"Error starting {service.name}: {str(e)}"

    def _start_gui_service(
        self, service: ServiceInfo, wait_for_start: bool, timeout: int
    ) -> Tuple[bool, str]:
        """Start the GUI service.

        Args:
            service: Service information.
            wait_for_start: Whether to wait for the service to start.
            timeout: Maximum time to wait for the service to start (in seconds).

        Returns:
            A tuple of (success, message).
        """
        try:
            # Check if API is running first
            api_status = self.check_service_status(ServiceType.API)
            if api_status != ServiceStatus.RUNNING:
                # Try to start the API
                success, message = self.start_service(ServiceType.API, True, timeout)
                if not success:
                    return False, f"Failed to start API service: {message}"
            
            # Now start the GUI service
            logger.info(f"Starting {service.name} using {service.startup_script}")
            
            # Open log file
            log_file = open(service.log_file, "w")
            
            # Use the run_gui.sh script to start the GUI
            process = subprocess.Popen(
                [str(service.startup_script)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,  # Line buffered
                cwd=self.project_root,
            )
            
            service.process = process
            service.process_pid = process.pid
            
            # Set up threads to log output
            def log_output(stream, log_file):
                for line in stream:
                    log_file.write(f"{line}\n")
                    log_file.flush()
                    # Log important events
                    if "Starting" in line or "started" in line.lower() or "Error" in line:
                        if "Error" in line:
                            logger.error(line.strip())
                        else:
                            logger.info(line.strip())
            
            stdout_thread = threading.Thread(
                target=log_output, args=(process.stdout, log_file)
            )
            stderr_thread = threading.Thread(
                target=log_output, args=(process.stderr, log_file)
            )
            
            stdout_thread.daemon = True
            stderr_thread.daemon = True
            stdout_thread.start()
            stderr_thread.start()
            
            service.stdout_thread = stdout_thread
            service.stderr_thread = stderr_thread
            
            if wait_for_start:
                # Wait for the GUI to become available
                start_time = time.time()
                while time.time() - start_time < timeout:
                    # Check if process is still running
                    if process.poll() is not None:
                        log_file.close()
                        return False, f"GUI process terminated unexpectedly with code {process.returncode}"
                    
                    # Check if we can connect to the GUI port
                    import socket
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                        sock.settimeout(1)
                        result = sock.connect_ex(("localhost", service.port))
                        if result == 0:  # Port is open
                            logger.info(f"GUI server is available on port {service.port}")
                            return True, f"Successfully started {service.name}"
                    
                    time.sleep(1)
                
                # If we get here, we timed out waiting for the GUI to start
                log_file.close()
                return False, f"Timed out waiting for {service.name} to start"
            
            return True, f"Started {service.name}"
            
        except Exception as e:
            logger.error(f"Error starting {service.name}: {e}")
            return False, f"Error starting {service.name}: {str(e)}"

    def stop_service(self, service_type: ServiceType) -> Tuple[bool, str]:
        """Stop a service.

        Args:
            service_type: The type of service to stop.

        Returns:
            A tuple of (success, message).
        """
        service = self.services[service_type]
        current_status = self.check_service_status(service_type)

        if current_status in [ServiceStatus.STOPPED, ServiceStatus.UNKNOWN]:
            return True, f"{service.name} is not running"

        try:
            # Different stopping procedures for different service types
            if service_type == ServiceType.DATABASE:
                # Check if Neo4j container is running
                result = subprocess.run(
                    ["docker", "ps", "--filter", "name=neo4j", "--format", "{{.Names}}"],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    check=False,
                )
                
                if "neo4j" in result.stdout:
                    # For Neo4j, use docker-compose to stop the container
                    logger.info(f"Stopping {service.name} using docker-compose")
                    result = subprocess.run(
                        ["docker-compose", "stop", "neo4j"],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True,
                        check=False,
                        cwd=self.project_root,
                    )
                    
                    if result.returncode != 0:
                        return False, f"Failed to stop {service.name}: {result.stderr}"
                    
                    return True, f"Successfully stopped {service.name}"
                else:
                    logger.info(f"{service.name} is already stopped")
                    return True, f"{service.name} is already stopped"
            
            else:  # API or GUI
                # If we have a process object, use it to stop the service
                if service.process and service.process.poll() is None:
                    logger.info(f"Stopping {service.name} (PID: {service.process.pid})")
                    service.process.terminate()
                    
                    # Give it a chance to terminate gracefully
                    try:
                        service.process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        logger.warning(f"{service.name} did not terminate gracefully, killing...")
                        service.process.kill()
                    
                    service.process = None
                    return True, f"Successfully stopped {service.name}"
                
                # If we don't have a process object but the service appears to be running,
                # try to find and kill the process using the port
                elif service.port:
                    # Find and kill process using the port
                    if sys.platform == 'win32':
                        # Windows
                        result = subprocess.run(
                            ["netstat", "-ano", f"| findstr :{service.port}"],
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,
                            text=True,
                            check=False,
                            shell=True,
                        )
                        
                        if result.returncode == 0 and result.stdout.strip():
                            # Parse PID from netstat output
                            lines = result.stdout.strip().split("\n")
                            for line in lines:
                                if f":{service.port}" in line:
                                    parts = line.split()
                                    if len(parts) >= 5:
                                        pid = parts[4]
                                        try:
                                            subprocess.run(
                                                ["taskkill", "/F", "/PID", pid],
                                                stdout=subprocess.PIPE,
                                                stderr=subprocess.PIPE,
                                                check=False,
                                            )
                                            return True, f"Stopped {service.name} (PID: {pid})"
                                        except Exception as e:
                                            return False, f"Failed to kill {service.name}: {str(e)}"
                    else:
                        # Unix-like
                        result = subprocess.run(
                            ["lsof", "-i", f":{service.port}", "-t"],
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,
                            text=True,
                            check=False,
                        )
                        
                        if result.returncode == 0 and result.stdout.strip():
                            pid = result.stdout.strip()
                            try:
                                subprocess.run(
                                    ["kill", "-9", pid],
                                    stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE,
                                    check=False,
                                )
                                return True, f"Stopped {service.name} (PID: {pid})"
                            except Exception as e:
                                return False, f"Failed to kill {service.name}: {str(e)}"
                
                return False, f"Could not find a running process for {service.name}"
            
        except Exception as e:
            logger.error(f"Error stopping {service.name}: {e}")
            return False, f"Error stopping {service.name}: {str(e)}"

    def stop_all_services(self) -> Dict[ServiceType, Tuple[bool, str]]:
        """Stop all services.

        Returns:
            A dictionary mapping service types to (success, message) tuples.
        """
        # Stop in reverse dependency order: GUI -> API -> Database
        results = {}
        for service_type in [ServiceType.GUI, ServiceType.API, ServiceType.DATABASE]:
            results[service_type] = self.stop_service(service_type)
        return results

    def ensure_service_running(
        self, service_type: ServiceType, timeout: int = 60
    ) -> Tuple[bool, str]:
        """Ensure a service is running, starting it if necessary.

        Args:
            service_type: The type of service to check/start.
            timeout: Maximum time to wait for the service to start (in seconds).

        Returns:
            A tuple of (success, message).
        """
        status = self.check_service_status(service_type)
        if status == ServiceStatus.RUNNING:
            return True, f"{self.services[service_type].name} is already running"
        
        return self.start_service(service_type, True, timeout)

    def get_service_url(self, service_type: ServiceType) -> Optional[str]:
        """Get the URL for a service.

        Args:
            service_type: The type of service.

        Returns:
            The URL for the service, or None if not available.
        """
        service = self.services[service_type]
        return service.url if service.status == ServiceStatus.RUNNING else None
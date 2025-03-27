"""Sandbox module for Skwaq.

This module provides sandboxing functionality for the Skwaq
vulnerability assessment copilot, enabling secure execution of
potentially dangerous code or tools.
"""

import json
import os
import shutil
import signal
import subprocess
import tempfile
import threading
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple, Union, cast

from skwaq.security.audit import AuditEventType, log_security_event, AuditLogLevel
from skwaq.utils.config import get_config
from skwaq.utils.logging import get_logger

logger = get_logger(__name__)


class SandboxError(Exception):
    """Exception raised for sandbox-related errors."""
    pass


class SandboxResourceLimitExceeded(SandboxError):
    """Exception raised when a sandbox resource limit is exceeded."""
    pass


class SandboxExecutionError(SandboxError):
    """Exception raised when execution within the sandbox fails."""
    pass


class SandboxIsolationLevel(Enum):
    """Isolation levels for sandboxes."""
    
    BASIC = "basic"         # Basic process isolation
    CONTAINER = "container"  # Container-based isolation with Docker
    VM = "vm"               # VM-based isolation (not implemented)


@dataclass
class SandboxResourceLimits:
    """Resource limits for a sandbox execution."""
    
    memory_mb: int = 512         # Maximum memory usage in MB
    cpu_time_sec: int = 30       # Maximum CPU time in seconds
    wall_time_sec: int = 60      # Maximum wall clock time in seconds
    disk_space_mb: int = 100     # Maximum disk space in MB
    network_access: bool = False  # Whether network access is allowed
    process_count: int = 10      # Maximum number of processes
    file_size_mb: int = 10       # Maximum file size in MB


@dataclass
class SandboxResult:
    """Result of a sandbox execution."""
    
    success: bool
    stdout: str
    stderr: str
    return_code: int
    execution_time: float  # Execution time in seconds
    memory_usage_mb: float  # Maximum memory usage in MB
    sandbox_id: str
    error_message: Optional[str] = None
    resource_limits_exceeded: bool = False
    execution_logs: List[str] = field(default_factory=list)
    files_created: List[str] = field(default_factory=list)
    files_modified: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary.
        
        Returns:
            Dictionary representation
        """
        return {
            "success": self.success,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "return_code": self.return_code,
            "execution_time": self.execution_time,
            "memory_usage_mb": self.memory_usage_mb,
            "sandbox_id": self.sandbox_id,
            "error_message": self.error_message,
            "resource_limits_exceeded": self.resource_limits_exceeded,
            "execution_logs": self.execution_logs,
            "files_created": self.files_created,
            "files_modified": self.files_modified,
        }


class Sandbox:
    """Base class for sandbox implementations."""
    
    def __init__(
        self,
        isolation_level: SandboxIsolationLevel = SandboxIsolationLevel.BASIC,
        resource_limits: Optional[SandboxResourceLimits] = None,
        working_dir: Optional[Path] = None,
        name: Optional[str] = None,
    ):
        """Initialize the sandbox.
        
        Args:
            isolation_level: Isolation level for the sandbox
            resource_limits: Resource limits for the sandbox
            working_dir: Working directory for the sandbox
            name: Name for the sandbox
        """
        self.isolation_level = isolation_level
        self.resource_limits = resource_limits or SandboxResourceLimits()
        self.working_dir = working_dir or Path(tempfile.mkdtemp(prefix="skwaq_sandbox_"))
        self.name = name or f"sandbox_{uuid.uuid4().hex[:8]}"
        self.sandbox_id = str(uuid.uuid4())
        self._initialized = False
        
    def initialize(self) -> None:
        """Initialize the sandbox environment.
        
        Raises:
            SandboxError: If initialization fails
        """
        if self._initialized:
            return
            
        try:
            # Create working directory if it doesn't exist
            os.makedirs(self.working_dir, exist_ok=True)
            
            # Initialize based on isolation level
            if self.isolation_level == SandboxIsolationLevel.CONTAINER:
                self._initialize_container()
            else:
                self._initialize_basic()
                
            self._initialized = True
            
            # Log initialization
            log_security_event(
                event_type=AuditEventType.COMPONENT_INITIALIZED,
                component=f"Sandbox-{self.name}",
                message=f"Initialized sandbox with isolation level {self.isolation_level.value}",
                details={
                    "sandbox_id": self.sandbox_id,
                    "isolation_level": self.isolation_level.value,
                    "working_dir": str(self.working_dir),
                },
            )
            
        except Exception as e:
            error_msg = f"Failed to initialize sandbox {self.name}: {e}"
            logger.error(error_msg)
            raise SandboxError(error_msg) from e
    
    def _initialize_basic(self) -> None:
        """Initialize a basic process isolation sandbox."""
        # Create directories
        os.makedirs(self.working_dir / "input", exist_ok=True)
        os.makedirs(self.working_dir / "output", exist_ok=True)
    
    def _initialize_container(self) -> None:
        """Initialize a container-based sandbox.
        
        Raises:
            SandboxError: If Docker is not available
        """
        # Check if Docker is available
        try:
            result = subprocess.run(
                ["docker", "version", "--format", "{{.Server.Version}}"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            
            if result.returncode != 0:
                raise SandboxError("Docker is not available or running")
                
            logger.info(f"Using Docker version: {result.stdout.strip()}")
            
        except (subprocess.SubprocessError, FileNotFoundError) as e:
            raise SandboxError("Docker is not available or running") from e
    
    def cleanup(self) -> None:
        """Clean up the sandbox environment."""
        try:
            # Clean up based on isolation level
            if self.isolation_level == SandboxIsolationLevel.CONTAINER:
                self._cleanup_container()
                
            # Remove working directory
            shutil.rmtree(self.working_dir, ignore_errors=True)
            
            # Log cleanup
            log_security_event(
                event_type=AuditEventType.COMPONENT_INITIALIZED,
                component=f"Sandbox-{self.name}",
                message=f"Cleaned up sandbox {self.name}",
                details={
                    "sandbox_id": self.sandbox_id,
                    "isolation_level": self.isolation_level.value,
                },
            )
            
        except Exception as e:
            logger.error(f"Error cleaning up sandbox {self.name}: {e}")
    
    def _cleanup_container(self) -> None:
        """Clean up a container-based sandbox."""
        try:
            # Stop and remove the container
            container_name = f"skwaq-sandbox-{self.sandbox_id}"
            subprocess.run(
                ["docker", "stop", container_name],
                capture_output=True,
                timeout=10,
            )
            subprocess.run(
                ["docker", "rm", container_name],
                capture_output=True,
                timeout=10,
            )
        except Exception as e:
            logger.error(f"Error cleaning up container: {e}")
    
    def add_file(self, file_path: Union[str, Path], content: Union[str, bytes]) -> Path:
        """Add a file to the sandbox.
        
        Args:
            file_path: Path to create within the sandbox
            content: Content to write to the file
            
        Returns:
            Path to the created file
            
        Raises:
            SandboxError: If file creation fails
        """
        if not self._initialized:
            self.initialize()
            
        try:
            # Create the full path
            file_path = Path(file_path)
            full_path = self.working_dir / "input" / file_path.name
            
            # Create parent directories if needed
            os.makedirs(full_path.parent, exist_ok=True)
            
            # Write the content
            mode = "w" if isinstance(content, str) else "wb"
            with open(full_path, mode) as f:
                f.write(content)
                
            return full_path
            
        except Exception as e:
            error_msg = f"Failed to add file to sandbox: {e}"
            logger.error(error_msg)
            raise SandboxError(error_msg) from e
    
    def execute_command(
        self, command: List[str], timeout: Optional[float] = None
    ) -> SandboxResult:
        """Execute a command in the sandbox.
        
        Args:
            command: Command to execute
            timeout: Timeout in seconds (overrides wall_time_sec if provided)
            
        Returns:
            SandboxResult with execution results
            
        Raises:
            SandboxError: If execution fails
        """
        if not self._initialized:
            self.initialize()
            
        # Determine the execution method based on isolation level
        if self.isolation_level == SandboxIsolationLevel.CONTAINER:
            return self._execute_in_container(command, timeout)
        else:
            return self._execute_basic(command, timeout)
    
    def _execute_basic(
        self, command: List[str], timeout: Optional[float] = None
    ) -> SandboxResult:
        """Execute a command with basic process isolation.
        
        Args:
            command: Command to execute
            timeout: Timeout in seconds
            
        Returns:
            SandboxResult with execution results
        """
        start_time = time.time()
        timeout = timeout or self.resource_limits.wall_time_sec
        memory_usage_mb = 0.0
        error_message = None
        resource_limits_exceeded = False
        execution_logs = []
        
        try:
            # Log the execution
            execution_logs.append(f"Executing command: {' '.join(command)}")
            
            # Create the process
            process = subprocess.Popen(
                command,
                cwd=self.working_dir / "input",
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                preexec_fn=os.setsid,  # Create a new process group for killing
            )
            
            # Monitor resource usage
            memory_usage_thread = threading.Thread(
                target=self._monitor_process_resources,
                args=(process.pid, self.resource_limits),
            )
            memory_usage_thread.daemon = True
            memory_usage_thread.start()
            
            # Wait for the process to complete
            try:
                stdout, stderr = process.communicate(timeout=timeout)
                return_code = process.returncode
            except subprocess.TimeoutExpired:
                # Kill the process group
                os.killpg(os.getpgid(process.pid), signal.SIGKILL)
                stdout, stderr = process.communicate()
                return_code = -1
                error_message = f"Command timed out after {timeout} seconds"
                resource_limits_exceeded = True
                execution_logs.append(f"Command timed out after {timeout} seconds")
                
            execution_time = time.time() - start_time
            
            # Try to get memory usage from the monitoring thread
            if hasattr(memory_usage_thread, "max_memory_mb"):
                memory_usage_mb = getattr(memory_usage_thread, "max_memory_mb")
                
            # Check for excessive output
            if len(stdout) > 1_000_000:  # 1MB
                stdout = stdout[:500_000] + "\n... [output truncated] ...\n" + stdout[-500_000:]
                execution_logs.append("Output exceeds 1MB and was truncated")
                
            if len(stderr) > 1_000_000:  # 1MB
                stderr = stderr[:500_000] + "\n... [output truncated] ...\n" + stderr[-500_000:]
                execution_logs.append("Error output exceeds 1MB and was truncated")
                
            # Create the result
            result = SandboxResult(
                success=(return_code == 0 and not resource_limits_exceeded),
                stdout=stdout,
                stderr=stderr,
                return_code=return_code,
                execution_time=execution_time,
                memory_usage_mb=memory_usage_mb,
                sandbox_id=self.sandbox_id,
                error_message=error_message,
                resource_limits_exceeded=resource_limits_exceeded,
                execution_logs=execution_logs,
                files_created=self._get_created_files(),
                files_modified=self._get_modified_files(),
            )
            
            # Log the execution result
            log_security_event(
                event_type=AuditEventType.TOOL_EXECUTED,
                component=f"Sandbox-{self.name}",
                message=f"Executed command in sandbox: {' '.join(command)}",
                details={
                    "sandbox_id": self.sandbox_id,
                    "command": command,
                    "success": result.success,
                    "return_code": return_code,
                    "execution_time": execution_time,
                    "memory_usage_mb": memory_usage_mb,
                },
                level=AuditLogLevel.INFO if result.success else AuditLogLevel.WARNING,
            )
            
            return result
            
        except Exception as e:
            error_msg = f"Failed to execute command in sandbox: {e}"
            logger.error(error_msg)
            execution_time = time.time() - start_time
            
            # Create error result
            result = SandboxResult(
                success=False,
                stdout="",
                stderr=f"Sandbox execution error: {e}",
                return_code=-1,
                execution_time=execution_time,
                memory_usage_mb=memory_usage_mb,
                sandbox_id=self.sandbox_id,
                error_message=str(e),
                resource_limits_exceeded=False,
                execution_logs=execution_logs + [f"Execution error: {e}"],
            )
            
            # Log the execution error
            log_security_event(
                event_type=AuditEventType.TOOL_EXECUTED,
                component=f"Sandbox-{self.name}",
                message=f"Error executing command in sandbox: {' '.join(command)}",
                details={
                    "sandbox_id": self.sandbox_id,
                    "command": command,
                    "error": str(e),
                },
                level=AuditLogLevel.ERROR,
            )
            
            return result
    
    def _execute_in_container(
        self, command: List[str], timeout: Optional[float] = None
    ) -> SandboxResult:
        """Execute a command in a Docker container.
        
        Args:
            command: Command to execute
            timeout: Timeout in seconds
            
        Returns:
            SandboxResult with execution results
        """
        start_time = time.time()
        timeout = timeout or self.resource_limits.wall_time_sec
        error_message = None
        resource_limits_exceeded = False
        execution_logs = []
        container_name = f"skwaq-sandbox-{self.sandbox_id}"
        
        try:
            # Prepare volume mounts
            input_dir = self.working_dir / "input"
            output_dir = self.working_dir / "output"
            
            # Log the execution
            execution_logs.append(f"Executing command in container: {' '.join(command)}")
            
            # Build Docker command
            docker_command = [
                "docker", "run",
                "--rm",  # Remove container after execution
                "--name", container_name,
                "-v", f"{input_dir}:/sandbox/input:ro",  # Mount input as read-only
                "-v", f"{output_dir}:/sandbox/output:rw",  # Mount output as writable
                "--workdir", "/sandbox/input",
                "--network", "none" if not self.resource_limits.network_access else "bridge",
                "--memory", f"{self.resource_limits.memory_mb}m",
                "--memory-swap", f"{self.resource_limits.memory_mb}m",  # No swap
                "--cpus", "1",
                "--pids-limit", str(self.resource_limits.process_count),
                "--security-opt", "no-new-privileges",
                "python:3.10-slim",  # Use a minimal Python image
            ]
            docker_command.extend(command)
            
            # Execute the Docker command
            process = subprocess.Popen(
                docker_command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            
            try:
                stdout, stderr = process.communicate(timeout=timeout)
                return_code = process.returncode
            except subprocess.TimeoutExpired:
                # Kill the container
                subprocess.run(
                    ["docker", "stop", container_name],
                    capture_output=True,
                    timeout=10,
                )
                stdout, stderr = process.communicate()
                return_code = -1
                error_message = f"Command timed out after {timeout} seconds"
                resource_limits_exceeded = True
                execution_logs.append(f"Command timed out after {timeout} seconds")
                
            execution_time = time.time() - start_time
            
            # Get memory usage from Docker stats
            memory_usage_mb = self._get_container_memory_usage(container_name)
            
            # Check for excessive output
            if len(stdout) > 1_000_000:  # 1MB
                stdout = stdout[:500_000] + "\n... [output truncated] ...\n" + stdout[-500_000:]
                execution_logs.append("Output exceeds 1MB and was truncated")
                
            if len(stderr) > 1_000_000:  # 1MB
                stderr = stderr[:500_000] + "\n... [output truncated] ...\n" + stderr[-500_000:]
                execution_logs.append("Error output exceeds 1MB and was truncated")
                
            # Create the result
            result = SandboxResult(
                success=(return_code == 0 and not resource_limits_exceeded),
                stdout=stdout,
                stderr=stderr,
                return_code=return_code,
                execution_time=execution_time,
                memory_usage_mb=memory_usage_mb,
                sandbox_id=self.sandbox_id,
                error_message=error_message,
                resource_limits_exceeded=resource_limits_exceeded,
                execution_logs=execution_logs,
                files_created=self._get_created_files(),
                files_modified=self._get_modified_files(),
            )
            
            # Log the execution result
            log_security_event(
                event_type=AuditEventType.TOOL_EXECUTED,
                component=f"Sandbox-{self.name}",
                message=f"Executed command in container sandbox: {' '.join(command)}",
                details={
                    "sandbox_id": self.sandbox_id,
                    "command": command,
                    "success": result.success,
                    "return_code": return_code,
                    "execution_time": execution_time,
                    "memory_usage_mb": memory_usage_mb,
                },
                level=AuditLogLevel.INFO if result.success else AuditLogLevel.WARNING,
            )
            
            return result
            
        except Exception as e:
            error_msg = f"Failed to execute command in container sandbox: {e}"
            logger.error(error_msg)
            execution_time = time.time() - start_time
            
            # Create error result
            result = SandboxResult(
                success=False,
                stdout="",
                stderr=f"Container sandbox execution error: {e}",
                return_code=-1,
                execution_time=execution_time,
                memory_usage_mb=0.0,
                sandbox_id=self.sandbox_id,
                error_message=str(e),
                resource_limits_exceeded=False,
                execution_logs=execution_logs + [f"Execution error: {e}"],
            )
            
            # Log the execution error
            log_security_event(
                event_type=AuditEventType.TOOL_EXECUTED,
                component=f"Sandbox-{self.name}",
                message=f"Error executing command in container sandbox: {' '.join(command)}",
                details={
                    "sandbox_id": self.sandbox_id,
                    "command": command,
                    "error": str(e),
                },
                level=AuditLogLevel.ERROR,
            )
            
            return result
    
    def _monitor_process_resources(
        self, pid: int, resource_limits: SandboxResourceLimits
    ) -> None:
        """Monitor process resource usage.
        
        Args:
            pid: Process ID to monitor
            resource_limits: Resource limits
        """
        import psutil
        
        try:
            process = psutil.Process(pid)
            max_memory_mb = 0.0
            
            while True:
                try:
                    # Get memory usage
                    memory_info = process.memory_info()
                    memory_mb = memory_info.rss / (1024 * 1024)
                    
                    if memory_mb > max_memory_mb:
                        max_memory_mb = memory_mb
                        
                    # Check if memory limit is exceeded
                    if memory_mb > resource_limits.memory_mb:
                        logger.warning(
                            f"Process {pid} exceeded memory limit: {memory_mb:.2f}MB > {resource_limits.memory_mb}MB"
                        )
                        os.killpg(os.getpgid(pid), signal.SIGKILL)
                        break
                        
                    # Sleep before checking again
                    time.sleep(0.1)
                    
                except psutil.NoSuchProcess:
                    # Process no longer exists
                    break
                    
            # Store the maximum memory usage for later retrieval
            setattr(threading.current_thread(), "max_memory_mb", max_memory_mb)
            
        except Exception as e:
            logger.error(f"Error monitoring process resources: {e}")
    
    def _get_container_memory_usage(self, container_name: str) -> float:
        """Get memory usage of a Docker container.
        
        Args:
            container_name: Container name
            
        Returns:
            Memory usage in MB
        """
        try:
            result = subprocess.run(
                ["docker", "stats", container_name, "--no-stream", "--format", "{{.MemUsage}}"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            
            if result.returncode != 0:
                return 0.0
                
            # Parse the memory usage (format: "10.5MiB / 100MiB")
            memory_str = result.stdout.strip().split("/")[0].strip()
            
            if "MiB" in memory_str:
                return float(memory_str.replace("MiB", ""))
            elif "KiB" in memory_str:
                return float(memory_str.replace("KiB", "")) / 1024
            elif "GiB" in memory_str:
                return float(memory_str.replace("GiB", "")) * 1024
                
            return 0.0
            
        except Exception as e:
            logger.error(f"Error getting container memory usage: {e}")
            return 0.0
    
    def _get_created_files(self) -> List[str]:
        """Get files created during execution.
        
        Returns:
            List of created file paths
        """
        try:
            output_dir = self.working_dir / "output"
            created_files = []
            
            for root, _, files in os.walk(output_dir):
                for file in files:
                    file_path = os.path.join(root, file)
                    rel_path = os.path.relpath(file_path, output_dir)
                    created_files.append(rel_path)
                    
            return created_files
            
        except Exception as e:
            logger.error(f"Error getting created files: {e}")
            return []
    
    def _get_modified_files(self) -> List[str]:
        """Get files modified during execution.
        
        Returns:
            List of modified file paths
        """
        # For process isolation, we can't track modifications to input files
        # since we mount them as read-only in containers
        return []
    
    def get_file(self, file_path: Union[str, Path]) -> Optional[bytes]:
        """Get the content of a file from the sandbox.
        
        Args:
            file_path: Path to read from the sandbox
            
        Returns:
            File content as bytes, or None if the file doesn't exist
        """
        try:
            file_path = Path(file_path)
            
            # Check input directory first
            input_path = self.working_dir / "input" / file_path
            if input_path.exists():
                with open(input_path, "rb") as f:
                    return f.read()
            
            # Check output directory
            output_path = self.working_dir / "output" / file_path
            if output_path.exists():
                with open(output_path, "rb") as f:
                    return f.read()
                    
            return None
            
        except Exception as e:
            logger.error(f"Error reading file from sandbox: {e}")
            return None


def create_sandbox(
    isolation_level: SandboxIsolationLevel = SandboxIsolationLevel.BASIC,
    resource_limits: Optional[SandboxResourceLimits] = None,
    name: Optional[str] = None,
) -> Sandbox:
    """Create a new sandbox.
    
    Args:
        isolation_level: Isolation level for the sandbox
        resource_limits: Resource limits for the sandbox
        name: Name for the sandbox
        
    Returns:
        Sandbox instance
    """
    sandbox = Sandbox(
        isolation_level=isolation_level,
        resource_limits=resource_limits,
        name=name,
    )
    
    # Initialize the sandbox
    sandbox.initialize()
    
    return sandbox


def is_container_available() -> bool:
    """Check if container-based isolation is available.
    
    Returns:
        True if available, False otherwise
    """
    try:
        result = subprocess.run(
            ["docker", "version", "--format", "{{.Server.Version}}"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        
        return result.returncode == 0
        
    except (subprocess.SubprocessError, FileNotFoundError):
        return False


def execute_in_sandbox(
    command: List[str],
    isolation_level: SandboxIsolationLevel = SandboxIsolationLevel.BASIC,
    resource_limits: Optional[SandboxResourceLimits] = None,
    files: Optional[Dict[str, Union[str, bytes]]] = None,
    cleanup: bool = True,
) -> SandboxResult:
    """Execute a command in a sandbox with one-time setup and cleanup.
    
    Args:
        command: Command to execute
        isolation_level: Isolation level for the sandbox
        resource_limits: Resource limits for the sandbox
        files: Dictionary of files to add to the sandbox (path -> content)
        cleanup: Whether to clean up the sandbox after execution
        
    Returns:
        SandboxResult with execution results
    """
    # Use container isolation if available
    if isolation_level == SandboxIsolationLevel.CONTAINER and not is_container_available():
        logger.warning("Container isolation requested but Docker is not available; falling back to basic isolation")
        isolation_level = SandboxIsolationLevel.BASIC
    
    # Create the sandbox
    sandbox = create_sandbox(
        isolation_level=isolation_level,
        resource_limits=resource_limits,
    )
    
    try:
        # Add files
        if files:
            for path, content in files.items():
                sandbox.add_file(path, content)
        
        # Execute the command
        result = sandbox.execute_command(command)
        
        return result
        
    finally:
        # Clean up
        if cleanup:
            sandbox.cleanup()
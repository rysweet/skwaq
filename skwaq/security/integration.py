"""Security integration module for Skwaq.

This module provides comprehensive security integration for the Skwaq
vulnerability assessment copilot, bringing together authentication,
authorization, encryption, audit logging, compliance, and sandboxing
to provide end-to-end security protection.
"""

import datetime
import functools
import inspect
import logging
import os
import re
import threading
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple, TypeVar, Union, cast

from skwaq.events.system_events import EventType, SystemEvent, publish, subscribe
from skwaq.security.audit import (
    AuditEventType,
    AuditLogLevel,
    get_audit_logger,
    log_security_event,
)
from skwaq.security.authentication import AuthRole, UserCredentials, get_auth_manager
from skwaq.security.authorization import (
    Authorization,
    Permission,
    get_authorization,
    require_permission,
)
from skwaq.security.compliance import (
    ComplianceCategory,
    ComplianceStandard,
    ComplianceRequirement,
    ComplianceViolation,
    ComplianceViolationSeverity,
    get_compliance_manager,
    validate_requirement,
)
from skwaq.security.encryption import (
    DataClassification,
    decrypt_sensitive_data,
    encrypt_config_value,
    encrypt_sensitive_data,
    get_encryption_manager,
)
from skwaq.security.sandbox import (
    SandboxIsolationLevel,
    SandboxResourceLimits,
    create_sandbox,
    is_container_available,
)
from skwaq.security.vulnerability import (
    VulnerabilityFinding,
    VulnerabilitySeverity,
    VulnerabilityStatus,
    VulnerabilityType,
    add_vulnerability,
    get_vulnerability_manager,
)
from skwaq.utils.config import get_config
from skwaq.utils.logging import get_logger

logger = get_logger(__name__)


class SecurityConfigurationError(Exception):
    """Exception raised for security configuration errors."""

    pass


class SecurityOperationError(Exception):
    """Exception raised for security operation errors."""

    pass


class SecurityContext:
    """Context for tracking security-related information during operations."""

    _thread_local = threading.local()

    @classmethod
    def get_current_user(cls) -> Optional[UserCredentials]:
        """Get the current user for this thread.

        Returns:
            Current user credentials or None if not set
        """
        return getattr(cls._thread_local, "current_user", None)

    @classmethod
    def set_current_user(cls, user: Optional[UserCredentials]) -> None:
        """Set the current user for this thread.

        Args:
            user: User credentials to set
        """
        cls._thread_local.current_user = user

    @classmethod
    def get_current_session_id(cls) -> Optional[str]:
        """Get the current session ID for this thread.

        Returns:
            Current session ID or None if not set
        """
        return getattr(cls._thread_local, "session_id", None)

    @classmethod
    def set_current_session_id(cls, session_id: Optional[str]) -> None:
        """Set the current session ID for this thread.

        Args:
            session_id: Session ID to set
        """
        cls._thread_local.session_id = session_id

    @classmethod
    def get_current_source_ip(cls) -> Optional[str]:
        """Get the current source IP for this thread.

        Returns:
            Current source IP or None if not set
        """
        return getattr(cls._thread_local, "source_ip", None)

    @classmethod
    def set_current_source_ip(cls, source_ip: Optional[str]) -> None:
        """Set the current source IP for this thread.

        Args:
            source_ip: Source IP to set
        """
        cls._thread_local.source_ip = source_ip

    @classmethod
    def clear(cls) -> None:
        """Clear all thread-local variables."""
        if hasattr(cls._thread_local, "current_user"):
            delattr(cls._thread_local, "current_user")
        if hasattr(cls._thread_local, "session_id"):
            delattr(cls._thread_local, "session_id")
        if hasattr(cls._thread_local, "source_ip"):
            delattr(cls._thread_local, "source_ip")


class SecurityEvent(SystemEvent):
    """Event for security-related notifications."""

    def __init__(
        self,
        event_type: str,
        component: str,
        message: str,
        severity: AuditLogLevel = AuditLogLevel.INFO,
        user_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ):
        """Initialize a security event.

        Args:
            event_type: Type of security event
            component: Component that generated the event
            message: Event message
            severity: Event severity level
            user_id: Optional user ID
            metadata: Optional additional metadata
        """
        super().__init__(
            sender=component,
            message=message,
            target=None,
            metadata=metadata or {},
        )
        self.event_type = event_type
        self.severity = severity
        self.user_id = user_id


class SecurityManager:
    """Manager for integrated security functionality."""

    _instance = None

    def __new__(cls) -> "SecurityManager":
        """Create a singleton instance.

        Returns:
            Singleton instance
        """
        if cls._instance is None:
            cls._instance = super(SecurityManager, cls).__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self):
        """Initialize the security manager."""
        if self._initialized:
            return

        self._initialized = True
        self._config = get_config()

        # Initialize security components
        self._auth_manager = get_auth_manager()
        self._authorization = get_authorization()
        self._audit_logger = get_audit_logger()
        self._encryption_manager = get_encryption_manager()
        self._compliance_manager = get_compliance_manager()
        self._vulnerability_manager = get_vulnerability_manager()

        # Subscribe to security events
        subscribe(EventType.SYSTEM, self._handle_system_event)

        # Register security compliance checks
        self._register_compliance_checks()

        # Security configuration check
        self._verify_security_configuration()

        # Log initialization
        log_security_event(
            event_type=AuditEventType.COMPONENT_INITIALIZED,
            component="SecurityManager",
            message="Security manager initialized",
            level=AuditLogLevel.INFO,
        )

    def _verify_security_configuration(self) -> None:
        """Verify that security is properly configured.

        Raises:
            SecurityConfigurationError: If security configuration is invalid
        """
        # Check encryption keys
        if not self._config.get("encryption.default_key"):
            logger.warning("No default encryption key configured")

        # Check audit logging
        if not self._config.get("audit.enabled", True):
            logger.warning("Audit logging is disabled")

        # Check authentication
        if not self._config.get("security.admin_username"):
            logger.warning("No admin username configured")

        # Minimum password length
        password_min_length = self._config.get("security.password_min_length")
        if not password_min_length or password_min_length < 12:
            logger.warning(
                f"Password minimum length ({password_min_length or 'not set'}) is below recommended value (12)"
            )

        # MFA
        if not self._config.get("security.mfa_enabled", False):
            logger.warning("Multi-factor authentication is not enabled")

    def _register_compliance_checks(self) -> None:
        """Register system security compliance checks."""
        # Register additional compliance checks for the system

        # Secure communication check
        secure_comm_req = ComplianceRequirement(
            id="SEC-01",
            name="Secure Communications",
            description="All communications should use secure protocols",
            standard=ComplianceStandard.SOC2,
            category=ComplianceCategory.NETWORK_SECURITY,
            validation_function="validate_secure_communications",
            references={"SOC2": "CC6.7", "NIST": "SC-8"},
        )
        self._compliance_manager.add_requirement(secure_comm_req)

        # Register the validation function
        def validate_secure_communications(params: Dict[str, Any]) -> Tuple[bool, str]:
            api_uses_https = self._config.get("api.use_https", True)
            if not api_uses_https:
                return False, "API communications are not using HTTPS"
            return True, "All communications use secure protocols"

        self._compliance_manager.register_validation_function(
            "validate_secure_communications", validate_secure_communications
        )

        # Data protection check
        data_protection_req = ComplianceRequirement(
            id="SEC-02",
            name="Data Protection",
            description="Sensitive data should be encrypted",
            standard=ComplianceStandard.PCI_DSS,
            category=ComplianceCategory.DATA_PROTECTION,
            validation_function="validate_data_protection",
            references={"PCI_DSS": "3.4", "NIST": "SC-28"},
        )
        self._compliance_manager.add_requirement(data_protection_req)

        # Register the validation function
        def validate_data_protection(params: Dict[str, Any]) -> Tuple[bool, str]:
            data_encryption_enabled = self._config.get("encryption.enabled", True)
            if not data_encryption_enabled:
                return False, "Data encryption is not enabled"
            return True, "Data encryption is enabled for sensitive data"

        self._compliance_manager.register_validation_function(
            "validate_data_protection", validate_data_protection
        )

    def _handle_system_event(self, event: SystemEvent) -> None:
        """Handle system events for security monitoring.

        Args:
            event: System event
        """
        # Process events of interest

        # Log configuration changes
        if event.sender == "config":
            # Log security-related configuration changes
            security_params = [
                "security.",
                "audit.",
                "encryption.",
                "authentication.",
                "authorization.",
                "compliance.",
                "sandbox.",
            ]

            if any(param in event.message for param in security_params):
                log_security_event(
                    event_type=AuditEventType.CONFIG_CHANGED,
                    component="SecurityManager",
                    message=f"Security configuration changed: {event.message}",
                    details=event.metadata,
                    level=AuditLogLevel.SECURITY,
                )

    def process_login(
        self,
        username: str,
        password: str,
        source_ip: Optional[str] = None,
        session_id: Optional[str] = None,
    ) -> Optional[UserCredentials]:
        """Process a user login.

        Args:
            username: Username
            password: Password
            source_ip: Optional source IP
            session_id: Optional session ID

        Returns:
            UserCredentials if login successful, None otherwise
        """
        try:
            # Authenticate the user
            user = self._auth_manager.authenticate(username, password, source_ip)

            if user:
                # Set the current security context
                SecurityContext.set_current_user(user)
                SecurityContext.set_current_source_ip(source_ip)
                SecurityContext.set_current_session_id(session_id)

                # Generate a token if needed
                token = self._auth_manager.generate_token(user)

                return user

            return None

        except Exception as e:
            logger.error(f"Login error: {e}")
            log_security_event(
                event_type=AuditEventType.USER_LOGIN,
                component="SecurityManager",
                message=f"Login error for user {username}: {e}",
                level=AuditLogLevel.ERROR,
            )
            return None

    def process_token_login(
        self,
        token: str,
        source_ip: Optional[str] = None,
        session_id: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        """Process a token login.

        Args:
            token: Authentication token
            source_ip: Optional source IP
            session_id: Optional session ID

        Returns:
            Token payload if valid, None otherwise
        """
        try:
            # Validate the token
            payload = self._auth_manager.validate_token(token)

            if payload:
                # Find the user
                user_id = payload.get("sub")
                username = payload.get("username")

                # Set roles from token
                roles = set()
                for role_value in payload.get("roles", []):
                    try:
                        roles.add(AuthRole(role_value))
                    except ValueError:
                        continue

                # Create a user object from token data
                user = UserCredentials(
                    username=username,
                    password_hash="",  # Not needed for token auth
                    salt="",  # Not needed for token auth
                    roles=roles,
                    user_id=user_id,
                )

                # Set the current security context
                SecurityContext.set_current_user(user)
                SecurityContext.set_current_source_ip(source_ip)
                SecurityContext.set_current_session_id(session_id)

                # Log the token login
                log_security_event(
                    event_type=AuditEventType.USER_LOGIN,
                    component="SecurityManager",
                    message=f"Token login for user {username}",
                    user_id=user_id,
                    details={"source_ip": source_ip},
                    level=AuditLogLevel.INFO,
                )

                return payload

            return None

        except Exception as e:
            logger.error(f"Token login error: {e}")
            log_security_event(
                event_type=AuditEventType.USER_LOGIN,
                component="SecurityManager",
                message=f"Token login error: {e}",
                level=AuditLogLevel.ERROR,
            )
            return None

    def logout(self, token: Optional[str] = None) -> bool:
        """Log out the current user.

        Args:
            token: Optional token to revoke

        Returns:
            True if logout successful, False otherwise
        """
        user = SecurityContext.get_current_user()

        # Revoke the token if provided
        if token:
            self._auth_manager.revoke_token(token)

        # Log the logout
        if user:
            log_security_event(
                event_type=AuditEventType.USER_LOGOUT,
                component="SecurityManager",
                message=f"User {user.username} logged out",
                user_id=user.user_id,
                level=AuditLogLevel.INFO,
            )

        # Clear the security context
        SecurityContext.clear()

        return True

    def check_permission(
        self, permission: Permission, resource_id: Optional[str] = None
    ) -> bool:
        """Check if the current user has a permission.

        Args:
            permission: Permission to check
            resource_id: Optional resource identifier

        Returns:
            True if the user has the permission, False otherwise
        """
        user = SecurityContext.get_current_user()
        if not user:
            logger.warning("Permission check failed: No user in security context")
            return False

        return self._authorization.has_permission(user, permission, resource_id)

    def run_compliance_assessment(
        self,
        standard: Optional[ComplianceStandard] = None,
        category: Optional[ComplianceCategory] = None,
    ) -> Dict[str, Tuple[bool, Optional[ComplianceViolation]]]:
        """Run a compliance assessment.

        Args:
            standard: Optional compliance standard to filter by
            category: Optional category to filter by

        Returns:
            Dictionary mapping requirement IDs to validation results
        """
        # Log the assessment
        log_security_event(
            event_type=AuditEventType.COMPLIANCE_CHECK,
            component="SecurityManager",
            message="Running compliance assessment",
            details={
                "standard": standard.value if standard else "All",
                "category": category.value if category else "All",
            },
            level=AuditLogLevel.INFO,
        )

        # Run the assessment
        results = self._compliance_manager.validate_all_requirements(
            standard=standard,
            category=category,
        )

        # Log any violations
        for req_id, (compliant, violation) in results.items():
            if not compliant and violation:
                log_security_event(
                    event_type=AuditEventType.COMPLIANCE_VIOLATION,
                    component="SecurityManager",
                    message=f"Compliance violation: {violation.message}",
                    details={
                        "requirement_id": req_id,
                        "severity": violation.severity.value,
                    },
                    level=AuditLogLevel.WARNING,
                )

        return results

    def encrypt_credentials(self, credentials: Dict[str, str]) -> str:
        """Encrypt credentials for storage.

        Args:
            credentials: Dictionary of credentials

        Returns:
            Encrypted credentials string
        """
        # Encrypt with CONFIDENTIAL classification
        return self._encryption_manager.encrypt_dict(
            credentials, DataClassification.CONFIDENTIAL
        )

    def decrypt_credentials(self, encrypted_credentials: str) -> Dict[str, str]:
        """Decrypt credentials from storage.

        Args:
            encrypted_credentials: Encrypted credentials string

        Returns:
            Decrypted credentials dictionary
        """
        return self._encryption_manager.decrypt_dict(encrypted_credentials)

    def report_security_finding(
        self,
        title: str,
        description: str,
        vulnerability_type: VulnerabilityType,
        severity: VulnerabilitySeverity,
        evidence: str,
        remediation: str = "",
        cwe_id: Optional[str] = None,
    ) -> str:
        """Report a security finding.

        Args:
            title: Finding title
            description: Finding description
            vulnerability_type: Type of vulnerability
            severity: Severity level
            evidence: Evidence of the vulnerability
            remediation: Optional remediation steps
            cwe_id: Optional CWE ID

        Returns:
            Finding ID
        """
        # Log the finding
        finding_id = add_vulnerability(
            title=title,
            description=description,
            vulnerability_type=vulnerability_type,
            severity=severity,
            evidence=evidence,
            remediation=remediation,
            cwe_id=cwe_id,
        )

        # Log the security event
        log_security_event(
            event_type=AuditEventType.SECURITY_ALERT,
            component="SecurityManager",
            message=f"Security finding reported: {title}",
            details={
                "finding_id": finding_id,
                "vulnerability_type": vulnerability_type.value,
                "severity": severity.value,
            },
            level=AuditLogLevel.SECURITY,
        )

        return finding_id

    def execute_in_sandbox(
        self,
        command: List[str],
        files: Optional[Dict[str, str]] = None,
        isolation_level: Optional[SandboxIsolationLevel] = None,
        resource_limits: Optional[SandboxResourceLimits] = None,
    ) -> Dict[str, Any]:
        """Execute a command in a security sandbox.

        Args:
            command: Command to execute
            files: Optional dictionary of files to create (path -> content)
            isolation_level: Optional isolation level
            resource_limits: Optional resource limits

        Returns:
            Dictionary with execution results
        """
        # Determine the isolation level based on configuration and availability
        if isolation_level is None:
            isolation_level = SandboxIsolationLevel(
                self._config.get("sandbox.default_isolation", "basic")
            )

        # If container isolation is requested but not available, fall back to basic
        if (
            isolation_level == SandboxIsolationLevel.CONTAINER
            and not is_container_available()
        ):
            logger.warning(
                "Container isolation requested but Docker is not available; falling back to basic isolation"
            )
            isolation_level = SandboxIsolationLevel.BASIC

        # Set default resource limits if not provided
        if resource_limits is None:
            resource_limits = SandboxResourceLimits(
                memory_mb=self._config.get("sandbox.memory_limit_mb", 512),
                cpu_time_sec=self._config.get("sandbox.cpu_time_limit_sec", 30),
                wall_time_sec=self._config.get("sandbox.wall_time_limit_sec", 60),
                disk_space_mb=self._config.get("sandbox.disk_space_limit_mb", 100),
                network_access=self._config.get("sandbox.allow_network", False),
                process_count=self._config.get("sandbox.process_limit", 10),
                file_size_mb=self._config.get("sandbox.file_size_limit_mb", 10),
            )

        # Log the execution request
        user_id = None
        user = SecurityContext.get_current_user()
        if user:
            user_id = user.user_id

        log_security_event(
            event_type=AuditEventType.TOOL_EXECUTED,
            component="SecurityManager",
            message=f"Executing command in sandbox: {' '.join(command)}",
            user_id=user_id,
            details={
                "command": command,
                "isolation_level": isolation_level.value,
            },
            level=AuditLogLevel.INFO,
        )

        # Convert files to bytes
        binary_files = {}
        if files:
            for path, content in files.items():
                binary_files[path] = content.encode()

        # Execute in the sandbox
        from skwaq.security.sandbox import execute_in_sandbox

        result = execute_in_sandbox(
            command=command,
            isolation_level=isolation_level,
            resource_limits=resource_limits,
            files=binary_files,
            cleanup=True,
        )

        # Convert result to dictionary
        return result.to_dict()


def get_security_manager() -> SecurityManager:
    """Get the global security manager instance.

    Returns:
        SecurityManager instance
    """
    return SecurityManager()


# Security decorator for securing functions
F = TypeVar("F", bound=Callable[..., Any])


def secure_operation(
    permission: Permission, resource_arg: Optional[str] = None
) -> Callable[[F], F]:
    """Decorator for securing operations with comprehensive security controls.

    This decorator provides:
    1. Permission checking
    2. Audit logging
    3. Error handling

    Args:
        permission: Required permission
        resource_arg: Optional argument name for resource ID

    Returns:
        Decorated function
    """

    def decorator(func: F) -> F:
        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            # Get the current user from the security context
            user = SecurityContext.get_current_user()
            if user is None:
                raise SecurityOperationError(
                    "No authenticated user in security context"
                )

            # Get resource ID if specified
            resource_id = None
            if resource_arg and resource_arg in kwargs:
                resource_id = kwargs[resource_arg]

            # Check permission
            security_manager = get_security_manager()
            if not security_manager.check_permission(permission, resource_id):
                # Log the permission denial
                log_security_event(
                    event_type=AuditEventType.PERMISSION_DENIED,
                    component=func.__module__,
                    message=f"Permission denied: {permission.value}",
                    user_id=user.user_id,
                    details={
                        "function": f"{func.__module__}.{func.__name__}",
                        "resource_id": resource_id,
                    },
                    level=AuditLogLevel.WARNING,
                )

                raise SecurityOperationError(f"Permission denied: {permission.value}")

            # Log the operation
            log_security_event(
                event_type=AuditEventType.PERMISSION_GRANTED,
                component=func.__module__,
                message=f"Permission granted: {permission.value}",
                user_id=user.user_id,
                details={
                    "function": f"{func.__module__}.{func.__name__}",
                    "resource_id": resource_id,
                },
                level=AuditLogLevel.INFO,
            )

            try:
                # Call the function
                result = func(*args, **kwargs)

                # Log successful operation
                log_security_event(
                    event_type=(
                        AuditEventType.DATA_ACCESSED
                        if "get" in func.__name__.lower()
                        else AuditEventType.DATA_MODIFIED
                    ),
                    component=func.__module__,
                    message=f"Operation completed: {func.__name__}",
                    user_id=user.user_id,
                    details={
                        "function": f"{func.__module__}.{func.__name__}",
                        "resource_id": resource_id,
                    },
                    level=AuditLogLevel.INFO,
                )

                return result

            except Exception as e:
                # Log operation error
                log_security_event(
                    event_type=AuditEventType.COMPONENT_ERROR,
                    component=func.__module__,
                    message=f"Operation error: {func.__name__} - {e}",
                    user_id=user.user_id,
                    details={
                        "function": f"{func.__module__}.{func.__name__}",
                        "resource_id": resource_id,
                        "error": str(e),
                    },
                    level=AuditLogLevel.ERROR,
                )

                # Re-raise the exception
                raise

        return cast(F, wrapper)

    return decorator

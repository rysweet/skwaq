"""Audit logging module for Skwaq.

This module provides audit logging functionality for the Skwaq
vulnerability assessment copilot, tracking security and compliance
relevant events for auditing purposes.
"""

import datetime
import hashlib
import json
import os
import uuid
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional

from skwaq.events.system_events import EventType, SystemEvent, subscribe
from skwaq.security.encryption import decrypt_sensitive_data, encrypt_sensitive_data
from skwaq.utils.config import get_config
from skwaq.utils.logging import get_logger

logger = get_logger(__name__)


class AuditLogLevel(Enum):
    """Audit log levels for events."""

    INFO = "info"  # Informational events
    WARNING = "warning"  # Warning events that might need attention
    ERROR = "error"  # Error events that indicate problems
    SECURITY = "security"  # Security-related events
    CRITICAL = "critical"  # Critical security events


class AuditEventType(Enum):
    """Types of events to audit."""

    # Authentication events
    USER_LOGIN = "user_login"
    USER_LOGOUT = "user_logout"
    USER_CREATED = "user_created"
    USER_MODIFIED = "user_modified"
    USER_DELETED = "user_deleted"
    USER_LOCKED = "user_locked"
    USER_UNLOCKED = "user_unlocked"
    PASSWORD_CHANGED = "password_changed"
    PASSWORD_RESET = "password_reset"

    # Authorization events
    PERMISSION_GRANTED = "permission_granted"
    PERMISSION_DENIED = "permission_denied"

    # Administration events
    CONFIG_CHANGED = "config_changed"
    SYSTEM_STARTUP = "system_startup"
    SYSTEM_SHUTDOWN = "system_shutdown"

    # Data access events
    DATA_ACCESSED = "data_accessed"
    DATA_MODIFIED = "data_modified"
    DATA_DELETED = "data_deleted"
    DATA_EXPORTED = "data_exported"

    # Security events
    SECURITY_ALERT = "security_alert"
    SECURITY_VIOLATION = "security_violation"
    ENCRYPTION_KEY_ROTATED = "encryption_key_rotated"
    SUSPICIOUS_ACTIVITY = "suspicious_activity"

    # Component events
    COMPONENT_INITIALIZED = "component_initialized"
    COMPONENT_ERROR = "component_error"

    # Repository events
    REPOSITORY_ADDED = "repository_added"
    REPOSITORY_DELETED = "repository_deleted"

    # Tool events
    TOOL_EXECUTED = "tool_executed"
    TOOL_RESULT = "tool_result"

    # Compliance events
    COMPLIANCE_CHECK = "compliance_check"
    COMPLIANCE_VIOLATION = "compliance_violation"


@dataclass
class AuditEvent:
    """Event data for audit logging."""

    event_type: AuditEventType
    user_id: Optional[str]
    component: str
    details: Dict[str, Any]
    level: AuditLogLevel = AuditLogLevel.INFO
    timestamp: datetime.datetime = field(default_factory=datetime.datetime.utcnow)
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    source_ip: Optional[str] = None
    success: bool = True
    resource_id: Optional[str] = None
    session_id: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for storage.

        Returns:
            Dictionary representation
        """
        return {
            "event_id": self.event_id,
            "event_type": self.event_type.value,
            "user_id": self.user_id,
            "component": self.component,
            "details": self.details,
            "level": self.level.value,
            "timestamp": self.timestamp.isoformat(),
            "source_ip": self.source_ip,
            "success": self.success,
            "resource_id": self.resource_id,
            "session_id": self.session_id,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AuditEvent":
        """Create from dictionary.

        Args:
            data: Dictionary with event data

        Returns:
            AuditEvent object
        """
        return cls(
            event_type=AuditEventType(data["event_type"]),
            user_id=data.get("user_id"),
            component=data["component"],
            details=data["details"],
            level=AuditLogLevel(data.get("level", "info")),
            timestamp=datetime.datetime.fromisoformat(data["timestamp"]),
            event_id=data.get("event_id", str(uuid.uuid4())),
            source_ip=data.get("source_ip"),
            success=data.get("success", True),
            resource_id=data.get("resource_id"),
            session_id=data.get("session_id"),
        )

    def get_checksum(self) -> str:
        """Generate a checksum for the event.

        This helps guarantee log integrity by providing a way to verify
        that log entries haven't been tampered with.

        Returns:
            SHA-256 hash of the event data
        """
        # Use a stable serialization of the event data
        data = json.dumps(self.to_dict(), sort_keys=True).encode()
        return hashlib.sha256(data).hexdigest()


class AuditLogger:
    """Audit logger for security and compliance events."""

    _instance = None

    def __new__(cls) -> "AuditLogger":
        """Create a singleton instance.

        Returns:
            Singleton instance
        """
        if cls._instance is None:
            cls._instance = super(AuditLogger, cls).__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self):
        """Initialize the audit logger."""
        if self._initialized:
            return

        self._initialized = True
        self._config = get_config()
        self._audit_enabled = self._config.get("audit.enabled", True)
        self._log_location = Path(
            self._config.get("audit.log_location", "~/.skwaq/audit_logs")
        ).expanduser()
        self._encrypt_logs = self._config.get("audit.encrypt_logs", True)
        self._retention_days = self._config.get("audit.retention_days", 90)

        # Create the log directory if it doesn't exist
        os.makedirs(self._log_location, exist_ok=True)

        # Subscribe to system events
        if self._audit_enabled:
            self._subscribe_to_events()

    def _subscribe_to_events(self) -> None:
        """Subscribe to system events for audit logging."""
        # Authentication events
        subscribe(EventType.SYSTEM, self._handle_system_event)

        # Log successful initialization
        self.log_event(
            AuditEvent(
                event_type=AuditEventType.COMPONENT_INITIALIZED,
                user_id=None,
                component="AuditLogger",
                details={"message": "Audit logging initialized"},
                level=AuditLogLevel.INFO,
            )
        )

    def _handle_system_event(self, event: SystemEvent) -> None:
        """Handle system events for audit logging.

        Args:
            event: System event
        """
        if not self._audit_enabled:
            return

        # Map system events to audit events
        if event.event_type == EventType.SYSTEM:
            audit_event = AuditEvent(
                event_type=AuditEventType.COMPONENT_INITIALIZED,
                user_id=None,
                component=event.sender,
                details={"message": event.message, "metadata": event.metadata},
                level=AuditLogLevel.INFO,
            )
            self.log_event(audit_event)
        elif event.event_type == EventType.CONFIG:
            audit_event = AuditEvent(
                event_type=AuditEventType.CONFIG_CHANGED,
                user_id=None,
                component=event.sender,
                details={"message": event.message, "metadata": event.metadata},
                level=AuditLogLevel.INFO,
            )
            self.log_event(audit_event)

    def log_event(self, event: AuditEvent) -> None:
        """Log an audit event.

        Args:
            event: Audit event
        """
        if not self._audit_enabled:
            return

        try:
            # Get the current date for file naming
            current_date = datetime.datetime.utcnow().strftime("%Y-%m-%d")
            log_file = self._log_location / f"audit_{current_date}.jsonl"

            # Add checksum to the event
            event_dict = event.to_dict()
            event_dict["checksum"] = event.get_checksum()

            # Convert to JSON
            log_entry = json.dumps(event_dict)

            # Encrypt if configured
            if self._encrypt_logs:
                encrypted_data = encrypt_sensitive_data(log_entry)
                log_entry = f"ENC:{encrypted_data.hex()}"

            # Write to log file
            with open(log_file, "a") as f:
                f.write(log_entry + "\n")

            # Log to regular logger for debug purposes
            if (
                event.level == AuditLogLevel.CRITICAL
                or event.level == AuditLogLevel.ERROR
            ):
                logger.warning(
                    f"Audit event: {event.event_type.value} - {event.component} - {event.details.get('message', '')}"
                )
            else:
                logger.debug(
                    f"Audit event: {event.event_type.value} - {event.component}"
                )

        except Exception as e:
            logger.error(f"Error logging audit event: {e}")

    def query_events(
        self,
        start_date: Optional[datetime.datetime] = None,
        end_date: Optional[datetime.datetime] = None,
        event_types: Optional[List[AuditEventType]] = None,
        user_id: Optional[str] = None,
        component: Optional[str] = None,
        level: Optional[AuditLogLevel] = None,
        resource_id: Optional[str] = None,
        success: Optional[bool] = None,
    ) -> List[AuditEvent]:
        """Query audit events within a date range.

        Args:
            start_date: Optional start date for query
            end_date: Optional end date for query
            event_types: Optional list of event types to include
            user_id: Optional user ID to filter by
            component: Optional component to filter by
            level: Optional audit level to filter by
            resource_id: Optional resource ID to filter by
            success: Optional success status to filter by

        Returns:
            List of audit events matching criteria
        """
        if not self._audit_enabled:
            return []

        # Default to last 24 hours if no dates provided
        if start_date is None:
            start_date = datetime.datetime.utcnow() - datetime.timedelta(days=1)
        if end_date is None:
            end_date = datetime.datetime.utcnow()

        # Convert event types to values for comparison
        event_type_values = None
        if event_types:
            event_type_values = [et.value for et in event_types]

        # Get the date range for files to check
        current_date = start_date
        date_strs = []

        while current_date <= end_date:
            date_strs.append(current_date.strftime("%Y-%m-%d"))
            current_date += datetime.timedelta(days=1)

        results = []

        # Check each log file in the date range
        for date_str in date_strs:
            log_file = self._log_location / f"audit_{date_str}.jsonl"

            if not log_file.exists():
                continue

            with open(log_file, "r") as f:
                for line in f:
                    line = line.strip()

                    if not line:
                        continue

                    try:
                        # Check if encrypted
                        if line.startswith("ENC:"):
                            # Decrypt the line
                            encrypted_hex = line[4:]
                            encrypted_data = bytes.fromhex(encrypted_hex)
                            decrypted_data = decrypt_sensitive_data(encrypted_data)
                            event_data = json.loads(decrypted_data)
                        else:
                            # Parse JSON directly
                            event_data = json.loads(line)

                        # Apply filters
                        event_timestamp = datetime.datetime.fromisoformat(
                            event_data["timestamp"]
                        )

                        if event_timestamp < start_date or event_timestamp > end_date:
                            continue

                        if (
                            event_type_values
                            and event_data["event_type"] not in event_type_values
                        ):
                            continue

                        if user_id and event_data.get("user_id") != user_id:
                            continue

                        if component and event_data.get("component") != component:
                            continue

                        if level and event_data.get("level") != level.value:
                            continue

                        if resource_id and event_data.get("resource_id") != resource_id:
                            continue

                        if (
                            success is not None
                            and event_data.get("success", True) != success
                        ):
                            continue

                        # Check integrity via checksum
                        stored_checksum = event_data.pop("checksum", None)
                        if stored_checksum:
                            event = AuditEvent.from_dict(event_data)
                            calculated_checksum = event.get_checksum()

                            if calculated_checksum != stored_checksum:
                                logger.warning(
                                    f"Checksum mismatch for audit event {event_data.get('event_id')}"
                                )
                                continue

                        # Add to results
                        results.append(AuditEvent.from_dict(event_data))

                    except Exception as e:
                        logger.error(f"Error parsing audit log entry: {e}")

        # Sort by timestamp (newest first)
        results.sort(key=lambda x: x.timestamp, reverse=True)
        return results

    def clean_old_logs(self) -> int:
        """Clean up old audit logs.

        Returns:
            Number of log files deleted
        """
        if not self._audit_enabled:
            return 0

        # Calculate the cutoff date
        cutoff_date = datetime.datetime.utcnow() - datetime.timedelta(
            days=self._retention_days
        )
        cutoff_date_str = cutoff_date.strftime("%Y-%m-%d")

        # Get all log files
        log_files = list(self._log_location.glob("audit_*.jsonl"))
        deleted_count = 0

        for log_file in log_files:
            # Get the date from the filename
            try:
                file_date_str = log_file.name.replace("audit_", "").replace(
                    ".jsonl", ""
                )

                # If the file date is before the cutoff date, delete it
                if file_date_str < cutoff_date_str:
                    log_file.unlink()
                    deleted_count += 1
            except Exception as e:
                logger.error(f"Error cleaning up audit log {log_file}: {e}")

        if deleted_count > 0:
            logger.info(f"Cleaned up {deleted_count} old audit log files")

        return deleted_count


def get_audit_logger() -> AuditLogger:
    """Get the global audit logger instance.

    Returns:
        AuditLogger instance
    """
    return AuditLogger()


# Helper functions for common audit logging tasks


def log_security_event(
    event_type: AuditEventType,
    component: str,
    message: str,
    user_id: Optional[str] = None,
    details: Optional[Dict[str, Any]] = None,
    level: AuditLogLevel = AuditLogLevel.SECURITY,
    success: bool = True,
    resource_id: Optional[str] = None,
) -> None:
    """Log a security-related audit event.

    Args:
        event_type: Type of event
        component: Component that generated the event
        message: Event message
        user_id: Optional user ID
        details: Optional additional details
        level: Audit log level
        success: Whether the action was successful
        resource_id: Optional resource identifier
    """
    audit_logger = get_audit_logger()

    event_details = details or {}
    event_details["message"] = message

    audit_event = AuditEvent(
        event_type=event_type,
        user_id=user_id,
        component=component,
        details=event_details,
        level=level,
        success=success,
        resource_id=resource_id,
    )

    audit_logger.log_event(audit_event)


def log_user_activity(
    event_type: AuditEventType,
    user_id: str,
    component: str,
    message: str,
    details: Optional[Dict[str, Any]] = None,
    success: bool = True,
    resource_id: Optional[str] = None,
) -> None:
    """Log a user activity event.

    Args:
        event_type: Type of event
        user_id: User ID
        component: Component that generated the event
        message: Event message
        details: Optional additional details
        success: Whether the action was successful
        resource_id: Optional resource identifier
    """
    audit_logger = get_audit_logger()

    event_details = details or {}
    event_details["message"] = message

    audit_event = AuditEvent(
        event_type=event_type,
        user_id=user_id,
        component=component,
        details=event_details,
        level=AuditLogLevel.INFO,
        success=success,
        resource_id=resource_id,
    )

    audit_logger.log_event(audit_event)


def log_system_activity(
    event_type: AuditEventType,
    component: str,
    message: str,
    details: Optional[Dict[str, Any]] = None,
    level: AuditLogLevel = AuditLogLevel.INFO,
) -> None:
    """Log a system activity event.

    Args:
        event_type: Type of event
        component: Component that generated the event
        message: Event message
        details: Optional additional details
        level: Audit log level
    """
    audit_logger = get_audit_logger()

    event_details = details or {}
    event_details["message"] = message

    audit_event = AuditEvent(
        event_type=event_type,
        user_id=None,
        component=component,
        details=event_details,
        level=level,
    )

    audit_logger.log_event(audit_event)

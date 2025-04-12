"""Security module for Skwaq.

This module provides security-related functionality for the Skwaq
vulnerability assessment copilot, including authentication, authorization,
encryption, audit logging, compliance, vulnerability management, sandboxing,
and integrated security controls.
"""

from skwaq.security.audit import (
    AuditEventType,
    AuditLogLevel,
    get_audit_logger,
    log_security_event,
    log_system_activity,
    log_user_activity,
)
from skwaq.security.authentication import (
    AuthRole,
    UserCredentials,
    authenticate_api_key,
    authenticate_token,
    authenticate_user,
    get_auth_manager,
)
from skwaq.security.authorization import (
    Permission,
    get_authorization,
    get_resource_permissions,
    require_permission,
)
from skwaq.security.compliance import (
    ComplianceCategory,
    ComplianceStandard,
    get_compliance_manager,
    get_compliance_report,
    validate_requirement,
)
from skwaq.security.encryption import (
    DataClassification,
    decrypt_config_value,
    decrypt_sensitive_data,
    encrypt_config_value,
    encrypt_sensitive_data,
    get_encryption_manager,
)
from skwaq.security.integration import (
    SecurityConfigurationError,
    SecurityContext,
    SecurityManager,
    SecurityOperationError,
    get_security_manager,
    secure_operation,
)
from skwaq.security.sandbox import (
    SandboxIsolationLevel,
    SandboxResourceLimits,
    create_sandbox,
    execute_in_sandbox,
    is_container_available,
)
from skwaq.security.vulnerability import (
    VulnerabilityFinding,
    VulnerabilitySeverity,
    VulnerabilityStatus,
    VulnerabilityType,
    add_remediation,
    add_vulnerability,
    complete_remediation,
    get_vulnerability_manager,
    get_vulnerability_report,
)

__all__ = [
    # Authentication
    "AuthRole",
    "UserCredentials",
    "get_auth_manager",
    "authenticate_user",
    "authenticate_token",
    "authenticate_api_key",
    # Authorization
    "Permission",
    "get_authorization",
    "require_permission",
    "get_resource_permissions",
    # Audit
    "AuditEventType",
    "AuditLogLevel",
    "get_audit_logger",
    "log_security_event",
    "log_user_activity",
    "log_system_activity",
    # Compliance
    "ComplianceStandard",
    "ComplianceCategory",
    "get_compliance_manager",
    "validate_requirement",
    "get_compliance_report",
    # Encryption
    "DataClassification",
    "get_encryption_manager",
    "encrypt_sensitive_data",
    "decrypt_sensitive_data",
    "encrypt_config_value",
    "decrypt_config_value",
    # Sandbox
    "SandboxIsolationLevel",
    "SandboxResourceLimits",
    "create_sandbox",
    "execute_in_sandbox",
    "is_container_available",
    # Vulnerability
    "VulnerabilityType",
    "VulnerabilitySeverity",
    "VulnerabilityStatus",
    "VulnerabilityFinding",
    "get_vulnerability_manager",
    "add_vulnerability",
    "add_remediation",
    "complete_remediation",
    "get_vulnerability_report",
    # Integration
    "SecurityManager",
    "SecurityContext",
    "SecurityConfigurationError",
    "SecurityOperationError",
    "secure_operation",
    "get_security_manager",
]

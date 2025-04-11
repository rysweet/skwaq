"""Security module for Skwaq.

This module provides security-related functionality for the Skwaq
vulnerability assessment copilot, including authentication, authorization,
encryption, audit logging, compliance, vulnerability management, sandboxing,
and integrated security controls.
"""

from skwaq.security.authentication import (
    AuthRole,
    UserCredentials,
    get_auth_manager,
    authenticate_user,
    authenticate_token,
    authenticate_api_key,
)
from skwaq.security.authorization import (
    Permission,
    get_authorization,
    require_permission,
    get_resource_permissions,
)
from skwaq.security.audit import (
    AuditEventType,
    AuditLogLevel,
    get_audit_logger,
    log_security_event,
    log_user_activity,
    log_system_activity,
)
from skwaq.security.compliance import (
    ComplianceStandard,
    ComplianceCategory,
    get_compliance_manager,
    validate_requirement,
    get_compliance_report,
)
from skwaq.security.encryption import (
    DataClassification,
    get_encryption_manager,
    encrypt_sensitive_data,
    decrypt_sensitive_data,
    encrypt_config_value,
    decrypt_config_value,
)
from skwaq.security.sandbox import (
    SandboxIsolationLevel,
    SandboxResourceLimits,
    create_sandbox,
    execute_in_sandbox,
    is_container_available,
)
from skwaq.security.vulnerability import (
    VulnerabilityType,
    VulnerabilitySeverity,
    VulnerabilityStatus,
    VulnerabilityFinding,
    get_vulnerability_manager,
    add_vulnerability,
    add_remediation,
    complete_remediation,
    get_vulnerability_report,
)
from skwaq.security.integration import (
    SecurityManager,
    SecurityContext,
    SecurityConfigurationError,
    SecurityOperationError,
    secure_operation,
    get_security_manager,
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

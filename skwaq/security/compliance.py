"""Compliance module for Skwaq.

This module provides compliance-related functionality for the Skwaq
vulnerability assessment copilot, including compliance checks,
reporting, and governance documentation.
"""

import datetime
import json
import os
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple, Union, cast

from skwaq.security.audit import AuditEventType, AuditLogLevel, log_security_event
from skwaq.utils.config import get_config
from skwaq.utils.logging import get_logger

logger = get_logger(__name__)


class ComplianceStandard(Enum):
    """Compliance standards supported by the system."""

    SOC2 = "soc2"  # SOC 2 Trust Services Criteria
    PCI_DSS = "pci_dss"  # Payment Card Industry Data Security Standard
    HIPAA = "hipaa"  # Health Insurance Portability and Accountability Act
    GDPR = "gdpr"  # General Data Protection Regulation
    CCPA = "ccpa"  # California Consumer Privacy Act
    ISO27001 = "iso27001"  # ISO/IEC 27001 Information Security Management
    NIST_800_53 = "nist_800_53"  # NIST Special Publication 800-53
    CUSTOM = "custom"  # Custom compliance standard


class ComplianceCategory(Enum):
    """Categories for compliance requirements."""

    ACCESS_CONTROL = "access_control"
    AUDIT_LOGGING = "audit_logging"
    DATA_PROTECTION = "data_protection"
    ENCRYPTION = "encryption"
    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    INCIDENT_RESPONSE = "incident_response"
    NETWORK_SECURITY = "network_security"
    VULNERABILITY_MANAGEMENT = "vulnerability_management"
    PHYSICAL_SECURITY = "physical_security"
    CONFIGURATION_MANAGEMENT = "configuration_management"
    BUSINESS_CONTINUITY = "business_continuity"
    RISK_MANAGEMENT = "risk_management"
    THIRD_PARTY_MANAGEMENT = "third_party_management"
    GOVERNANCE = "governance"


class ComplianceViolationSeverity(Enum):
    """Severity levels for compliance violations."""

    CRITICAL = "critical"  # Severe violation requiring immediate action
    HIGH = "high"  # Significant violation requiring prompt action
    MEDIUM = "medium"  # Moderate violation requiring timely action
    LOW = "low"  # Minor violation requiring routine action
    INFORMATIONAL = "informational"  # Informational finding, not a violation


@dataclass
class ComplianceRequirement:
    """Compliance requirement definition."""

    id: str
    name: str
    description: str
    standard: ComplianceStandard
    category: ComplianceCategory
    validation_function: str  # Name of function that validates this requirement
    parameters: Dict[str, Any] = field(default_factory=dict)
    references: Dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary.

        Returns:
            Dictionary representation
        """
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "standard": self.standard.value,
            "category": self.category.value,
            "validation_function": self.validation_function,
            "parameters": self.parameters,
            "references": self.references,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ComplianceRequirement":
        """Create from dictionary.

        Args:
            data: Dictionary with requirement data

        Returns:
            ComplianceRequirement object
        """
        return cls(
            id=data["id"],
            name=data["name"],
            description=data["description"],
            standard=ComplianceStandard(data["standard"]),
            category=ComplianceCategory(data["category"]),
            validation_function=data["validation_function"],
            parameters=data.get("parameters", {}),
            references=data.get("references", {}),
        )


@dataclass
class ComplianceViolation:
    """Compliance violation finding."""

    requirement_id: str
    component: str
    message: str
    severity: ComplianceViolationSeverity
    evidence: str
    recommendation: str
    violation_id: str = field(default_factory=lambda: str(__import__("uuid").uuid4()))
    timestamp: datetime.datetime = field(default_factory=datetime.datetime.utcnow)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary.

        Returns:
            Dictionary representation
        """
        return {
            "violation_id": self.violation_id,
            "requirement_id": self.requirement_id,
            "component": self.component,
            "message": self.message,
            "severity": self.severity.value,
            "evidence": self.evidence,
            "recommendation": self.recommendation,
            "timestamp": self.timestamp.isoformat(),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ComplianceViolation":
        """Create from dictionary.

        Args:
            data: Dictionary with violation data

        Returns:
            ComplianceViolation object
        """
        return cls(
            requirement_id=data["requirement_id"],
            component=data["component"],
            message=data["message"],
            severity=ComplianceViolationSeverity(data["severity"]),
            evidence=data["evidence"],
            recommendation=data["recommendation"],
            violation_id=data.get("violation_id", str(__import__("uuid").uuid4())),
            timestamp=(
                datetime.datetime.fromisoformat(data["timestamp"])
                if "timestamp" in data
                else datetime.datetime.utcnow()
            ),
        )


class ComplianceManager:
    """Manager for compliance functionality."""

    _instance = None

    def __new__(cls) -> "ComplianceManager":
        """Create a singleton instance.

        Returns:
            Singleton instance
        """
        if cls._instance is None:
            cls._instance = super(ComplianceManager, cls).__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self):
        """Initialize the compliance manager."""
        if self._initialized:
            return

        self._initialized = True
        self._config = get_config()
        self._requirements: Dict[str, ComplianceRequirement] = {}
        self._violations: List[ComplianceViolation] = []
        self._validation_functions: Dict[str, callable] = {}

        # Load built-in requirements
        self._load_built_in_requirements()

        # Register built-in validation functions
        self._register_built_in_validations()

    def _load_built_in_requirements(self) -> None:
        """Load built-in compliance requirements."""
        # Authentication requirements
        auth_req = ComplianceRequirement(
            id="AUTH-01",
            name="Password Complexity",
            description="Password must meet complexity requirements",
            standard=ComplianceStandard.SOC2,
            category=ComplianceCategory.AUTHENTICATION,
            validation_function="validate_password_complexity",
            parameters={
                "min_length": 8,
                "require_numbers": True,
                "require_special": True,
            },
            references={"SOC2": "CC6.1", "NIST": "IA-5(1)"},
        )
        self._requirements[auth_req.id] = auth_req

        auth_req2 = ComplianceRequirement(
            id="AUTH-02",
            name="MFA Requirement",
            description="Multi-factor authentication must be available",
            standard=ComplianceStandard.PCI_DSS,
            category=ComplianceCategory.AUTHENTICATION,
            validation_function="validate_mfa_availability",
            parameters={},
            references={"PCI_DSS": "8.3", "SOC2": "CC6.1"},
        )
        self._requirements[auth_req2.id] = auth_req2

        # Encryption requirements
        encrypt_req = ComplianceRequirement(
            id="ENC-01",
            name="Data Encryption at Rest",
            description="Sensitive data must be encrypted at rest",
            standard=ComplianceStandard.SOC2,
            category=ComplianceCategory.ENCRYPTION,
            validation_function="validate_encryption_at_rest",
            parameters={"data_classes": ["CONFIDENTIAL", "RESTRICTED"]},
            references={"SOC2": "CC6.1", "NIST": "SC-28"},
        )
        self._requirements[encrypt_req.id] = encrypt_req

        # Audit logging requirements
        audit_req = ComplianceRequirement(
            id="AUDIT-01",
            name="Security Event Logging",
            description="Security events must be logged",
            standard=ComplianceStandard.SOC2,
            category=ComplianceCategory.AUDIT_LOGGING,
            validation_function="validate_security_logging",
            parameters={},
            references={"SOC2": "CC7.2", "NIST": "AU-2"},
        )
        self._requirements[audit_req.id] = audit_req

        # Authorization requirements
        authz_req = ComplianceRequirement(
            id="AUTHZ-01",
            name="Role-Based Access Control",
            description="Access control must be based on user roles",
            standard=ComplianceStandard.SOC2,
            category=ComplianceCategory.AUTHORIZATION,
            validation_function="validate_rbac",
            parameters={},
            references={"SOC2": "CC6.3", "NIST": "AC-2"},
        )
        self._requirements[authz_req.id] = authz_req

        # Vulnerability management
        vuln_req = ComplianceRequirement(
            id="VULN-01",
            name="Regular Vulnerability Scanning",
            description="Regular vulnerability scanning must be performed",
            standard=ComplianceStandard.PCI_DSS,
            category=ComplianceCategory.VULNERABILITY_MANAGEMENT,
            validation_function="validate_vuln_scanning",
            parameters={"min_frequency_days": 30},
            references={"PCI_DSS": "11.2", "NIST": "RA-5"},
        )
        self._requirements[vuln_req.id] = vuln_req

        logger.info(
            f"Loaded {len(self._requirements)} built-in compliance requirements"
        )

    def _register_built_in_validations(self) -> None:
        """Register built-in validation functions."""

        # Password complexity validation
        def validate_password_complexity(params: Dict[str, Any]) -> Tuple[bool, str]:
            min_length = params.get("min_length", 8)
            config_min_length = self._config.get("security.password_min_length")

            if config_min_length is None or config_min_length < min_length:
                return (
                    False,
                    f"Password minimum length ({config_min_length or 'not set'}) does not meet requirement ({min_length})",
                )

            return True, "Password complexity requirements are met"

        # MFA validation
        def validate_mfa_availability(params: Dict[str, Any]) -> Tuple[bool, str]:
            mfa_enabled = self._config.get("security.mfa_enabled", False)
            if not mfa_enabled:
                return False, "Multi-factor authentication is not enabled"

            return True, "Multi-factor authentication is available"

        # Encryption validation
        def validate_encryption_at_rest(params: Dict[str, Any]) -> Tuple[bool, str]:
            data_encryption_enabled = self._config.get("encryption.enabled", False)
            if not data_encryption_enabled:
                return False, "Data encryption at rest is not enabled"

            return True, "Data encryption at rest is enabled"

        # Security logging validation
        def validate_security_logging(params: Dict[str, Any]) -> Tuple[bool, str]:
            audit_enabled = self._config.get("audit.enabled", False)
            if not audit_enabled:
                return False, "Security event logging is not enabled"

            return True, "Security event logging is enabled"

        # RBAC validation
        def validate_rbac(params: Dict[str, Any]) -> Tuple[bool, str]:
            rbac_enabled = self._config.get("security.rbac_enabled", False)
            if not rbac_enabled:
                return False, "Role-based access control is not enabled"

            return True, "Role-based access control is enabled"

        # Vulnerability scanning validation
        def validate_vuln_scanning(params: Dict[str, Any]) -> Tuple[bool, str]:
            last_scan = self._config.get("security.last_vuln_scan")
            if not last_scan:
                return False, "No vulnerability scan has been recorded"

            try:
                last_scan_date = datetime.datetime.fromisoformat(last_scan)
                days_since_scan = (datetime.datetime.utcnow() - last_scan_date).days
                min_frequency = params.get("min_frequency_days", 30)

                if days_since_scan > min_frequency:
                    return (
                        False,
                        f"Last vulnerability scan was {days_since_scan} days ago (requirement: {min_frequency} days)",
                    )

            except Exception as e:
                return False, f"Error parsing last scan date: {e}"

            return (
                True,
                f"Vulnerability scanning was performed {days_since_scan} days ago",
            )

        # Register all validation functions
        self._validation_functions = {
            "validate_password_complexity": validate_password_complexity,
            "validate_mfa_availability": validate_mfa_availability,
            "validate_encryption_at_rest": validate_encryption_at_rest,
            "validate_security_logging": validate_security_logging,
            "validate_rbac": validate_rbac,
            "validate_vuln_scanning": validate_vuln_scanning,
        }

    def add_requirement(self, requirement: ComplianceRequirement) -> None:
        """Add a new compliance requirement.

        Args:
            requirement: Compliance requirement to add
        """
        self._requirements[requirement.id] = requirement
        logger.info(
            f"Added compliance requirement: {requirement.id} - {requirement.name}"
        )

    def get_requirement(self, requirement_id: str) -> Optional[ComplianceRequirement]:
        """Get a compliance requirement by ID.

        Args:
            requirement_id: Requirement ID

        Returns:
            ComplianceRequirement if found, None otherwise
        """
        return self._requirements.get(requirement_id)

    def get_requirements(
        self,
        standard: Optional[ComplianceStandard] = None,
        category: Optional[ComplianceCategory] = None,
    ) -> List[ComplianceRequirement]:
        """Get compliance requirements.

        Args:
            standard: Optional compliance standard to filter by
            category: Optional category to filter by

        Returns:
            List of compliance requirements
        """
        requirements = list(self._requirements.values())

        if standard:
            requirements = [r for r in requirements if r.standard == standard]

        if category:
            requirements = [r for r in requirements if r.category == category]

        return requirements

    def register_validation_function(
        self, function_name: str, validation_function: callable
    ) -> None:
        """Register a validation function.

        Args:
            function_name: Name of the function
            validation_function: Validation function
        """
        self._validation_functions[function_name] = validation_function
        logger.info(f"Registered validation function: {function_name}")

    def validate_requirement(
        self, requirement_id: str, component: str = "system"
    ) -> Tuple[bool, Optional[ComplianceViolation]]:
        """Validate a compliance requirement.

        Args:
            requirement_id: Requirement ID
            component: Component being validated

        Returns:
            Tuple of (compliance status, violation if any)
        """
        requirement = self._requirements.get(requirement_id)
        if not requirement:
            logger.error(f"Unknown compliance requirement: {requirement_id}")
            return False, None

        # Get the validation function
        validation_function = self._validation_functions.get(
            requirement.validation_function
        )
        if not validation_function:
            logger.error(
                f"Unknown validation function: {requirement.validation_function}"
            )
            return False, None

        try:
            # Call the validation function
            compliant, message = validation_function(requirement.parameters)

            if compliant:
                # Log a successful compliance check
                log_security_event(
                    event_type=AuditEventType.COMPLIANCE_CHECK,
                    component=component,
                    message=f"Compliance check passed: {requirement.name}",
                    details={"requirement_id": requirement_id, "result": "pass"},
                    level=AuditLogLevel.INFO,
                )

                return True, None
            else:
                # Create a violation
                violation = ComplianceViolation(
                    requirement_id=requirement_id,
                    component=component,
                    message=f"Failed compliance check: {requirement.name}",
                    severity=ComplianceViolationSeverity.MEDIUM,
                    evidence=message,
                    recommendation=f"Ensure {requirement.description.lower()}",
                )

                # Add to violations list
                self._violations.append(violation)

                # Log the violation
                log_security_event(
                    event_type=AuditEventType.COMPLIANCE_VIOLATION,
                    component=component,
                    message=f"Compliance violation detected: {requirement.name}",
                    details={
                        "requirement_id": requirement_id,
                        "evidence": message,
                        "violation_id": violation.violation_id,
                    },
                    level=AuditLogLevel.WARNING,
                )

                return False, violation

        except Exception as e:
            logger.error(
                f"Error validating compliance requirement {requirement_id}: {e}"
            )
            return False, None

    def validate_all_requirements(
        self,
        standard: Optional[ComplianceStandard] = None,
        category: Optional[ComplianceCategory] = None,
        component: str = "system",
    ) -> Dict[str, Tuple[bool, Optional[ComplianceViolation]]]:
        """Validate all compliance requirements.

        Args:
            standard: Optional compliance standard to filter by
            category: Optional category to filter by
            component: Component being validated

        Returns:
            Dictionary mapping requirement IDs to validation results
        """
        requirements = self.get_requirements(standard=standard, category=category)
        results = {}

        for requirement in requirements:
            results[requirement.id] = self.validate_requirement(
                requirement_id=requirement.id, component=component
            )

        return results

    def get_violations(
        self,
        standard: Optional[ComplianceStandard] = None,
        category: Optional[ComplianceCategory] = None,
        severity: Optional[ComplianceViolationSeverity] = None,
    ) -> List[ComplianceViolation]:
        """Get compliance violations.

        Args:
            standard: Optional compliance standard to filter by
            category: Optional category to filter by
            severity: Optional severity to filter by

        Returns:
            List of compliance violations
        """
        violations = self._violations

        if standard or category:
            filtered_violations = []
            for violation in violations:
                requirement = self._requirements.get(violation.requirement_id)
                if not requirement:
                    continue

                if standard and requirement.standard != standard:
                    continue

                if category and requirement.category != category:
                    continue

                filtered_violations.append(violation)

            violations = filtered_violations

        if severity:
            violations = [v for v in violations if v.severity == severity]

        return violations

    def generate_compliance_report(
        self,
        title: str = "Compliance Assessment Report",
        standard: Optional[ComplianceStandard] = None,
        include_passing: bool = True,
    ) -> Dict[str, Any]:
        """Generate a compliance report.

        Args:
            title: Report title
            standard: Optional compliance standard to filter by
            include_passing: Whether to include passing checks

        Returns:
            Compliance report as a dictionary
        """
        # Run validation on all requirements
        validation_results = self.validate_all_requirements(standard=standard)

        # Count passing and failing checks
        pass_count = sum(1 for result in validation_results.values() if result[0])
        fail_count = sum(1 for result in validation_results.values() if not result[0])

        # Calculate overall compliance score (percentage of passing checks)
        total_checks = len(validation_results)
        compliance_score = (pass_count / total_checks * 100) if total_checks > 0 else 0

        # Get all violations
        violations = []
        for req_id, (compliant, violation) in validation_results.items():
            if not compliant and violation:
                violations.append(violation)

        # Group findings by category
        category_results = {}
        for req_id, (compliant, violation) in validation_results.items():
            requirement = self._requirements.get(req_id)
            if not requirement:
                continue

            category = requirement.category.value
            if category not in category_results:
                category_results[category] = {"pass": 0, "fail": 0, "total": 0}

            category_results[category]["total"] += 1
            if compliant:
                category_results[category]["pass"] += 1
            else:
                category_results[category]["fail"] += 1

        # Build the report
        report = {
            "title": title,
            "date": datetime.datetime.utcnow().isoformat(),
            "standard": standard.value if standard else "All",
            "summary": {
                "total_checks": total_checks,
                "passing_checks": pass_count,
                "failing_checks": fail_count,
                "compliance_score": round(compliance_score, 1),
            },
            "category_summary": category_results,
            "violations": [v.to_dict() for v in violations],
        }

        # Include passing checks if requested
        if include_passing:
            passing_checks = []
            for req_id, (compliant, _) in validation_results.items():
                if compliant:
                    requirement = self._requirements.get(req_id)
                    if requirement:
                        passing_checks.append(
                            {
                                "id": requirement.id,
                                "name": requirement.name,
                                "standard": requirement.standard.value,
                                "category": requirement.category.value,
                            }
                        )

            report["passing_checks"] = passing_checks

        return report

    def save_violations_to_file(self, file_path: str) -> int:
        """Save compliance violations to a file.

        Args:
            file_path: Path to save violations to

        Returns:
            Number of violations saved
        """
        # Create directory if it doesn't exist
        os.makedirs(os.path.dirname(os.path.abspath(file_path)), exist_ok=True)

        # Convert violations to dictionaries
        violations_data = [v.to_dict() for v in self._violations]

        # Write to file
        with open(file_path, "w") as f:
            json.dump(violations_data, f, indent=2)

        return len(violations_data)

    def load_violations_from_file(self, file_path: str) -> int:
        """Load compliance violations from a file.

        Args:
            file_path: Path to load violations from

        Returns:
            Number of violations loaded
        """
        if not os.path.exists(file_path):
            logger.warning(f"Violations file not found: {file_path}")
            return 0

        try:
            # Read from file
            with open(file_path, "r") as f:
                violations_data = json.load(f)

            # Convert to ComplianceViolation objects
            violations = []
            for data in violations_data:
                try:
                    violations.append(ComplianceViolation.from_dict(data))
                except Exception as e:
                    logger.error(f"Error parsing violation: {e}")

            # Replace current violations
            self._violations = violations

            return len(violations)
        except Exception as e:
            logger.error(f"Error loading violations from file: {e}")
            return 0


def get_compliance_manager() -> ComplianceManager:
    """Get the global compliance manager instance.

    Returns:
        ComplianceManager instance
    """
    return ComplianceManager()


# Helper functions for common compliance tasks


def validate_requirement(requirement_id: str, component: str = "system") -> bool:
    """Validate a compliance requirement.

    Args:
        requirement_id: Requirement ID
        component: Component being validated

    Returns:
        True if compliant, False otherwise
    """
    compliance_manager = get_compliance_manager()
    result, _ = compliance_manager.validate_requirement(requirement_id, component)
    return result


def get_compliance_report(
    standard: Optional[ComplianceStandard] = None,
    title: str = "Compliance Assessment Report",
) -> Dict[str, Any]:
    """Generate a compliance report.

    Args:
        standard: Optional compliance standard to filter by
        title: Report title

    Returns:
        Compliance report as a dictionary
    """
    compliance_manager = get_compliance_manager()
    return compliance_manager.generate_compliance_report(title=title, standard=standard)

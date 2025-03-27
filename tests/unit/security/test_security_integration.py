"""Unit tests for skwaq.security module integration."""

import os
import pytest
from unittest.mock import MagicMock, patch, mock_open
from pathlib import Path

from skwaq.security.authentication import (
    AuthenticationManager, 
    AuthRole, 
    UserCredentials,
    get_auth_manager
)
from skwaq.security.authorization import (
    Authorization,
    Permission,
    get_authorization
)
from skwaq.security.audit import (
    AuditLogger,
    AuditEventType,
    AuditLogLevel,
    log_security_event,
    get_audit_logger
)
from skwaq.security.encryption import (
    EncryptionManager,
    DataClassification,
    encrypt_sensitive_data,
    decrypt_sensitive_data,
    get_encryption_manager
)
from skwaq.security.compliance import (
    ComplianceManager,
    ComplianceStandard,
    ComplianceCategory,
    get_compliance_manager
)
from skwaq.security.sandbox import (
    Sandbox,
    SandboxIsolationLevel,
    create_sandbox
)
from skwaq.security.vulnerability import (
    VulnerabilityManager,
    get_vulnerability_manager
)


class TestSecurityIntegration:
    """Tests for the security module integration."""
    
    def setup_method(self):
        """Set up test fixtures before each test."""
        # Reset singleton instances
        AuthenticationManager._instance = None
        Authorization._instance = None
        AuditLogger._instance = None
        EncryptionManager._instance = None
        ComplianceManager._instance = None
        VulnerabilityManager._instance = None
    
    @patch('skwaq.security.authentication.get_config')
    @patch('skwaq.security.authorization.get_config')
    @patch('skwaq.security.audit.get_config')
    @patch('skwaq.security.encryption.get_config')
    @patch('skwaq.security.compliance.get_config')
    @patch('skwaq.security.vulnerability.get_config')
    @patch('os.makedirs')
    def test_security_component_initialization(
        self, mock_makedirs, mock_vuln_config, mock_compliance_config, 
        mock_encryption_config, mock_audit_config, mock_auth_config,
        mock_authn_config
    ):
        """Test that all security components can be initialized together."""
        # Configure mocks
        for mock_config in [
            mock_authn_config, mock_auth_config, mock_audit_config, 
            mock_encryption_config, mock_compliance_config, mock_vuln_config
        ]:
            mock_config.return_value.get.return_value = "/tmp/test_dir"
        
        # Initialize all security components
        auth_manager = get_auth_manager()
        authz = get_authorization()
        audit_logger = get_audit_logger()
        encryption_manager = get_encryption_manager()
        compliance_manager = get_compliance_manager()
        vuln_manager = get_vulnerability_manager()
        
        # Verify all components were initialized
        assert auth_manager._initialized is True
        assert authz._initialized is True
        assert audit_logger._initialized is True
        assert encryption_manager._initialized is True
        assert compliance_manager._initialized is True
        assert vuln_manager._initialized is True
    
    @patch('skwaq.security.authentication.get_config')
    @patch('skwaq.security.authorization.get_config')
    @patch('os.makedirs')
    def test_authentication_authorization_integration(
        self, mock_makedirs, mock_auth_config, mock_authn_config
    ):
        """Test integration between authentication and authorization components."""
        # Configure mocks
        mock_authn_config.return_value.get.return_value = "/tmp/test_dir"
        mock_auth_config.return_value.get.return_value = "/tmp/test_dir"
        
        # Create user with specific roles
        auth_manager = get_auth_manager()
        auth_manager._initialized = True
        
        # Create a test user
        user = UserCredentials(
            username="test_user",
            password_hash="hash123",
            salt="salt123",
            roles={AuthRole.USER},
            user_id="user123"
        )
        
        # Get authorization and check permissions
        authz = get_authorization()
        
        # User should have permissions from the USER role
        assert authz.has_permission(user, Permission.VIEW_REPOSITORY) is True
        assert authz.has_permission(user, Permission.LIST_REPOSITORIES) is True
        
        # User should not have ADMIN permissions
        assert authz.has_permission(user, Permission.ADMIN) is False
        assert authz.has_permission(user, Permission.MANAGE_USERS) is False
        
        # Add admin role and verify permissions change
        auth_manager.add_user_role = MagicMock()
        auth_manager.add_user_role("test_user", AuthRole.ADMIN)
        user.roles.add(AuthRole.ADMIN)
        
        # Now user should have ADMIN permissions
        assert authz.has_permission(user, Permission.ADMIN) is True
        assert authz.has_permission(user, Permission.MANAGE_USERS) is True
    
    @patch('skwaq.security.authentication.get_config')
    @patch('skwaq.security.audit.get_config')
    @patch('os.makedirs')
    def test_authentication_audit_integration(
        self, mock_makedirs, mock_audit_config, mock_authn_config
    ):
        """Test integration between authentication and audit components."""
        # Configure mocks
        mock_authn_config.return_value.get.return_value = "/tmp/test_dir"
        mock_audit_config.return_value.get.return_value = "/tmp/test_dir"
        
        # Initialize components
        auth_manager = get_auth_manager()
        auth_manager._initialized = True
        
        audit_logger = get_audit_logger()
        audit_logger._initialized = True
        audit_logger.log_event = MagicMock()
        
        # Mock authentication event publishing
        with patch('skwaq.security.authentication.publish') as mock_publish:
            # Simulate a login attempt
            user = UserCredentials(
                username="test_user",
                password_hash="hash123",
                salt="salt123",
                roles={AuthRole.USER},
                user_id="user123"
            )
            auth_manager._users["test_user"] = user
            
            # Test successful authentication
            auth_manager.authenticate("test_user", "password", "192.168.1.1")
            
            # Verify event was published
            mock_publish.assert_called()
            event = mock_publish.call_args[0][0]
            assert event.action == "password_login"
            assert event.user_id == "user123"
            assert event.success is True
    
    @patch('skwaq.security.encryption.get_config')
    @patch('skwaq.security.audit.get_config')
    @patch('os.makedirs')
    def test_encryption_audit_integration(
        self, mock_makedirs, mock_audit_config, mock_encryption_config
    ):
        """Test integration between encryption and audit components."""
        # Configure mocks
        mock_encryption_config.return_value.get.return_value = "/tmp/test_dir"
        mock_audit_config.return_value.get.return_value = "/tmp/test_dir"
        
        # Initialize components
        encryption_manager = get_encryption_manager()
        encryption_manager._initialized = True
        encryption_manager._default_key = MagicMock()
        encryption_manager._default_key.key = b"thisisatestencryptionkeythatis32chars"
        
        from cryptography.fernet import Fernet
        test_fernet = Fernet(b"thisisatestencryptionkeythatis32chars")
        with patch('cryptography.fernet.Fernet', return_value=test_fernet):
            # Test encryption and decryption
            with patch('skwaq.security.audit.log_security_event') as mock_log:
                # Encrypt sensitive data
                encrypted = encrypt_sensitive_data("test_data")
                
                # Verify audit log was not called (encryption itself doesn't log)
                mock_log.assert_not_called()
                
                # Now test an operation that would log
                log_security_event(
                    event_type=AuditEventType.ENCRYPTION_KEY_ROTATED,
                    component="TestComponent",
                    message="Key rotation test",
                    level=AuditLogLevel.SECURITY
                )
                
                # Verify audit log was called
                mock_log.assert_called_once()
                assert mock_log.call_args[1]["event_type"] == AuditEventType.ENCRYPTION_KEY_ROTATED
                assert mock_log.call_args[1]["component"] == "TestComponent"
    
    @patch('skwaq.security.compliance.get_config')
    @patch('skwaq.security.vulnerability.get_config')
    @patch('os.makedirs')
    def test_compliance_vulnerability_integration(
        self, mock_makedirs, mock_vuln_config, mock_compliance_config
    ):
        """Test integration between compliance and vulnerability components."""
        # Configure mocks
        mock_compliance_config.return_value.get.return_value = "/tmp/test_dir"
        mock_vuln_config.return_value.get.return_value = "/tmp/test_dir"
        
        # Initialize components
        compliance_manager = get_compliance_manager()
        compliance_manager._initialized = True
        
        vuln_manager = get_vulnerability_manager()
        vuln_manager._initialized = True
        vuln_manager.get_findings = MagicMock(return_value=[])
        
        # Verify compliance check for vulnerability management
        requirement = compliance_manager.get_requirement("VULN-01")
        assert requirement is not None
        assert requirement.category == ComplianceCategory.VULNERABILITY_MANAGEMENT
        
        # Mock the validation function to return compliant
        with patch.dict(compliance_manager._validation_functions, 
                      {"validate_vuln_scanning": MagicMock(return_value=(True, "Compliant"))}):
            # Validate the requirement
            result, violation = compliance_manager.validate_requirement("VULN-01")
            assert result is True
            assert violation is None


class TestSecurityConfiguration:
    """Tests for security configuration integration."""
    
    @patch('skwaq.security.authentication.get_config')
    @patch('skwaq.security.authorization.get_config')
    @patch('skwaq.security.audit.get_config')
    @patch('skwaq.security.encryption.get_config')
    @patch('skwaq.security.compliance.get_config')
    @patch('skwaq.utils.config.get_config')
    @patch('os.makedirs')
    def test_security_configuration_loading(
        self, mock_makedirs, mock_global_config, mock_compliance_config, 
        mock_encryption_config, mock_audit_config, mock_auth_config,
        mock_authn_config
    ):
        """Test that security configurations are loaded correctly."""
        # Configure global config mock with security settings
        security_config = {
            "security.admin_username": "admin",
            "security.admin_password": "secure_password",
            "security.users_file": "/tmp/test_dir/users.json",
            "security.token_secret": "test_token_secret",
            "security.credentials_key": "test_credentials_key",
            "security.findings_dir": "/tmp/test_dir/findings",
            "security.nvd_api_key": "test_nvd_api_key",
            "security.password_min_length": 12,
            "security.mfa_enabled": True,
            "security.rbac_enabled": True,
            "security.last_vuln_scan": "2023-01-01T00:00:00",
            "audit.enabled": True,
            "audit.log_location": "/tmp/test_dir/audit_logs",
            "audit.encrypt_logs": True,
            "audit.retention_days": 90,
            "encryption.enabled": True,
            "encryption.default_key": "test_encryption_key",
            "encryption.confidential_key": "test_confidential_key",
            "encryption.restricted_key": "test_restricted_key",
        }
        
        # Make all config mocks return values from security_config
        def config_side_effect(key, default=None):
            return security_config.get(key, default)
        
        mock_global_config.return_value.get.side_effect = config_side_effect
        mock_authn_config.return_value.get.side_effect = config_side_effect
        mock_auth_config.return_value.get.side_effect = config_side_effect
        mock_audit_config.return_value.get.side_effect = config_side_effect
        mock_encryption_config.return_value.get.side_effect = config_side_effect
        mock_compliance_config.return_value.get.side_effect = config_side_effect
        
        # Test compliance validation with the config
        compliance_manager = get_compliance_manager()
        compliance_manager._initialized = True
        
        # Call the validation functions directly
        password_complexity_validator = compliance_manager._validation_functions["validate_password_complexity"]
        mfa_validator = compliance_manager._validation_functions["validate_mfa_availability"]
        encryption_validator = compliance_manager._validation_functions["validate_encryption_at_rest"]
        security_logging_validator = compliance_manager._validation_functions["validate_security_logging"]
        rbac_validator = compliance_manager._validation_functions["validate_rbac"]
        
        # Check results
        assert password_complexity_validator({"min_length": 8})[0] is True
        assert mfa_validator({})[0] is True
        assert encryption_validator({})[0] is True
        assert security_logging_validator({})[0] is True
        assert rbac_validator({})[0] is True


@patch('skwaq.security.sandbox.subprocess.run')
@patch('skwaq.security.sandbox.os.makedirs')
class TestSandboxIntegration:
    """Tests for sandbox integration with other security components."""
    
    @patch('skwaq.security.audit.get_config')
    def test_sandbox_audit_integration(
        self, mock_audit_config, mock_makedirs, mock_subprocess_run
    ):
        """Test integration between sandbox and audit components."""
        # Configure mocks
        mock_audit_config.return_value.get.return_value = "/tmp/test_dir"
        mock_subprocess_run.return_value.returncode = 0
        mock_subprocess_run.return_value.stdout = "stdout_test"
        mock_subprocess_run.return_value.stderr = "stderr_test"
        
        # Create a sandbox
        with patch('skwaq.security.sandbox.log_security_event') as mock_log:
            # Initialize a sandbox
            sandbox = create_sandbox(
                isolation_level=SandboxIsolationLevel.BASIC,
                name="test_sandbox"
            )
            
            # Verify audit log was called for initialization
            mock_log.assert_called_once()
            assert mock_log.call_args[1]["event_type"] == AuditEventType.COMPONENT_INITIALIZED
            assert "test_sandbox" in mock_log.call_args[1]["component"]
            
            # Reset mock
            mock_log.reset_mock()
            
            # Execute a command in the sandbox
            with patch('subprocess.Popen') as mock_popen:
                # Configure mock for Popen
                mock_process = MagicMock()
                mock_process.returncode = 0
                mock_process.communicate.return_value = ("test output", "test error")
                mock_process.pid = 12345
                mock_popen.return_value = mock_process
                
                # Execute command
                result = sandbox.execute_command(["echo", "test"])
                
                # Verify audit log was called for command execution
                mock_log.assert_called_once()
                assert mock_log.call_args[1]["event_type"] == AuditEventType.TOOL_EXECUTED
                assert "test_sandbox" in mock_log.call_args[1]["component"]
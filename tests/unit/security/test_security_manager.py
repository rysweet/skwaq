"""Unit tests for skwaq.security.integration module."""

import os
import pytest
from unittest.mock import MagicMock, patch, mock_open

from skwaq.security.integration import (
    SecurityManager, SecurityContext, SecurityConfigurationError,
    SecurityOperationError, secure_operation, get_security_manager
)
from skwaq.security.authorization import Permission


@patch('skwaq.security.integration.get_config')
@patch('skwaq.security.integration.get_auth_manager')
@patch('skwaq.security.integration.get_authorization')
@patch('skwaq.security.integration.get_audit_logger')
@patch('skwaq.security.integration.get_encryption_manager')
@patch('skwaq.security.integration.get_compliance_manager')
@patch('skwaq.security.integration.get_vulnerability_manager')
@patch('skwaq.security.integration.subscribe')
@patch('skwaq.security.integration.log_security_event')
class TestSecurityManager:
    """Tests for the SecurityManager class."""
    
    def setup_method(self):
        """Set up test fixtures before each test."""
        # Reset singleton instance
        SecurityManager._instance = None
        
        # Clear security context
        SecurityContext.clear()
    
    def test_singleton_pattern(
        self, mock_log, mock_subscribe, mock_vuln, mock_compliance, 
        mock_encryption, mock_audit, mock_auth, mock_authn, mock_config
    ):
        """Test the singleton pattern implementation."""
        # Create two instances
        manager1 = SecurityManager()
        manager2 = SecurityManager()
        
        # Verify they are the same instance
        assert manager1 is manager2
    
    def test_init(
        self, mock_log, mock_subscribe, mock_vuln, mock_compliance, 
        mock_encryption, mock_audit, mock_auth, mock_authn, mock_config
    ):
        """Test initialization."""
        manager = SecurityManager()
        
        assert manager._initialized is True
        
        # Verify components were initialized
        mock_authn.assert_called_once()
        mock_auth.assert_called_once()
        mock_audit.assert_called_once()
        mock_encryption.assert_called_once()
        mock_compliance.assert_called_once()
        mock_vuln.assert_called_once()
        
        # Verify event subscription
        mock_subscribe.assert_called_once()
        
        # Verify log event
        mock_log.assert_called_once()
    
    def test_verify_security_configuration(
        self, mock_log, mock_subscribe, mock_vuln, mock_compliance, 
        mock_encryption, mock_audit, mock_auth, mock_authn, mock_config
    ):
        """Test security configuration verification."""
        # Configure mock to return security settings
        mock_config.return_value.get.side_effect = lambda key, default=None: {
            "encryption.default_key": "test_key",
            "audit.enabled": True,
            "security.admin_username": "admin",
            "security.password_min_length": 12,
            "security.mfa_enabled": True,
        }.get(key, default)
        
        # Initialize security manager
        manager = SecurityManager()
        
        # Call verification method explicitly
        manager._verify_security_configuration()
        
        # Test with insecure configuration
        mock_config.return_value.get.side_effect = lambda key, default=None: {
            "encryption.default_key": None,
            "audit.enabled": False,
            "security.admin_username": None,
            "security.password_min_length": 8,
            "security.mfa_enabled": False,
        }.get(key, default)
        
        # This should log warnings but not raise exceptions
        manager._verify_security_configuration()
    
    def test_process_login(
        self, mock_log, mock_subscribe, mock_vuln, mock_compliance, 
        mock_encryption, mock_audit, mock_auth, mock_authn, mock_config
    ):
        """Test login processing."""
        # Set up mock authentication manager
        mock_user = MagicMock()
        mock_user.username = "test_user"
        mock_user.user_id = "user123"
        
        mock_authn.return_value.authenticate.return_value = mock_user
        mock_authn.return_value.generate_token.return_value = "test_token"
        
        # Initialize security manager
        manager = SecurityManager()
        
        # Process login
        user = manager.process_login("test_user", "password", "192.168.1.1", "session123")
        
        # Verify results
        assert user is mock_user
        mock_authn.return_value.authenticate.assert_called_once_with(
            "test_user", "password", "192.168.1.1"
        )
        mock_authn.return_value.generate_token.assert_called_once_with(mock_user)
        
        # Verify security context was set
        assert SecurityContext.get_current_user() is mock_user
        assert SecurityContext.get_current_source_ip() == "192.168.1.1"
        assert SecurityContext.get_current_session_id() == "session123"
        
        # Test failed login
        mock_authn.return_value.authenticate.return_value = None
        
        user = manager.process_login("test_user", "wrong_password", "192.168.1.1")
        
        assert user is None
    
    def test_process_token_login(
        self, mock_log, mock_subscribe, mock_vuln, mock_compliance, 
        mock_encryption, mock_audit, mock_auth, mock_authn, mock_config
    ):
        """Test token login processing."""
        # Set up mock authentication manager
        token_payload = {
            "sub": "user123",
            "username": "test_user",
            "roles": ["user", "admin"],
            "exp": 1893456000,  # Future timestamp
        }
        mock_authn.return_value.validate_token.return_value = token_payload
        
        # Initialize security manager
        manager = SecurityManager()
        
        # Process token login
        payload = manager.process_token_login("test_token", "192.168.1.1", "session123")
        
        # Verify results
        assert payload is token_payload
        mock_authn.return_value.validate_token.assert_called_once_with("test_token")
        
        # Verify security context was set
        user = SecurityContext.get_current_user()
        assert user is not None
        assert user.username == "test_user"
        assert user.user_id == "user123"
        assert len(user.roles) == 2
        assert SecurityContext.get_current_source_ip() == "192.168.1.1"
        assert SecurityContext.get_current_session_id() == "session123"
        
        # Verify log was called
        mock_log.assert_called_with(
            event_type=mock_log.call_args[1]["event_type"],
            component="SecurityManager",
            message="Token login for user test_user",
            user_id="user123",
            details={"source_ip": "192.168.1.1"},
            level=mock_log.call_args[1]["level"],
        )
        
        # Test invalid token
        mock_authn.return_value.validate_token.return_value = None
        
        payload = manager.process_token_login("invalid_token")
        
        assert payload is None
    
    def test_logout(
        self, mock_log, mock_subscribe, mock_vuln, mock_compliance, 
        mock_encryption, mock_audit, mock_auth, mock_authn, mock_config
    ):
        """Test logout."""
        # Set up mock user in security context
        mock_user = MagicMock()
        mock_user.username = "test_user"
        mock_user.user_id = "user123"
        SecurityContext.set_current_user(mock_user)
        
        # Initialize security manager
        manager = SecurityManager()
        
        # Logout
        result = manager.logout("test_token")
        
        # Verify results
        assert result is True
        mock_authn.return_value.revoke_token.assert_called_once_with("test_token")
        
        # Verify security context was cleared
        assert SecurityContext.get_current_user() is None
        assert SecurityContext.get_current_source_ip() is None
        assert SecurityContext.get_current_session_id() is None
        
        # Verify log was called
        mock_log.assert_called_with(
            event_type=mock_log.call_args[1]["event_type"],
            component="SecurityManager",
            message="User test_user logged out",
            user_id="user123",
            level=mock_log.call_args[1]["level"],
        )
    
    def test_check_permission(
        self, mock_log, mock_subscribe, mock_vuln, mock_compliance, 
        mock_encryption, mock_audit, mock_auth, mock_authn, mock_config
    ):
        """Test permission checking."""
        # Set up mock user in security context
        mock_user = MagicMock()
        mock_user.username = "test_user"
        mock_user.user_id = "user123"
        SecurityContext.set_current_user(mock_user)
        
        # Set up mock authorization
        mock_auth.return_value.has_permission.return_value = True
        
        # Initialize security manager
        manager = SecurityManager()
        
        # Check permission
        result = manager.check_permission(Permission.VIEW_REPOSITORY, "repo123")
        
        # Verify results
        assert result is True
        mock_auth.return_value.has_permission.assert_called_once_with(
            mock_user, Permission.VIEW_REPOSITORY, "repo123"
        )
        
        # Test without user in context
        SecurityContext.clear()
        
        result = manager.check_permission(Permission.VIEW_REPOSITORY)
        
        assert result is False
    
    def test_run_compliance_assessment(
        self, mock_log, mock_subscribe, mock_vuln, mock_compliance, 
        mock_encryption, mock_audit, mock_auth, mock_authn, mock_config
    ):
        """Test compliance assessment."""
        # Set up mock compliance manager
        mock_results = {
            "SEC-01": (True, None),
            "SEC-02": (False, MagicMock()),
        }
        mock_compliance.return_value.validate_all_requirements.return_value = mock_results
        
        # Initialize security manager
        manager = SecurityManager()
        
        # Run compliance assessment
        results = manager.run_compliance_assessment()
        
        # Verify results
        assert results == mock_results
        mock_compliance.return_value.validate_all_requirements.assert_called_once_with(
            standard=None, category=None
        )
        
        # Verify log was called
        assert mock_log.call_count >= 2  # Initialization + assessment
    
    def test_encrypt_decrypt_credentials(
        self, mock_log, mock_subscribe, mock_vuln, mock_compliance, 
        mock_encryption, mock_audit, mock_auth, mock_authn, mock_config
    ):
        """Test credential encryption and decryption."""
        # Set up mock encryption manager
        mock_encryption.return_value.encrypt_dict.return_value = "encrypted"
        mock_encryption.return_value.decrypt_dict.return_value = {"key": "value"}
        
        # Initialize security manager
        manager = SecurityManager()
        
        # Encrypt credentials
        encrypted = manager.encrypt_credentials({"key": "value"})
        
        # Verify results
        assert encrypted == "encrypted"
        
        # Decrypt credentials
        decrypted = manager.decrypt_credentials("encrypted")
        
        # Verify results
        assert decrypted == {"key": "value"}
    
    def test_report_security_finding(
        self, mock_log, mock_subscribe, mock_vuln, mock_compliance, 
        mock_encryption, mock_audit, mock_auth, mock_authn, mock_config
    ):
        """Test security finding reporting."""
        from skwaq.security.vulnerability import VulnerabilityType, VulnerabilitySeverity
        
        # Set up mock add_vulnerability
        with patch('skwaq.security.integration.add_vulnerability') as mock_add:
            mock_add.return_value = "finding123"
            
            # Initialize security manager
            manager = SecurityManager()
            
            # Report a finding
            finding_id = manager.report_security_finding(
                title="Test Finding",
                description="Test description",
                vulnerability_type=VulnerabilityType.XSS,
                severity=VulnerabilitySeverity.HIGH,
                evidence="<script>alert(1)</script>",
                remediation="Sanitize input",
                cwe_id="CWE-79"
            )
            
            # Verify results
            assert finding_id == "finding123"
            mock_add.assert_called_once_with(
                title="Test Finding",
                description="Test description",
                vulnerability_type=VulnerabilityType.XSS,
                severity=VulnerabilitySeverity.HIGH,
                evidence="<script>alert(1)</script>",
                remediation="Sanitize input",
                cwe_id="CWE-79"
            )
            
            # Verify log was called
            mock_log.assert_called_with(
                event_type=mock_log.call_args[1]["event_type"],
                component="SecurityManager",
                message="Security finding reported: Test Finding",
                details={
                    "finding_id": "finding123",
                    "vulnerability_type": "xss",
                    "severity": "high",
                },
                level=mock_log.call_args[1]["level"],
            )
    
    def test_execute_in_sandbox(
        self, mock_log, mock_subscribe, mock_vuln, mock_compliance, 
        mock_encryption, mock_audit, mock_auth, mock_authn, mock_config
    ):
        """Test sandbox execution."""
        # Set up mock config
        mock_config.return_value.get.side_effect = lambda key, default=None: {
            "sandbox.default_isolation": "basic",
            "sandbox.memory_limit_mb": 256,
            "sandbox.cpu_time_limit_sec": 15,
            "sandbox.wall_time_limit_sec": 30,
            "sandbox.disk_space_limit_mb": 50,
            "sandbox.allow_network": False,
            "sandbox.process_limit": 5,
            "sandbox.file_size_limit_mb": 5,
        }.get(key, default)
        
        # Set up mock user in security context
        mock_user = MagicMock()
        mock_user.username = "test_user"
        mock_user.user_id = "user123"
        SecurityContext.set_current_user(mock_user)
        
        # Set up mock execute_in_sandbox
        with patch('skwaq.security.integration.execute_in_sandbox') as mock_execute:
            mock_result = MagicMock()
            mock_result.to_dict.return_value = {
                "success": True,
                "stdout": "test output",
                "stderr": "",
                "return_code": 0,
            }
            mock_execute.return_value = mock_result
            
            # Initialize security manager
            manager = SecurityManager()
            
            # Execute in sandbox
            with patch('skwaq.security.integration.is_container_available', return_value=False):
                result = manager.execute_in_sandbox(
                    command=["echo", "test"],
                    files={"test.txt": "content"}
                )
                
                # Verify results
                assert result == {
                    "success": True,
                    "stdout": "test output",
                    "stderr": "",
                    "return_code": 0,
                }
                
                # Verify execute_in_sandbox was called
                mock_execute.assert_called_once()
                
                # Verify log was called
                mock_log.assert_called_with(
                    event_type=mock_log.call_args[1]["event_type"],
                    component="SecurityManager",
                    message="Executing command in sandbox: echo test",
                    user_id="user123",
                    details={
                        "command": ["echo", "test"],
                        "isolation_level": "basic",
                    },
                    level=mock_log.call_args[1]["level"],
                )


class TestSecurityContext:
    """Tests for the SecurityContext class."""
    
    def setup_method(self):
        """Set up test fixtures before each test."""
        # Clear security context
        SecurityContext.clear()
    
    def test_user_context(self):
        """Test user context management."""
        # Initially should be None
        assert SecurityContext.get_current_user() is None
        
        # Set a user
        mock_user = MagicMock()
        SecurityContext.set_current_user(mock_user)
        
        # Should return the user
        assert SecurityContext.get_current_user() is mock_user
        
        # Clear and verify
        SecurityContext.clear()
        assert SecurityContext.get_current_user() is None
    
    def test_session_context(self):
        """Test session context management."""
        # Initially should be None
        assert SecurityContext.get_current_session_id() is None
        
        # Set a session ID
        SecurityContext.set_current_session_id("session123")
        
        # Should return the session ID
        assert SecurityContext.get_current_session_id() == "session123"
        
        # Clear and verify
        SecurityContext.clear()
        assert SecurityContext.get_current_session_id() is None
    
    def test_source_ip_context(self):
        """Test source IP context management."""
        # Initially should be None
        assert SecurityContext.get_current_source_ip() is None
        
        # Set a source IP
        SecurityContext.set_current_source_ip("192.168.1.1")
        
        # Should return the source IP
        assert SecurityContext.get_current_source_ip() == "192.168.1.1"
        
        # Clear and verify
        SecurityContext.clear()
        assert SecurityContext.get_current_source_ip() is None


@patch('skwaq.security.integration.get_security_manager')
class TestSecureOperation:
    """Tests for the secure_operation decorator."""
    
    def setup_method(self):
        """Set up test fixtures before each test."""
        # Clear security context
        SecurityContext.clear()
    
    def test_secure_operation_success(self, mock_get_manager):
        """Test successful secure operation."""
        # Set up mocks
        mock_manager = MagicMock()
        mock_manager.check_permission.return_value = True
        mock_get_manager.return_value = mock_manager
        
        # Set up mock user in security context
        mock_user = MagicMock()
        mock_user.username = "test_user"
        mock_user.user_id = "user123"
        SecurityContext.set_current_user(mock_user)
        
        # Create a decorated function
        @secure_operation(Permission.VIEW_REPOSITORY, "repo_id")
        def test_function(repo_id: str, other_arg: str = "default") -> str:
            return f"Success: {repo_id}, {other_arg}"
        
        # Call the function
        result = test_function(repo_id="repo123", other_arg="test")
        
        # Verify results
        assert result == "Success: repo123, test"
        mock_manager.check_permission.assert_called_once_with(
            Permission.VIEW_REPOSITORY, "repo123"
        )
    
    def test_secure_operation_no_user(self, mock_get_manager):
        """Test secure operation with no user."""
        # Set up mocks
        mock_manager = MagicMock()
        mock_get_manager.return_value = mock_manager
        
        # Create a decorated function
        @secure_operation(Permission.VIEW_REPOSITORY)
        def test_function() -> str:
            return "Success"
        
        # Call the function - should raise an exception
        with pytest.raises(SecurityOperationError) as excinfo:
            test_function()
        
        assert "No authenticated user" in str(excinfo.value)
    
    def test_secure_operation_permission_denied(self, mock_get_manager):
        """Test secure operation with permission denied."""
        # Set up mocks
        mock_manager = MagicMock()
        mock_manager.check_permission.return_value = False
        mock_get_manager.return_value = mock_manager
        
        # Set up mock user in security context
        mock_user = MagicMock()
        mock_user.username = "test_user"
        mock_user.user_id = "user123"
        SecurityContext.set_current_user(mock_user)
        
        # Create a decorated function
        @secure_operation(Permission.ADMIN)
        def test_function() -> str:
            return "Success"
        
        # Call the function - should raise an exception
        with pytest.raises(SecurityOperationError) as excinfo:
            test_function()
        
        assert "Permission denied" in str(excinfo.value)
        mock_manager.check_permission.assert_called_once_with(
            Permission.ADMIN, None
        )
    
    def test_secure_operation_with_exception(self, mock_get_manager):
        """Test secure operation that raises an exception."""
        # Set up mocks
        mock_manager = MagicMock()
        mock_manager.check_permission.return_value = True
        mock_get_manager.return_value = mock_manager
        
        # Set up mock user in security context
        mock_user = MagicMock()
        mock_user.username = "test_user"
        mock_user.user_id = "user123"
        SecurityContext.set_current_user(mock_user)
        
        # Create a decorated function
        @secure_operation(Permission.VIEW_REPOSITORY)
        def test_function() -> str:
            raise ValueError("Test error")
        
        # Call the function - should raise the original exception
        with pytest.raises(ValueError) as excinfo:
            test_function()
        
        assert "Test error" in str(excinfo.value)
        mock_manager.check_permission.assert_called_once_with(
            Permission.VIEW_REPOSITORY, None
        )


@patch('skwaq.security.integration.SecurityManager')
def test_get_security_manager(mock_manager_class):
    """Test the get_security_manager function."""
    # Set up the mock
    mock_instance = MagicMock()
    mock_manager_class.return_value = mock_instance
    
    # Call the function
    manager = get_security_manager()
    
    # Verify the result
    assert manager == mock_instance
    mock_manager_class.assert_called_once()
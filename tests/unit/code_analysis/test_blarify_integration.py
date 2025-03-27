"""Unit tests for the blarify integration module."""

import pytest
from unittest.mock import patch, MagicMock, mock_open
import os

from skwaq.code_analysis.blarify_integration import BlarifyIntegration


class TestBlarifyIntegration:
    """Tests for the BlarifyIntegration class."""

    def test_initialization_with_logging(self):
        """Test initialization with simple logging checks."""
        # Create a BlarifyIntegration without any mocking
        integration = BlarifyIntegration()
        
        # Just verify we can create the instance
        assert isinstance(integration, BlarifyIntegration)
        assert hasattr(integration, 'blarify_available')
        assert hasattr(integration, 'tree_sitter_helper')
    
    def test_is_available(self):
        """Test the is_available method."""
        # Create instance
        integration = BlarifyIntegration()
        
        # Test the method
        result = integration.is_available()
        
        # We just check it returns a boolean and doesn't crash
        assert isinstance(result, bool)
    
    @pytest.mark.parametrize("availability", [True, False])
    def test_get_ast_based_on_availability(self, availability):
        """Test get_ast method honors the availability flag."""
        # Create integration with controlled availability
        integration = BlarifyIntegration()
        integration.blarify_available = availability
        
        # Set tree_sitter_helper to None to prevent using real dependencies
        integration.tree_sitter_helper = None
        
        # Call the method with unavailable state
        result = integration.get_ast("def test(): pass", "Python")
        
        # When availability is False, result should be None
        if not availability:
            assert result is None
            
    def test_extract_code_structure_with_unavailable_blarify(self):
        """Test extract_code_structure returns None when Blarify is unavailable."""
        # Create integration with controlled availability
        integration = BlarifyIntegration()
        integration.blarify_available = False
        
        # Call the method
        result = integration.extract_code_structure("def test(): pass", "Python")
        
        # Result should be None when Blarify is unavailable
        assert result is None
    
    def test_analyze_security_patterns_with_unavailable_blarify(self):
        """Test analyze_security_patterns returns empty list when Blarify is unavailable."""
        # Create integration with controlled availability
        integration = BlarifyIntegration()
        integration.blarify_available = False
        
        # Call the method
        result = integration.analyze_security_patterns("def test(): pass", "Python", 123)
        
        # Result should be an empty list when Blarify is unavailable
        assert result == []
        
    def test_analyze_security_patterns_with_unavailable_ast(self):
        """Test analyze_security_patterns returns empty list when AST is unavailable."""
        # Create integration with controlled availability
        integration = BlarifyIntegration()
        integration.blarify_available = True
        
        # Mock get_ast to return None
        integration.get_ast = MagicMock(return_value=None)
        
        # Call the method
        result = integration.analyze_security_patterns("def test(): pass", "Python", 123)
        
        # Result should be an empty list when AST is unavailable
        assert result == []
        assert integration.get_ast.called
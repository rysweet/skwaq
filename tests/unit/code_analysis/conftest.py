"""Pytest fixtures specific to code analysis tests."""

import pytest
from unittest.mock import MagicMock, AsyncMock, patch
from dataclasses import dataclass
from typing import Dict, List, Optional, Any


@pytest.fixture
def mock_strategy():
    """Mock analysis strategy."""
    strategy = MagicMock()
    strategy.analyze = AsyncMock(return_value=[])
    strategy.get_name.return_value = "mock_strategy"
    return strategy


@pytest.fixture
def mock_language_analyzer():
    """Mock language analyzer."""
    analyzer = MagicMock()
    analyzer.get_language_name.return_value = "MockLanguage"
    analyzer.parse_code.return_value = {"ast": {}, "tokens": []}
    return analyzer
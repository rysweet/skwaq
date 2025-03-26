"""Test configuration for ingestion tests."""

import pytest


def pytest_configure(config):
    """Register custom markers."""
    config.addinivalue_line("markers", "focus: mark tests to run in isolation")
    config.addinivalue_line("markers", "isolated: mark tests that should only run in isolation")
"""Test the logging module."""

import logging
import tempfile
from pathlib import Path
from unittest import mock

import pytest

from skwaq.utils.logging import (
    LOG_FORMAT,
    get_logger,
    setup_logging,
)


def test_setup_logging():
    """Test setting up a logger with various configurations."""
    # Test with default parameters
    logger = setup_logging()
    assert logger.name == "skwaq"
    assert logger.level == logging.INFO
    assert len(logger.handlers) >= 2  # Console and file handler

    # Verify console handler setup
    console_handler = [
        h
        for h in logger.handlers
        if isinstance(h, logging.StreamHandler) and h.stream.name == "<stdout>"
    ][0]
    assert console_handler.level == logging.INFO
    assert console_handler.formatter._fmt == LOG_FORMAT

    # Verify we have a file handler
    file_handlers = [h for h in logger.handlers if isinstance(h, logging.FileHandler)]
    assert len(file_handlers) >= 1

    # Test with custom log level
    debug_logger = setup_logging(level=logging.DEBUG)
    assert debug_logger.level == logging.DEBUG

    # Test with custom module name
    custom_logger = setup_logging(module_name="custom_module")
    assert custom_logger.name == "custom_module"

    # Test with custom log file
    with tempfile.NamedTemporaryFile() as tmp:
        log_path = Path(tmp.name)
        file_logger = setup_logging(log_file=log_path)
        file_handler = [h for h in file_logger.handlers if isinstance(h, logging.FileHandler)][0]
        assert str(file_handler.baseFilename) == str(log_path)


def test_get_logger():
    """Test the global logger getter."""
    # Mock setup_logging to verify it's called correctly
    with mock.patch("skwaq.utils.logging.setup_logging") as mock_setup:
        mock_logger = mock.MagicMock()
        mock_setup.return_value = mock_logger

        # First call should create a new logger
        logger1 = get_logger()
        mock_setup.assert_called_once_with(module_name="skwaq")

        # Second call should return the same logger
        logger2 = get_logger()
        assert logger1 is logger2
        assert mock_setup.call_count == 1

        # Call with a different module name should use that name
        logger3 = get_logger("custom_module")
        assert logger1 is logger3  # In our mock setup, we're returning the same mock object
        assert mock_setup.call_count == 1  # Should not call setup_logging again

        # Reset global state for other tests
        import skwaq.utils.logging

        skwaq.utils.logging._logger = None

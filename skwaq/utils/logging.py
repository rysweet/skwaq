"""Logging functionality for Skwaq.

This module provides standardized logging functionality for the Skwaq
vulnerability assessment copilot.
"""

import logging
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional, Union

# Configure logging format
LOG_FORMAT = "[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s"
LOG_DATEFMT = "%Y-%m-%d %H:%M:%S"

# Global logger instance
_logger: Optional[logging.Logger] = None


def setup_logging(
    level: int = logging.INFO,
    module_name: str = "skwaq",
    log_file: Optional[Union[str, Path]] = None,
    log_to_console: bool = True,
) -> logging.Logger:
    """Set up logging with consistent formatting.

    Args:
        level: The logging level (default: INFO)
        module_name: Name of the module/application (default: skwaq)
        log_file: Path to log file (default: skwaq_{timestamp}.log)
        log_to_console: Whether to log to console (default: True)

    Returns:
        Configured logger instance
    """
    # Create or get logger
    logger = logging.getLogger(module_name)
    logger.setLevel(level)
    logger.handlers = []  # Remove existing handlers

    # Create formatter
    formatter = logging.Formatter(LOG_FORMAT, datefmt=LOG_DATEFMT)

    # Add console handler if requested
    if log_to_console:
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(level)
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)

    # Add file handler if requested or use default
    if log_file is None:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        log_dir = Path(os.getenv("SKWAQ_LOG_DIR", Path.home() / ".skwaq" / "logs"))
        log_dir.mkdir(parents=True, exist_ok=True)
        log_file = log_dir / f"skwaq_{timestamp}.log"

    file_handler = logging.FileHandler(log_file)
    file_handler.setLevel(level)
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

    return logger


def get_logger(module_name: str = "skwaq") -> logging.Logger:
    """Get the global logger instance.

    Args:
        module_name: Name to use for the logger (default: skwaq)

    Returns:
        The global logger instance
    """
    global _logger
    if _logger is None:
        _logger = setup_logging(module_name=module_name)
    return _logger

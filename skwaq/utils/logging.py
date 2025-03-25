"""Logging utilities for the Skwaq vulnerability assessment copilot.

This module provides a standardized logging setup for the Skwaq system.
"""
import logging
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional

# Log format with timestamp, level, and message
LOG_FORMAT = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"

# Default log directory
LOG_DIR = Path("logs")


def setup_logging(
    level: int = logging.INFO,
    log_file: Optional[Path] = None,
    module_name: str = "skwaq",
) -> logging.Logger:
    """Set up logging for the application.
    
    Args:
        level: The logging level (default: INFO)
        log_file: Optional path to a log file. If not provided, a default
                  log file will be created in the logs directory with a
                  timestamp.
        module_name: The name of the module to create a logger for
        
    Returns:
        A configured logger instance
    """
    # Create the logger
    logger = logging.getLogger(module_name)
    logger.setLevel(level)
    
    # Remove any existing handlers to avoid duplicates
    for handler in logger.handlers[:]:
        logger.removeHandler(handler)
    
    # Create a handler for console output
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(level)
    console_handler.setFormatter(logging.Formatter(LOG_FORMAT))
    logger.addHandler(console_handler)
    
    # Create a file handler if requested or by default
    if log_file is not None or True:  # Always create a log file
        # If log_file is not specified, create a default one
        if log_file is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            # Ensure log directory exists
            os.makedirs(LOG_DIR, exist_ok=True)
            log_file = LOG_DIR / f"skwaq_{timestamp}.log"
        
        # Create file handler
        try:
            file_handler = logging.FileHandler(log_file)
            file_handler.setLevel(level)
            file_handler.setFormatter(logging.Formatter(LOG_FORMAT))
            logger.addHandler(file_handler)
        except IOError as e:
            # Fall back to just console logging if file creation fails
            logger.error(f"Failed to create log file {log_file}: {e}")
    
    # Add a note about the logger being initialized
    logger.info(f"Logging initialized for {module_name} at level {logging.getLevelName(level)}")
    if log_file:
        logger.info(f"Log file: {log_file}")
    
    return logger


# Global logger instance
_logger: Optional[logging.Logger] = None


def get_logger(module_name: str = "skwaq") -> logging.Logger:
    """Get the global logger instance.
    
    Args:
        module_name: The name of the module to get a logger for
        
    Returns:
        The configured logger instance
    """
    global _logger
    if _logger is None:
        _logger = setup_logging(module_name=module_name)
    return _logger
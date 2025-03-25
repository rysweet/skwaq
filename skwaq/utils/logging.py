"""Logging functionality for Skwaq.

This module provides standardized logging functionality for the Skwaq
vulnerability assessment copilot, including structured logging, log rotation,
and context-aware logging.
"""

import json
import logging
import os
import sys
import threading
from datetime import datetime
from logging.handlers import RotatingFileHandler, TimedRotatingFileHandler
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Type, Union, cast

try:
    from skwaq.events.system_events import LoggingEvent, publish

    HAS_EVENTS = True
except ImportError:
    HAS_EVENTS = False

# Configure logging format
DEFAULT_FORMAT = "[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s"
STRUCTURED_FORMAT = "%(message)s"
LOG_DATEFMT = "%Y-%m-%d %H:%M:%S"

# Global logger instances
_loggers: Dict[str, logging.Logger] = {}
_logger_lock = threading.RLock()

# Logging levels with names
LEVELS = {
    "DEBUG": logging.DEBUG,
    "INFO": logging.INFO,
    "WARNING": logging.WARNING,
    "ERROR": logging.ERROR,
    "CRITICAL": logging.CRITICAL,
}


class StructuredLogRecord(logging.LogRecord):
    """LogRecord that formats message as JSON when context is provided."""

    def getMessage(self) -> str:
        """Get the message with context as JSON if context is present.

        Returns:
            Formatted message string
        """
        if hasattr(self, "context") and self.context:
            record_data = {
                "timestamp": datetime.utcfromtimestamp(self.created).isoformat(),
                "level": self.levelname,
                "logger": self.name,
                "message": super().getMessage(),
                "context": self.context,
            }

            if hasattr(self, "event_id"):
                record_data["event_id"] = self.event_id

            return json.dumps(record_data)

        return super().getMessage()


class ContextAdapter(logging.LoggerAdapter):
    """Adapter that adds context to log messages."""

    def __init__(self, logger: logging.Logger, context: Dict[str, Any]):
        """Initialize logger adapter with context.

        Args:
            logger: The logger to adapt
            context: Context to add to log messages
        """
        super().__init__(logger, context)

    def process(self, msg, kwargs):
        """Process log message to add context.

        Args:
            msg: Log message
            kwargs: Additional keyword arguments

        Returns:
            Tuple of (message, keyword arguments)
        """
        if "extra" not in kwargs:
            kwargs["extra"] = {}

        if "context" not in kwargs["extra"]:
            kwargs["extra"]["context"] = {}

        # Merge context from adapter with any provided in the log call
        for key, value in self.extra.items():
            if key not in kwargs["extra"]["context"]:
                kwargs["extra"]["context"][key] = value

        return msg, kwargs

    def with_context(self, **context) -> "ContextAdapter":
        """Create a new adapter with additional context.

        Args:
            **context: Context items to add

        Returns:
            New context adapter with merged context
        """
        # Merge existing context with new context
        new_context = dict(self.extra)
        new_context.update(context)

        return ContextAdapter(self.logger, new_context)


class SkwaqLogger(logging.Logger):
    """Extended logger with additional functionality."""

    def makeRecord(
        self,
        name: str,
        level: int,
        fn: str,
        lno: int,
        msg: object,
        args: Any,
        exc_info: Any,
        func: Optional[str] = None,
        extra: Optional[Dict[str, Any]] = None,
        sinfo: Optional[str] = None,
    ) -> logging.LogRecord:
        """Create a log record with support for structured data.

        Args:
            name: Logger name
            level: Log level
            fn: Filename where log was called
            lno: Line number
            msg: Log message
            args: Message formatting arguments
            exc_info: Exception info
            func: Function name
            extra: Extra context for the log
            sinfo: Stack info

        Returns:
            Log record
        """
        record = StructuredLogRecord(name, level, fn, lno, msg, args, exc_info, func, sinfo)

        if extra is not None:
            for key, value in extra.items():
                setattr(record, key, value)

        return record

    def with_context(self, **context) -> ContextAdapter:
        """Create a context adapter for this logger.

        Args:
            **context: Context items

        Returns:
            Context adapter with the specified context
        """
        return ContextAdapter(self, context)


# Register the custom logger class
logging.setLoggerClass(SkwaqLogger)


class RotationConfig:
    """Configuration for log rotation."""

    def __init__(
        self,
        rotation_type: str = "size",
        max_bytes: int = 10 * 1024 * 1024,  # 10 MB
        backup_count: int = 5,
        when: str = "midnight",
        interval: int = 1,
    ):
        """Initialize rotation configuration.

        Args:
            rotation_type: "size" or "time"
            max_bytes: Maximum log file size for size-based rotation
            backup_count: Number of backup files to keep
            when: Rotation time interval type (midnight, h, d, w0-w6)
            interval: Number of units between rotations
        """
        self.rotation_type = rotation_type
        self.max_bytes = max_bytes
        self.backup_count = backup_count
        self.when = when
        self.interval = interval


def setup_logging(
    level: Union[int, str] = logging.INFO,
    module_name: str = "skwaq",
    log_file: Optional[Union[str, Path]] = None,
    log_to_console: bool = True,
    structured: bool = False,
    rotation: Optional[RotationConfig] = None,
    testing: bool = False,
) -> Union[logging.Logger, ContextAdapter]:
    """Set up logging with consistent formatting.

    Args:
        level: The logging level (default: INFO)
        module_name: Name of the module/application (default: skwaq)
        log_file: Path to log file (default: skwaq_{timestamp}.log)
        log_to_console: Whether to log to console (default: True)
        structured: Whether to use structured JSON logging
        rotation: Log rotation configuration
        testing: Whether this is being run in a test environment

    Returns:
        Configured logger instance or context adapter
    """
    global _loggers

    # Convert string level to int if needed
    if isinstance(level, str):
        level = LEVELS.get(level.upper(), logging.INFO)

    with _logger_lock:
        # Check if logger already exists
        if module_name in _loggers:
            # Only update level for existing logger
            _loggers[module_name].setLevel(level)
            return _loggers[module_name]

        # Create or get logger
        logger = cast(SkwaqLogger, logging.getLogger(module_name))
        logger.setLevel(level)
        logger.handlers = []  # Remove existing handlers

        # Create formatter
        if structured:
            formatter = logging.Formatter(STRUCTURED_FORMAT)
        else:
            formatter = logging.Formatter(DEFAULT_FORMAT, datefmt=LOG_DATEFMT)

        # Add handlers based on testing mode
        if testing:
            # For testing, use StringIO for both console and file output
            from io import StringIO
            
            # Console output (always enabled in testing)
            console_stream = StringIO()
            console_handler = logging.StreamHandler(console_stream)
            console_handler.setLevel(level)
            console_handler.setFormatter(formatter)
            console_handler.stream = console_stream  # Make stream accessible
            logger.addHandler(console_handler)
            
            # File output (if requested)
            if log_file:
                file_stream = StringIO()
                file_handler = logging.StreamHandler(file_stream)
                file_handler.setLevel(level)
                file_handler.setFormatter(formatter)
                file_handler.stream = file_stream  # Make stream accessible
                # Store the path for reference
                setattr(file_handler, 'log_file_path', log_file)
                logger.addHandler(file_handler)
        else:
            # Normal non-testing mode
            
            # Console output
            if log_to_console:
                console_handler = logging.StreamHandler(sys.stdout)
                console_handler.setLevel(level)
                console_handler.setFormatter(formatter)
                logger.addHandler(console_handler)
            
            # File output
            if log_file is None:
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                log_dir = Path(os.getenv("SKWAQ_LOG_DIR", Path.home() / ".skwaq" / "logs"))
                log_dir.mkdir(parents=True, exist_ok=True)
                log_file = log_dir / f"skwaq_{timestamp}.log"

            # Create log file handler with rotation if specified
            if rotation is not None:
                if rotation.rotation_type == "size":
                    file_handler = RotatingFileHandler(
                        log_file, maxBytes=rotation.max_bytes, backupCount=rotation.backup_count
                    )
                else:  # time-based rotation
                    file_handler = TimedRotatingFileHandler(
                        log_file,
                        when=rotation.when,
                        interval=rotation.interval,
                        backupCount=rotation.backup_count,
                    )
            else:
                file_handler = logging.FileHandler(log_file)

            file_handler.setLevel(level)
            file_handler.setFormatter(formatter)
            logger.addHandler(file_handler)

        # Store logger in global registry
        _loggers[module_name] = logger

        return logger


def get_logger(module_name: str = "skwaq") -> Union[logging.Logger, ContextAdapter]:
    """Get a logger instance.

    Args:
        module_name: Name to use for the logger (default: skwaq)

    Returns:
        Logger instance or context adapter
    """
    global _loggers

    with _logger_lock:
        if module_name in _loggers:
            return _loggers[module_name]

        # Create a new logger with default settings
        return setup_logging(module_name=module_name)


def set_log_level(level: Union[int, str], module_name: Optional[str] = None) -> None:
    """Set the log level for one or all loggers.

    Args:
        level: Logging level to set
        module_name: Logger name or None for all loggers
    """
    # Convert string level to int if needed
    if isinstance(level, str):
        level = LEVELS.get(level.upper(), logging.INFO)

    with _logger_lock:
        if module_name is None:
            # Update all loggers
            for logger in _loggers.values():
                logger.setLevel(level)

                # Update all handlers
                for handler in logger.handlers:
                    handler.setLevel(level)
        elif module_name in _loggers:
            # Update specific logger
            _loggers[module_name].setLevel(level)

            # Update its handlers
            for handler in _loggers[module_name].handlers:
                handler.setLevel(level)


class LogEvent:
    """Decorator that emits logging events when a function is called."""

    def __init__(
        self,
        event_name: str,
        level: int = logging.INFO,
        include_args: bool = False,
        include_result: bool = False,
        logger: Optional[logging.Logger] = None,
    ):
        """Initialize the log event decorator.

        Args:
            event_name: Name for the event
            level: Logging level
            include_args: Whether to include function arguments in the log
            include_result: Whether to include function result in the log
            logger: Logger to use or None for default
        """
        self.event_name = event_name
        self.level = level
        self.include_args = include_args
        self.include_result = include_result
        self.logger = logger

    def __call__(self, func: Callable) -> Callable:
        """Apply the decorator to a function.

        Args:
            func: Function to decorate

        Returns:
            Decorated function
        """
        if self.logger is None:
            self.logger = get_logger()

        def wrapper(*args, **kwargs):
            # Capture start time
            start_time = datetime.now()
            event_id = f"{self.event_name}_{start_time.strftime('%Y%m%d%H%M%S')}"

            # Create log context
            context = {
                "function": func.__name__,
                "module": func.__module__,
                "event_name": self.event_name,
                "event_id": event_id,
            }

            # Add arguments if requested
            if self.include_args:
                # Only include simple args in context to avoid serialization issues
                safe_args = []
                for arg in args:
                    if isinstance(arg, (str, int, float, bool, type(None))):
                        safe_args.append(arg)
                    else:
                        safe_args.append(f"{type(arg).__name__}@{id(arg)}")

                safe_kwargs = {}
                for key, value in kwargs.items():
                    if isinstance(value, (str, int, float, bool, type(None))):
                        safe_kwargs[key] = value
                    else:
                        safe_kwargs[key] = f"{type(value).__name__}@{id(value)}"

                context["args"] = safe_args
                context["kwargs"] = safe_kwargs

            # Log function call start
            logger_msg = f"Event {self.event_name}: {func.__name__} called"
            self.logger.log(
                self.level, logger_msg, extra={"context": context, "event_id": event_id}
            )

            # Emit event if available
            if HAS_EVENTS:
                publish(
                    LoggingEvent(
                        sender="logger",
                        level=logging.getLevelName(self.level),
                        log_message=logger_msg,
                        context=context,
                    )
                )

            try:
                # Call the original function
                result = func(*args, **kwargs)

                # Capture execution time
                duration = (datetime.now() - start_time).total_seconds()
                context["duration_seconds"] = duration

                # Add result if requested
                if self.include_result and result is not None:
                    if isinstance(result, (str, int, float, bool, type(None))):
                        context["result"] = result
                    else:
                        context["result"] = f"{type(result).__name__}@{id(result)}"

                # Log successful completion
                self.logger.log(
                    self.level,
                    f"Event {self.event_name}: {func.__name__} completed in {duration:.3f}s",
                    extra={"context": context, "event_id": event_id},
                )

                return result
            except Exception as e:
                # Capture error information
                duration = (datetime.now() - start_time).total_seconds()
                context["duration_seconds"] = duration
                context["error"] = str(e)
                context["error_type"] = type(e).__name__

                # Log the error
                self.logger.error(
                    f"Event {self.event_name}: {func.__name__} failed in {duration:.3f}s",
                    exc_info=True,
                    extra={"context": context, "event_id": event_id},
                )

                # Re-raise the exception
                raise

        return wrapper

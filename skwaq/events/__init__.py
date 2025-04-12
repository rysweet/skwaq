"""Event system package for Skwaq.

This package provides event handling and message passing functionality
for the Skwaq vulnerability assessment copilot.
"""

from .system_events import (
    ConfigEvent,
    LoggingEvent,
    SystemEvent,
    TelemetryEvent,
    get_subscribers,
    publish,
    subscribe,
    unsubscribe,
)

__all__ = [
    "SystemEvent",
    "ConfigEvent",
    "TelemetryEvent",
    "LoggingEvent",
    "subscribe",
    "unsubscribe",
    "publish",
    "get_subscribers",
]

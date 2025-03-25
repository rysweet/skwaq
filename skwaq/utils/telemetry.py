"""Telemetry functionality for Skwaq.

This module provides telemetry functionality for the Skwaq
vulnerability assessment copilot, allowing capture of events and
usage metrics while respecting user opt-out settings.
"""

from skwaq.utils.config import get_config
from skwaq.utils.logging import get_logger

logger = get_logger(__name__)


class Telemetry:
    """Telemetry system for capturing and reporting events."""

    def __init__(self):
        config = get_config()
        self.enabled = config.telemetry_enabled
        if self.enabled:
            logger.info("Telemetry is enabled.")
        else:
            logger.info("Telemetry is disabled per configuration.")

    def capture_event(self, event_name: str, data: dict):
        """Capture a telemetry event if telemetry is enabled.

        Args:
            event_name: Name of the event
            data: Additional event data
        """
        if not self.enabled:
            logger.debug(f"Telemetry disabled. Event '{event_name}' not captured.")
            return
        # Placeholder for event capture logic (e.g., send to external service)
        logger.info(f"Telemetry event captured: {event_name} - {data}")

    def set_enabled(self, enabled: bool):
        """Enable or disable telemetry.

        Args:
            enabled: True to enable, False to disable
        """
        self.enabled = enabled
        logger.info(f"Telemetry {'enabled' if enabled else 'disabled'}.")


telemetry_instance = Telemetry()

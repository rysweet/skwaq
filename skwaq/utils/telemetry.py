"""Telemetry functionality for Skwaq.

This module provides telemetry functionality for the Skwaq
vulnerability assessment copilot, allowing capture of events and
usage metrics while respecting user opt-out settings.
"""

import json
import uuid
import time
from typing import Dict, Any, Optional
from dataclasses import dataclass

from skwaq.utils.config import get_config
from skwaq.utils.logging import get_logger
from skwaq.events.system_events import TelemetryEvent, publish

logger = get_logger(__name__)


@dataclass
class TelemetryEndpoint:
    """Configuration for a telemetry endpoint."""

    name: str
    url: str
    enabled: bool = True
    headers: Optional[Dict[str, str]] = None
    timeout_seconds: int = 5


class Telemetry:
    """Telemetry system for capturing and reporting events."""

    def __init__(self, config=None, enabled=None, testing=False):
        """Initialize the telemetry system.
        
        Args:
            config: Optional configuration object to use
            enabled: Optional explicit enabled state to override the config
            testing: Whether this is being run in a test environment
        """
        self.testing = testing
        
        if config is None:
            try:
                config = get_config()
            except Exception as e:
                if testing:
                    # Use default values for testing
                    from dataclasses import dataclass
                    
                    @dataclass
                    class TestConfig:
                        telemetry_enabled: bool = False
                        telemetry: Dict[str, Any] = None
                        
                    config = TestConfig()
                    config.telemetry = {}
                else:
                    # Re-raise if not in testing mode
                    raise e
            
        # Allow explicit override of enabled state
        self.enabled = enabled if enabled is not None else config.telemetry_enabled
        self.session_id = str(uuid.uuid4())
        self.endpoints: Dict[str, TelemetryEndpoint] = {}
        self.captured_events = [] if testing else None  # Track events for testing

        # Initialize endpoints from config if available
        telemetry_config = getattr(config, "telemetry", {})
        endpoints = telemetry_config.get("endpoints", [])
        
        if endpoints:
            for endpoint in endpoints:
                if isinstance(endpoint, dict) and "name" in endpoint and "url" in endpoint:
                    self.add_endpoint(
                        name=endpoint["name"],
                        url=endpoint["url"],
                        enabled=endpoint.get("enabled", True),
                        headers=endpoint.get("headers"),
                        timeout_seconds=endpoint.get("timeout_seconds", 5),
                    )
        elif testing:
            # Add a default testing endpoint
            self.add_endpoint(
                name="test_endpoint",
                url="https://test.example.com/telemetry",
                enabled=True
            )

        if self.enabled:
            logger.info("Telemetry is enabled.")
        else:
            logger.info("Telemetry is disabled per configuration.")

    def add_endpoint(
        self,
        name: str,
        url: str,
        enabled: bool = True,
        headers: Optional[Dict[str, str]] = None,
        timeout_seconds: int = 5,
    ) -> None:
        """Add or update a telemetry endpoint.

        Args:
            name: Unique name for the endpoint
            url: URL to send telemetry data to
            enabled: Whether this endpoint is enabled
            headers: HTTP headers to include in requests
            timeout_seconds: Request timeout in seconds
        """
        self.endpoints[name] = TelemetryEndpoint(
            name=name, url=url, enabled=enabled, headers=headers, timeout_seconds=timeout_seconds
        )
        logger.debug(f"Added telemetry endpoint: {name} ({url})")

    def remove_endpoint(self, name: str) -> bool:
        """Remove a telemetry endpoint.

        Args:
            name: Name of the endpoint to remove

        Returns:
            True if the endpoint was removed, False if it didn't exist
        """
        if name in self.endpoints:
            del self.endpoints[name]
            logger.debug(f"Removed telemetry endpoint: {name}")
            return True
        return False

    def capture_event(
        self, event_name: str, data: Dict[str, Any], user_id: Optional[str] = None
    ) -> None:
        """Capture a telemetry event if telemetry is enabled.

        Args:
            event_name: Name of the event
            data: Additional event data
            user_id: Optional user identifier
        """
        if not self.enabled:
            logger.debug(f"Telemetry disabled. Event '{event_name}' not captured.")
            return

        # Create a telemetry event
        event = TelemetryEvent(
            sender="telemetry",
            event_name=event_name,
            event_data=data,
            user_id=user_id,
            session_id=self.session_id,
        )

        # Publish the event
        publish(event)

        # Send the event to configured endpoints
        self._send_event(event_name, data, user_id)

        logger.info(f"Telemetry event captured: {event_name}")
        logger.debug(f"Telemetry event details: {event_name} - {data}")

    def _send_event(
        self, event_name: str, data: Dict[str, Any], user_id: Optional[str] = None
    ) -> None:
        """Send an event to all enabled endpoints.

        Args:
            event_name: Name of the event
            data: Event data
            user_id: Optional user identifier
        """
        if not self.endpoints:
            logger.debug("No telemetry endpoints configured, skipping send")
            return

        # Prepare the payload
        payload = {
            "event_name": event_name,
            "timestamp": time.time(),
            "session_id": self.session_id,
            "data": data,
        }

        if user_id:
            payload["user_id"] = user_id
            
        # Store event for testing if needed
        if self.testing and self.captured_events is not None:
            self.captured_events.append({
                "event_name": event_name,
                "data": data,
                "user_id": user_id,
                "payload": payload
            })

        # In a real implementation, this would send the data to endpoints
        # For now, just log it
        for name, endpoint in self.endpoints.items():
            if endpoint.enabled:
                try:
                    if self.testing:
                        # Skip actual HTTP requests in testing
                        logger.debug(
                            f"[TEST] Telemetry event to {name} ({endpoint.url}): "
                            f"{json.dumps(payload)}"
                        )
                    else:
                        # This is a placeholder for actual HTTP request
                        # In production, you would use requests or aiohttp
                        # requests.post(
                        #     endpoint.url,
                        #     json=payload,
                        #     headers=endpoint.headers,
                        #     timeout=endpoint.timeout_seconds
                        # )
                        logger.debug(
                            f"Would send telemetry to {name} ({endpoint.url}): "
                            f"{json.dumps(payload)}"
                        )
                except Exception as e:
                    logger.error(f"Error sending telemetry to {name}: {e}")

    def set_enabled(self, enabled: bool) -> None:
        """Enable or disable telemetry.

        Args:
            enabled: True to enable, False to disable
        """
        old_state = self.enabled
        self.enabled = enabled

        if old_state != enabled:
            logger.info(f"Telemetry {'enabled' if enabled else 'disabled'}.")


# Global telemetry instance
telemetry_instance = Telemetry()

# Get a telemetry instance for testing
def get_test_telemetry(enabled=True):
    """Get a telemetry instance configured for testing.
    
    Args:
        enabled: Whether telemetry should be enabled in the test instance
        
    Returns:
        A telemetry instance configured for testing
    """
    return Telemetry(enabled=enabled, testing=True)

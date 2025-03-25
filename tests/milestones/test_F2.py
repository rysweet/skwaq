"""Tests for Milestone F2: Core Utilities and Infrastructure."""

import os
import json
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

from skwaq.utils.config import Config, get_config, init_config
from skwaq.utils.logging import get_logger, setup_logging, ContextAdapter, LogEvent
from skwaq.utils.telemetry import Telemetry, telemetry_instance
from skwaq.events.system_events import (
    SystemEvent,
    ConfigEvent,
    TelemetryEvent,
    LoggingEvent,
    subscribe,
    publish,
    get_subscribers,
)


def test_telemetry_system():
    """Test that the telemetry system works correctly with opt-out functionality."""
    # Test initial state from config
    with patch("skwaq.utils.config.get_config") as mock_get_config:
        # Test when telemetry is enabled
        mock_config = MagicMock()
        mock_config.telemetry_enabled = True
        mock_get_config.return_value = mock_config

        telemetry = Telemetry()
        assert telemetry.enabled is True

        # Test when telemetry is disabled
        mock_config.telemetry_enabled = False
        telemetry = Telemetry()
        assert telemetry.enabled is False

    # Test enable/disable functionality
    telemetry = Telemetry()
    telemetry.set_enabled(True)
    assert telemetry.enabled is True

    telemetry.set_enabled(False)
    assert telemetry.enabled is False


def test_telemetry_event_capture():
    """Test that telemetry events are captured when enabled and not when disabled."""
    telemetry = Telemetry()

    # Test with telemetry enabled
    telemetry.set_enabled(True)
    with patch.object(telemetry, "_send_event") as mock_send:
        telemetry.capture_event("test_event", {"data": "value"})
        mock_send.assert_called_once()

    # Test with telemetry disabled
    telemetry.set_enabled(False)
    with patch.object(telemetry, "_send_event") as mock_send:
        telemetry.capture_event("test_event", {"data": "value"})
        mock_send.assert_not_called()


def test_telemetry_endpoints():
    """Test that telemetry endpoints can be added and removed."""
    telemetry = Telemetry()

    # Add an endpoint
    telemetry.add_endpoint(name="test_endpoint", url="https://example.com/telemetry", enabled=True)

    assert "test_endpoint" in telemetry.endpoints
    assert telemetry.endpoints["test_endpoint"].url == "https://example.com/telemetry"

    # Remove an endpoint
    result = telemetry.remove_endpoint("test_endpoint")
    assert result is True
    assert "test_endpoint" not in telemetry.endpoints

    # Remove non-existent endpoint
    result = telemetry.remove_endpoint("nonexistent")
    assert result is False


def test_config_management():
    """Test that configuration is loaded from various sources correctly."""
    # Test env var config
    with patch.dict(
        os.environ,
        {
            "OPENAI_API_KEY": "test-key",
            "OPENAI_ORG_ID": "test-org",
            "NEO4J_URI": "bolt://testhost:7687",
            "TELEMETRY_ENABLED": "true",
        },
    ):
        config = Config.from_env()
        assert config.openai_api_key == "test-key"
        assert config.openai_org_id == "test-org"
        assert config.neo4j_uri == "bolt://testhost:7687"
        assert config.telemetry_enabled is True

    # Test file config
    with tempfile.NamedTemporaryFile(mode="w+", suffix=".json") as temp_file:
        config_data = {
            "openai_api_key": "file-key",
            "openai_org_id": "file-org",
            "neo4j_uri": "bolt://filehost:7687",
            "telemetry": {"enabled": False},
        }
        json.dump(config_data, temp_file)
        temp_file.flush()

        config = Config.from_file(Path(temp_file.name))
        assert config.openai_api_key == "file-key"
        assert config.openai_org_id == "file-org"
        assert config.neo4j_uri == "bolt://filehost:7687"
        assert config.telemetry_enabled is False


def test_config_validation():
    """Test that configuration validation works correctly."""
    # Test a valid config
    valid_config = {
        "openai_api_key": "valid-key",
        "openai_org_id": "valid-org",
    }
    # Should not raise an exception
    Config.validate(valid_config)

    # Test config with invalid Neo4j URI
    invalid_uri_config = {
        "openai_api_key": "valid-key",
        "openai_org_id": "valid-org",
        "neo4j_uri": "invalid-uri",
    }
    with pytest.raises(Exception):
        Config.validate(invalid_uri_config)


def test_config_merge():
    """Test that configurations can be merged correctly."""
    # Create base config
    base_config = Config(
        openai_api_key="base-key", openai_org_id="base-org", neo4j_uri="bolt://base:7687"
    )

    # Create overlay config
    overlay_config = Config(
        openai_api_key="overlay-key", openai_org_id="overlay-org", neo4j_user="overlay-user"
    )

    # Merge configs
    result = base_config.merge(overlay_config)

    # Check result
    assert result is base_config  # Should return self
    assert base_config.openai_api_key == "overlay-key"
    assert base_config.openai_org_id == "overlay-org"
    assert base_config.neo4j_uri == "bolt://base:7687"  # Unchanged
    assert base_config.neo4j_user == "overlay-user"  # From overlay


def test_event_system():
    """Test that the event system can emit and receive events."""
    # Test event subscription
    test_event_received = False

    def test_handler(event):
        nonlocal test_event_received
        test_event_received = True

    # Subscribe to events
    subscribe(SystemEvent, test_handler)

    # Publish an event
    event = SystemEvent(sender="test", message="Test message")
    publish(event)

    # Check that the event was received
    assert test_event_received is True

    # Check event typing
    assert isinstance(event, SystemEvent)
    assert event.sender == "test"
    assert event.message == "Test message"


def test_event_inheritance():
    """Test that event inheritance works correctly."""
    config_events_received = 0
    system_events_received = 0

    # Handler for all system events
    def system_handler(event):
        nonlocal system_events_received
        system_events_received += 1

    # Handler specifically for config events
    def config_handler(event):
        nonlocal config_events_received
        config_events_received += 1

    # Subscribe to events
    subscribe(SystemEvent, system_handler)
    subscribe(ConfigEvent, config_handler)

    # Publish a system event
    publish(SystemEvent(sender="test", message="Test message"))

    # Publish a config event
    publish(ConfigEvent(sender="test", key="test_key", value="test_value"))

    # The system handler should receive both events
    assert system_events_received == 2

    # The config handler should only receive the config event
    assert config_events_received == 1


def test_logging_system():
    """Test that the logging system captures appropriate information."""
    # Test log file creation and content
    with tempfile.TemporaryDirectory() as temp_dir:
        log_file = Path(temp_dir) / "test.log"
        logger = setup_logging(level=10, log_file=log_file)

        # Test logging at different levels
        logger.debug("Debug message")
        logger.info("Info message")
        logger.warning("Warning message")
        logger.error("Error message")

        # Check log file content
        with open(log_file, "r") as f:
            log_content = f.read()
            assert "Debug message" in log_content
            assert "Info message" in log_content
            assert "Warning message" in log_content
            assert "Error message" in log_content


def test_structured_logging():
    """Test structured logging functionality."""
    with tempfile.TemporaryDirectory() as temp_dir:
        log_file = Path(temp_dir) / "structured.log"
        logger = setup_logging(level=10, log_file=log_file, structured=True)

        # Log with additional context
        logger.info(
            "Structured message",
            extra={"context": {"user_id": "123", "action": "login", "status": "success"}},
        )

        # Check log file content
        with open(log_file, "r") as f:
            log_line = f.readline()
            log_data = json.loads(log_line)
            assert log_data["message"] == "Structured message"
            assert log_data["context"]["user_id"] == "123"
            assert log_data["context"]["action"] == "login"
            assert log_data["context"]["status"] == "success"


def test_logger_context():
    """Test logger context functionality."""
    with tempfile.TemporaryDirectory() as temp_dir:
        log_file = Path(temp_dir) / "context.log"
        logger = setup_logging(level=10, log_file=log_file, structured=True)

        # Create contextual logger
        if hasattr(logger, "with_context"):
            contextual_logger = logger.with_context(component="auth", user_id="123")

            # Log with the contextual logger
            contextual_logger.info("User authenticated")

            # Check log file content
            with open(log_file, "r") as f:
                log_line = f.readline()
                log_data = json.loads(log_line)
                assert "component" in log_data["context"]
                assert log_data["context"]["component"] == "auth"
                assert log_data["context"]["user_id"] == "123"


@LogEvent("test_event")
def sample_function(arg1, arg2):
    """Sample function for testing log event decorator."""
    return arg1 + arg2


def test_log_event_decorator():
    """Test the LogEvent decorator."""
    with tempfile.TemporaryDirectory() as temp_dir:
        log_file = Path(temp_dir) / "decorator.log"
        logger = setup_logging(level=10, log_file=log_file)

        # Call decorated function
        result = sample_function(5, 7)

        # Check result
        assert result == 12

        # Check log file content
        with open(log_file, "r") as f:
            log_content = f.read()
            assert "test_event" in log_content
            assert "sample_function called" in log_content
            assert "completed" in log_content


def test_component_integration():
    """Test integration between telemetry, logging, and event systems."""
    # Initialize systems
    with tempfile.TemporaryDirectory() as temp_dir:
        log_file = Path(temp_dir) / "integration.log"
        logger = setup_logging(level=10, log_file=log_file)

        telemetry = Telemetry()
        telemetry.set_enabled(True)

        # Set up event tracking
        events_received = []

        def track_event(event):
            events_received.append(event)

        subscribe(TelemetryEvent, track_event)

        # Generate telemetry event
        telemetry.capture_event(
            "user_action", {"action": "click", "element": "button", "page": "home"}
        )

        # Check that events were received
        assert len(events_received) > 0
        assert any(isinstance(e, TelemetryEvent) for e in events_received)

        # Check log file has telemetry entries
        with open(log_file, "r") as f:
            log_content = f.read()
            assert "Telemetry event captured" in log_content

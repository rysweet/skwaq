"""Configuration management for the Skwaq vulnerability assessment copilot.

This module handles loading, validation, and access to configuration settings
for the Skwaq system.
"""

import json
import os
from pathlib import Path
from typing import Any, Dict, Optional

# Default configuration paths
DEFAULT_CONFIG_PATH = Path("config/default_config.json")
USER_CONFIG_PATH = Path("config/user_config.json")


class ConfigurationError(Exception):
    """Exception raised for configuration-related errors."""

    pass


class Configuration:
    """Configuration manager for the Skwaq copilot.
    
    This class is responsible for loading, validating, and providing access to
    configuration settings for the Skwaq system.
    """

    def __init__(self, config_path: Optional[Path] = None):
        """Initialize the configuration manager.
        
        Args:
            config_path: Optional custom path to a configuration file.
                         If not provided, the system will try to load from
                         the default locations.
        """
        self._config: Dict[str, Any] = {}
        self._config_path = config_path
        self._load_config()

    def _load_config(self) -> None:
        """Load configuration from file.
        
        The loading order is:
        1. Default configuration (config/default_config.json)
        2. User configuration (config/user_config.json) - if exists
        3. Custom configuration (specified in constructor) - if exists
        
        Later configurations override earlier ones.
        """
        # Start with empty configuration
        self._config = {}
        
        # Load default configuration if it exists
        if DEFAULT_CONFIG_PATH.exists():
            try:
                with open(DEFAULT_CONFIG_PATH, "r") as f:
                    default_config = json.load(f)
                    self._config.update(default_config)
            except json.JSONDecodeError as e:
                raise ConfigurationError(f"Invalid default configuration format: {e}")
        
        # Load user configuration if it exists
        if USER_CONFIG_PATH.exists():
            try:
                with open(USER_CONFIG_PATH, "r") as f:
                    user_config = json.load(f)
                    self._config.update(user_config)
            except json.JSONDecodeError as e:
                raise ConfigurationError(f"Invalid user configuration format: {e}")
        
        # Load custom configuration if provided
        if self._config_path and self._config_path.exists():
            try:
                with open(self._config_path, "r") as f:
                    custom_config = json.load(f)
                    self._config.update(custom_config)
            except json.JSONDecodeError as e:
                raise ConfigurationError(f"Invalid custom configuration format: {e}")
        
        # Validate critical configuration elements
        self._validate_config()

    def _validate_config(self) -> None:
        """Validate that the configuration has all required elements."""
        # Validate Neo4j configuration
        if "neo4j" not in self._config:
            raise ConfigurationError("Missing Neo4j configuration")
        
        neo4j_config = self._config["neo4j"]
        for key in ["uri", "user", "password"]:
            if key not in neo4j_config:
                raise ConfigurationError(f"Missing Neo4j configuration: {key}")
        
        # Validate OpenAI configuration
        if "openai" not in self._config:
            raise ConfigurationError("Missing OpenAI configuration")
        
        # Check for Azure-specific OpenAI configuration
        openai_config = self._config["openai"]
        if "api_type" in openai_config and openai_config["api_type"] == "azure":
            # Azure-specific validation
            for key in ["api_version"]:
                if key not in openai_config:
                    raise ConfigurationError(f"Missing Azure OpenAI configuration: {key}")
            
            # Check if azure_openai_credentials.json exists and load if needed
            azure_creds_path = Path("config/azure_openai_credentials.json")
            if azure_creds_path.exists() and "api_key" not in openai_config:
                try:
                    with open(azure_creds_path, "r") as f:
                        azure_creds = json.load(f)
                        # Update the OpenAI config with the credentials
                        self._config["openai"].update(azure_creds)
                except json.JSONDecodeError as e:
                    raise ConfigurationError(f"Invalid Azure credentials format: {e}")

    def get(self, key: str, default: Any = None) -> Any:
        """Get a configuration value by key.
        
        Args:
            key: The configuration key to retrieve
            default: Default value to return if key doesn't exist
            
        Returns:
            The configuration value, or the default if the key doesn't exist
        """
        return self._config.get(key, default)

    def set(self, key: str, value: Any) -> None:
        """Set a configuration value.
        
        Args:
            key: The configuration key to set
            value: The value to set
        """
        self._config[key] = value

    def save_user_config(self) -> None:
        """Save the current configuration to the user configuration file."""
        # Ensure config directory exists
        os.makedirs(os.path.dirname(USER_CONFIG_PATH), exist_ok=True)
        
        try:
            with open(USER_CONFIG_PATH, "w") as f:
                json.dump(self._config, f, indent=2)
        except IOError as e:
            raise ConfigurationError(f"Failed to save user configuration: {e}")

    @property
    def neo4j(self) -> Dict[str, Any]:
        """Get Neo4j configuration."""
        return self._config.get("neo4j", {})

    @property
    def openai(self) -> Dict[str, Any]:
        """Get OpenAI configuration."""
        return self._config.get("openai", {})

    @property
    def telemetry(self) -> Dict[str, Any]:
        """Get telemetry configuration."""
        return self._config.get("telemetry", {"enabled": False})


# Global configuration instance
_config: Optional[Configuration] = None


def get_config(config_path: Optional[Path] = None) -> Configuration:
    """Get the global configuration instance.
    
    Args:
        config_path: Optional custom path to a configuration file.
                     If not provided, the system will try to load from
                     the default locations.
                     
    Returns:
        The global Configuration instance
    """
    global _config
    if _config is None or config_path is not None:
        _config = Configuration(config_path)
    return _config
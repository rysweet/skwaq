"""Configuration management for Skwaq.

This module provides configuration management functionality for the Skwaq
vulnerability assessment copilot.
"""

import json
import os
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Optional, Dict, Any, List, Set, TypeVar, Union, cast
import threading
import json

try:
    from dotenv import load_dotenv, find_dotenv
    HAS_DOTENV = True
except ImportError:
    HAS_DOTENV = False

from skwaq.utils.logging import get_logger

try:
    from skwaq.events.system_events import ConfigEvent, publish

    HAS_EVENTS = True
except ImportError:
    HAS_EVENTS = False

logger = get_logger(__name__)

# Define type for configuration sources
ConfigSource = TypeVar("ConfigSource", bound="BaseConfigSource")


class ConfigValidationError(Exception):
    """Exception raised when configuration validation fails."""

    pass


class BaseConfigSource:
    """Base class for configuration sources."""

    def __init__(self, name: str, priority: int = 0):
        """Initialize a configuration source.

        Args:
            name: Name of the configuration source
            priority: Priority of the source (higher values take precedence)
        """
        self.name = name
        self.priority = priority

    def get_config(self) -> Dict[str, Any]:
        """Get configuration from this source.

        Returns:
            Dictionary with configuration values
        """
        raise NotImplementedError("Subclasses must implement get_config")


class FileConfigSource(BaseConfigSource):
    """Configuration source that loads from a file."""

    def __init__(
        self,
        file_path: Union[str, Path],
        name: Optional[str] = None,
        priority: int = 50,
        auto_reload: bool = False,
        reload_interval_seconds: int = 30,
    ):
        """Initialize a file-based configuration source.

        Args:
            file_path: Path to the configuration file
            name: Name of the configuration source
            priority: Priority of the source (higher values take precedence)
            auto_reload: Whether to automatically reload configuration
            reload_interval_seconds: Interval between reload checks
        """
        super().__init__(name=name or f"file:{file_path}", priority=priority)
        self.file_path = Path(file_path)
        self.last_modified: Optional[float] = None
        self.last_checked: float = 0
        self.auto_reload = auto_reload
        self.reload_interval = reload_interval_seconds
        self._config_cache: Dict[str, Any] = {}
        self._lock = threading.RLock()

    def get_config(self) -> Dict[str, Any]:
        """Get configuration from this file source.

        Returns:
            Dictionary with configuration values
        """
        with self._lock:
            current_time = time.time()

            # Check if we need to reload configuration
            if (
                self.auto_reload
                and current_time - self.last_checked > self.reload_interval
            ):
                self.last_checked = current_time

                if not self.file_path.exists():
                    if self._config_cache:
                        logger.warning(
                            f"Configuration file {self.file_path} no longer exists"
                        )
                        self._config_cache = {}
                    return {}

                # Check if file has been modified
                modified_time = self.file_path.stat().st_mtime
                if self.last_modified is None or modified_time > self.last_modified:
                    try:
                        with open(self.file_path) as f:
                            new_config = json.load(f)

                        # Only update if config has changed
                        if new_config != self._config_cache:
                            logger.info(f"Reloaded configuration from {self.file_path}")
                            self._config_cache = new_config

                        self.last_modified = modified_time
                    except Exception as e:
                        logger.error(
                            f"Error reloading configuration from {self.file_path}: {e}"
                        )

            # If cache is empty and file exists, load it
            if not self._config_cache and self.file_path.exists():
                try:
                    with open(self.file_path) as f:
                        self._config_cache = json.load(f)
                    self.last_modified = self.file_path.stat().st_mtime
                except Exception as e:
                    logger.error(
                        f"Error loading configuration from {self.file_path}: {e}"
                    )
                    return {}

            return self._config_cache


class EnvConfigSource(BaseConfigSource):
    """Configuration source that loads from environment variables."""

    def __init__(
        self, prefix: str = "SKWAQ_", name: str = "environment", priority: int = 100
    ):
        """Initialize an environment-based configuration source.

        Args:
            prefix: Prefix for environment variables
            name: Name of the configuration source
            priority: Priority of the source (higher values take precedence)
        """
        super().__init__(name=name, priority=priority)
        self.prefix = prefix

    def get_config(self) -> Dict[str, Any]:
        """Get configuration from environment variables.

        Returns:
            Dictionary with configuration values
        """
        config = {}

        # Special case for OpenAI variables
        if "OPENAI_API_KEY" in os.environ:
            config["openai_api_key"] = os.environ["OPENAI_API_KEY"]

        if "AZURE_OPENAI_API_KEY" in os.environ:
            config["openai_api_key"] = os.environ["AZURE_OPENAI_API_KEY"]
            config["openai"] = config.get("openai", {})
            config["openai"]["api_type"] = "azure"

        if "AZURE_OPENAI_ENDPOINT" in os.environ:
            config["openai"] = config.get("openai", {})
            config["openai"]["endpoint"] = os.environ["AZURE_OPENAI_ENDPOINT"]

        if "AZURE_OPENAI_API_VERSION" in os.environ:
            config["openai"] = config.get("openai", {})
            config["openai"]["api_version"] = os.environ["AZURE_OPENAI_API_VERSION"]

        # Azure Entra ID (Azure AD) authentication
        if "AZURE_OPENAI_USE_ENTRA_ID" in os.environ:
            use_entra_id = os.environ["AZURE_OPENAI_USE_ENTRA_ID"].lower() in (
                "true", "1", "yes", "y"
            )
            config["openai"] = config.get("openai", {})
            config["openai"]["use_entra_id"] = use_entra_id
            
            if use_entra_id:
                # Check if we're using bearer token authentication
                if "AZURE_OPENAI_AUTH_METHOD" in os.environ and os.environ["AZURE_OPENAI_AUTH_METHOD"] == "bearer_token":
                    config["openai"]["auth_method"] = "bearer_token"
                    if "AZURE_OPENAI_TOKEN_SCOPE" in os.environ:
                        config["openai"]["token_scope"] = os.environ["AZURE_OPENAI_TOKEN_SCOPE"]
                else:
                    # Standard Entra ID authentication with client credentials
                    if "AZURE_TENANT_ID" in os.environ:
                        config["openai"]["tenant_id"] = os.environ["AZURE_TENANT_ID"]
                    
                    if "AZURE_CLIENT_ID" in os.environ:
                        config["openai"]["client_id"] = os.environ["AZURE_CLIENT_ID"]
                    
                    if "AZURE_CLIENT_SECRET" in os.environ:
                        config["openai"]["client_secret"] = os.environ["AZURE_CLIENT_SECRET"]

        # Model deployments
        if "AZURE_OPENAI_MODEL_DEPLOYMENTS" in os.environ:
            try:
                deployments = json.loads(os.environ["AZURE_OPENAI_MODEL_DEPLOYMENTS"])
                config["openai"] = config.get("openai", {})
                config["openai"]["model_deployments"] = deployments
            except json.JSONDecodeError:
                logger.warning(
                    f"Failed to parse AZURE_OPENAI_MODEL_DEPLOYMENTS as JSON: {os.environ['AZURE_OPENAI_MODEL_DEPLOYMENTS']}"
                )

        if "OPENAI_ORG_ID" in os.environ:
            config["openai_org_id"] = os.environ["OPENAI_ORG_ID"]

        if "OPENAI_MODEL" in os.environ:
            config["openai_model"] = os.environ["OPENAI_MODEL"]

        # Special case for Neo4j variables
        if "NEO4J_URI" in os.environ:
            config["neo4j_uri"] = os.environ["NEO4J_URI"]

        if "NEO4J_USER" in os.environ:
            config["neo4j_user"] = os.environ["NEO4J_USER"]

        if "NEO4J_PASSWORD" in os.environ:
            config["neo4j_password"] = os.environ["NEO4J_PASSWORD"]

        # Special case for telemetry enabled
        if "TELEMETRY_ENABLED" in os.environ:
            config["telemetry_enabled"] = os.environ["TELEMETRY_ENABLED"].lower() in (
                "true",
                "1",
                "yes",
                "y",
            )

        # Look for variables with prefix
        for key, value in os.environ.items():
            if key.startswith(self.prefix):
                config_key = key[len(self.prefix) :].lower()

                # Convert values to appropriate types
                if value.lower() in ("true", "false"):
                    config[config_key] = value.lower() == "true"
                elif value.isdigit():
                    config[config_key] = int(value)
                elif value.replace(".", "", 1).isdigit():
                    config[config_key] = float(value)
                else:
                    config[config_key] = value

        return config


class DotEnvConfigSource(BaseConfigSource):
    """Configuration source that loads from a .env file."""

    def __init__(
        self, 
        file_path: Optional[Union[str, Path]] = None,
        name: str = "dotenv",
        priority: int = 75
    ):
        """Initialize a dotenv-based configuration source.

        Args:
            file_path: Path to the .env file (optional, will search if not provided)
            name: Name of the configuration source
            priority: Priority of the source (higher values take precedence)
        """
        if not HAS_DOTENV:
            raise ImportError(
                "The 'python-dotenv' package is required for DotEnvConfigSource. "
                "Install it with 'pip install python-dotenv'."
            )
        
        super().__init__(name=name, priority=priority)
        
        if file_path:
            self.file_path = Path(file_path)
        else:
            # Try to find a .env file
            dotenv_path = find_dotenv(usecwd=True)
            self.file_path = Path(dotenv_path) if dotenv_path else None
            
        self.loaded = False
        
    def get_config(self) -> Dict[str, Any]:
        """Get configuration from .env file.

        Returns:
            Dictionary with configuration values
        """
        config = {}
        
        if not self.file_path or not self.file_path.exists():
            logger.debug("No .env file found for configuration")
            return config
        
        # Load the .env file into environment variables if not already loaded
        if not self.loaded:
            load_dotenv(self.file_path)
            self.loaded = True
            logger.info(f"Loaded configuration from .env file: {self.file_path}")
        
        # Create an environment config source to parse the environment variables
        # that were just loaded from the .env file
        env_source = EnvConfigSource(name=f"dotenv:{self.file_path}")
        return env_source.get_config()


@dataclass
class Config:
    """Configuration container for Skwaq.

    Attributes:
        openai_api_key: OpenAI API key for authentication
        openai_org_id: OpenAI organization ID
        openai_model: Model to use for completions
        neo4j_uri: URI for Neo4j database connection
        neo4j_user: Username for Neo4j authentication
        neo4j_password: Password for Neo4j authentication
        telemetry_enabled: Whether telemetry is enabled
        telemetry: Detailed telemetry configuration
        openai: Detailed OpenAI configuration
    """

    openai_api_key: str
    openai_org_id: str
    openai_model: Optional[str] = None
    neo4j_uri: str = "bolt://localhost:7687"
    neo4j_user: str = "neo4j"
    neo4j_password: str = "skwaqdev"
    telemetry_enabled: bool = False
    telemetry: Dict[str, Any] = field(default_factory=dict)
    openai: Dict[str, Any] = field(default_factory=dict)
    log_level: str = "INFO"
    custom_values: Dict[str, Any] = field(default_factory=dict)

    # Keep track of which sources provided which values
    _sources: Dict[str, str] = field(default_factory=dict)

    @classmethod
    def from_file(cls, config_path: Path) -> "Config":
        """Load configuration from a JSON file.

        Args:
            config_path: Path to the configuration file

        Returns:
            Config object with values from file

        Raises:
            FileNotFoundError: If config file doesn't exist
            JSONDecodeError: If config file isn't valid JSON
        """
        with open(config_path) as f:
            config_data = json.load(f)

        # Process the configuration data
        return cls.from_dict(config_data, source=f"file:{config_path}")

    @classmethod
    def from_dict(cls, config_data: Dict[str, Any], source: str = "dict") -> "Config":
        """Create a Config object from a dictionary.

        Args:
            config_data: Dictionary with configuration values
            source: Source identifier for tracking

        Returns:
            Config object with values from the dictionary
        """
        # Make a copy to avoid modifying the original
        data = dict(config_data)

        # Process telemetry configuration
        telemetry_data = data.pop("telemetry", {})
        telemetry_enabled = data.get(
            "telemetry_enabled", telemetry_data.get("enabled", False)
        )

        # Create the config
        config = cls(
            openai_api_key=data.pop("openai_api_key", ""),
            openai_org_id=data.pop("openai_org_id", ""),
            openai_model=data.pop("openai_model", None),
            neo4j_uri=data.pop("neo4j_uri", "bolt://localhost:7687"),
            neo4j_user=data.pop("neo4j_user", "neo4j"),
            neo4j_password=data.pop("neo4j_password", "skwaqdev"),
            telemetry_enabled=telemetry_enabled,
            telemetry=telemetry_data,
            openai=data.pop("openai", {}),
            log_level=data.pop("log_level", "INFO"),
            custom_values=data,  # Store remaining values as custom values
        )

        # Track sources for all fields
        for field_name in [
            "openai_api_key",
            "openai_org_id",
            "openai_model",
            "neo4j_uri",
            "neo4j_user",
            "neo4j_password",
            "telemetry_enabled",
            "log_level",
        ]:
            config._sources[field_name] = source

        # Track sources for nested configurations
        config._sources["telemetry"] = source
        config._sources["openai"] = source

        return config

    @classmethod
    def from_env(cls) -> "Config":
        """Load configuration from environment variables.

        Returns:
            Config object with values from environment
        """
        env_source = EnvConfigSource()
        config_data = env_source.get_config()
        return cls.from_dict(config_data, source="environment")

    @classmethod
    def from_sources(cls, sources: List[BaseConfigSource]) -> "Config":
        """Create a Config object by merging multiple sources.

        Sources are processed in order of priority (highest to lowest).

        Args:
            sources: List of configuration sources

        Returns:
            Config object with merged configuration values
        """
        # Sort sources by priority (highest first)
        sorted_sources = sorted(sources, key=lambda s: s.priority, reverse=True)

        # Collect configuration from all sources
        merged_config: Dict[str, Any] = {}
        source_map: Dict[str, str] = {}

        for source in sorted_sources:
            source_config = source.get_config()

            # Track source for each value
            for key, value in source_config.items():
                if key not in merged_config:
                    merged_config[key] = value
                    source_map[key] = source.name

        # Create config object
        config = cls.from_dict(merged_config)

        # Update source tracking
        config._sources.update(source_map)

        return config

    @classmethod
    def validate(cls, config_data: Dict[str, Any]) -> bool:
        """Validate configuration data.

        Args:
            config_data: Configuration data to validate

        Returns:
            True if validation succeeds

        Raises:
            ConfigValidationError: If validation fails
        """
        # Check for required fields
        required_fields = ["openai_api_key", "openai_org_id"]
        missing_fields = [f for f in required_fields if f not in config_data]

        if missing_fields:
            raise ConfigValidationError(
                f"Missing required configuration fields: {', '.join(missing_fields)}"
            )

        # Validate Neo4j URI format
        if "neo4j_uri" in config_data:
            uri = config_data["neo4j_uri"]
            if not (
                uri.startswith("bolt://")
                or uri.startswith("neo4j://")
                or uri.startswith("neo4j+s://")
            ):
                raise ConfigValidationError(
                    f"Invalid Neo4j URI format: {uri}. "
                    "Must start with bolt://, neo4j://, or neo4j+s://"
                )

        return True

    def get(self, key: str, default: Any = None) -> Any:
        """Get a configuration value by key.

        Checks direct attributes first, then nested configurations,
        and finally custom values.

        Args:
            key: The configuration key (can use dot notation for nested values)
            default: Default value if key is not found

        Returns:
            The configuration value or default
        """
        # Handle nested keys with dot notation
        if "." in key:
            parts = key.split(".", 1)
            parent, child = parts

            # Check nested configurations
            if parent == "openai" and self.openai:
                return self.openai.get(child, default)
            elif parent == "telemetry" and self.telemetry:
                return self.telemetry.get(child, default)
            elif parent == "custom" and self.custom_values:
                return self.custom_values.get(child, default)
            else:
                return default

        # Check direct attributes
        if hasattr(self, key):
            return getattr(self, key)

        # Check nested configs
        if key in self.openai:
            return self.openai[key]

        if key in self.telemetry:
            return self.telemetry[key]

        # Check custom values
        if key in self.custom_values:
            return self.custom_values[key]

        return default

    def set(self, key: str, value: Any, source: str = "api") -> bool:
        """Set a configuration value.

        Args:
            key: The configuration key
            value: The value to set
            source: Source identifier for tracking

        Returns:
            True if the value was set, False otherwise
        """
        # Handle nested keys with dot notation
        if "." in key:
            parts = key.split(".", 1)
            parent, child = parts

            if parent == "openai":
                old_value = self.openai.get(child)
                self.openai[child] = value
                self._sources[f"openai.{child}"] = source

                if HAS_EVENTS:
                    publish(
                        ConfigEvent(
                            sender="config",
                            key=f"openai.{child}",
                            value=value,
                            old_value=old_value,
                        )
                    )
                return True

            elif parent == "telemetry":
                old_value = self.telemetry.get(child)
                self.telemetry[child] = value
                self._sources[f"telemetry.{child}"] = source

                if HAS_EVENTS:
                    publish(
                        ConfigEvent(
                            sender="config",
                            key=f"telemetry.{child}",
                            value=value,
                            old_value=old_value,
                        )
                    )
                return True

            elif parent == "custom":
                old_value = self.custom_values.get(child)
                self.custom_values[child] = value
                self._sources[f"custom.{child}"] = source

                if HAS_EVENTS:
                    publish(
                        ConfigEvent(
                            sender="config",
                            key=f"custom.{child}",
                            value=value,
                            old_value=old_value,
                        )
                    )
                return True

            else:
                return False

        # Handle direct attributes
        if hasattr(self, key) and key not in ("_sources", "custom_values"):
            old_value = getattr(self, key)
            setattr(self, key, value)
            self._sources[key] = source

            if HAS_EVENTS:
                publish(
                    ConfigEvent(
                        sender="config", key=key, value=value, old_value=old_value
                    )
                )
            return True

        # Store in custom values if not a direct attribute
        old_value = self.custom_values.get(key)
        self.custom_values[key] = value
        self._sources[f"custom.{key}"] = source

        if HAS_EVENTS:
            publish(
                ConfigEvent(
                    sender="config",
                    key=f"custom.{key}",
                    value=value,
                    old_value=old_value,
                )
            )
        return True

    def get_source(self, key: str) -> Optional[str]:
        """Get the source that provided a configuration value.

        Args:
            key: The configuration key

        Returns:
            Source identifier or None if key not found
        """
        if "." in key:
            return self._sources.get(key)
        return self._sources.get(key)

    def merge(self, other: "Config", source: str = "merge") -> "Config":
        """Merge another configuration into this one.

        Values from the other configuration take precedence, except for
        empty or None values which won't overwrite existing values.

        Args:
            other: Configuration to merge
            source: Source identifier for tracking

        Returns:
            Self, for chaining
        """
        # Merge direct fields
        for field in [
            "openai_api_key",
            "openai_org_id",
            "openai_model",
            "neo4j_user",
            "neo4j_password",
            "telemetry_enabled",
            "log_level",
        ]:
            value = getattr(other, field)
            if value:  # Don't overwrite with empty values
                setattr(self, field, value)
                self._sources[field] = other._sources.get(field, source)

        # Handle neo4j_uri specially - don't overwrite test values
        if getattr(other, "neo4j_uri") and (
            self.neo4j_uri == "bolt://localhost:7687" or not self.neo4j_uri
        ):
            self.neo4j_uri = other.neo4j_uri
            self._sources["neo4j_uri"] = other._sources.get("neo4j_uri", source)

        # Merge nested dictionaries
        self.openai.update(other.openai)
        self._sources["openai"] = other._sources.get("openai", source)

        self.telemetry.update(other.telemetry)
        self._sources["telemetry"] = other._sources.get("telemetry", source)

        self.custom_values.update(other.custom_values)

        return self

    def to_dict(self) -> Dict[str, Any]:
        """Convert configuration to a dictionary.

        Returns:
            Dictionary representation of the configuration
        """
        config_dict = asdict(self)

        # Remove internal fields
        config_dict.pop("_sources", None)

        # Merge custom values
        if not config_dict["custom_values"]:
            config_dict.pop("custom_values")
        else:
            for key, value in config_dict.pop("custom_values").items():
                config_dict[key] = value

        return config_dict

    def to_json(self, indent: int = 2) -> str:
        """Convert configuration to a JSON string.

        Args:
            indent: Indentation level for JSON formatting

        Returns:
            JSON string representation of the configuration
        """
        return json.dumps(self.to_dict(), indent=indent)

    def save_to_file(self, file_path: Union[str, Path]) -> None:
        """Save configuration to a file.

        Args:
            file_path: Path to the file
        """
        file_path = Path(file_path)
        file_path.parent.mkdir(parents=True, exist_ok=True)

        with open(file_path, "w") as f:
            f.write(self.to_json())

        logger.info(f"Configuration saved to {file_path}")

    @property
    def neo4j(self) -> Dict[str, str]:
        """Get Neo4j configuration as a dictionary.

        Returns:
            Dictionary with Neo4j configuration
        """
        return {
            "uri": self.neo4j_uri,
            "user": self.neo4j_user,
            "password": self.neo4j_password,
        }


# Global config instance
_config: Optional[Config] = None
_config_sources: List[BaseConfigSource] = []
_config_lock = threading.RLock()


def register_config_source(source: BaseConfigSource) -> None:
    """Register a configuration source.

    Args:
        source: Configuration source to register
    """
    global _config_sources
    with _config_lock:
        # Check if source with the same name already exists
        for i, existing in enumerate(_config_sources):
            if existing.name == source.name:
                # Replace the existing source
                _config_sources[i] = source
                logger.debug(f"Replaced config source: {source.name}")
                return

        # Add the new source
        _config_sources.append(source)
        logger.debug(f"Added config source: {source.name}")

        # Sort sources by priority
        _config_sources.sort(key=lambda s: s.priority, reverse=True)

        # Reset the global config so it will be reloaded
        _config = None


def get_config() -> Config:
    """Get the global configuration instance.

    If no configuration has been loaded yet, attempts to load from registered
    sources, environment variables, .env file, and finally falls back to default configuration.

    Returns:
        The global Config instance
    """
    global _config, _config_sources
    with _config_lock:
        if _config is None:
            try:
                # If we have registered sources, use them
                if _config_sources:
                    _config = Config.from_sources(_config_sources)
                else:
                    # First try to load from .env file if available
                    if HAS_DOTENV:
                        try:
                            dotenv_source = DotEnvConfigSource()
                            register_config_source(dotenv_source)
                        except Exception as e:
                            logger.debug(f"Error setting up dotenv config source: {e}")
                    
                    # Register the environment source (higher priority than dotenv)
                    register_config_source(EnvConfigSource())
                    
                    # Create configuration from registered sources
                    _config = Config.from_sources(_config_sources)

                    # Look for default config file
                    default_config = Path.home() / ".skwaq" / "config.json"
                    if default_config.exists():
                        try:
                            file_config = Config.from_file(default_config)
                            _config.merge(file_config)

                            # Register the file source
                            register_config_source(
                                FileConfigSource(default_config, auto_reload=True)
                            )
                        except Exception as e:
                            logger.warning(f"Error loading default config file: {e}")
            except Exception as e:
                logger.error(f"Error loading configuration: {e}")
                # Fall back to default configuration
                _config = Config(
                    openai_api_key="",
                    openai_org_id="",
                )

    return cast(Config, _config)


def init_config(config: Config) -> None:
    """Initialize the global configuration with a specific config instance.

    Args:
        config: The configuration instance to use
    """
    global _config
    with _config_lock:
        _config = config
        logger.debug("Initialized global configuration")


def reload_config() -> None:
    """Reload configuration from all registered sources."""
    global _config, _config_sources
    with _config_lock:
        if not _config_sources:
            logger.warning("No configuration sources registered, nothing to reload")
            return

        # Create a new config from sources
        new_config = Config.from_sources(_config_sources)

        # If we have an existing config, compare and emit events for changes
        if _config is not None:
            old_dict = _config.to_dict()
            new_dict = new_config.to_dict()

            # Check for changes
            for key, new_value in new_dict.items():
                if key in old_dict and old_dict[key] != new_value:
                    if HAS_EVENTS:
                        publish(
                            ConfigEvent(
                                sender="config_reload",
                                key=key,
                                value=new_value,
                                old_value=old_dict[key],
                            )
                        )

        # Update the global config
        _config = new_config
        logger.info("Configuration reloaded from all sources")


def update_config(key: str, value: Any, source: str = "cli") -> None:
    """Update a configuration value.
    
    Args:
        key: Configuration key (can use dot notation for nested values)
        value: New value to set
        source: Source identifier for tracking
    
    Raises:
        ValueError: If the key format is invalid
    """
    config = get_config()
    
    if not key:
        raise ValueError("Configuration key cannot be empty")
    
    result = config.set(key, value, source)
    
    if not result:
        raise ValueError(f"Failed to update configuration key: {key}")
    
    logger.info(f"Updated configuration: {key} = {value}")


def save_config(file_path: Optional[Union[str, Path]] = None) -> None:
    """Save the current configuration to a file.
    
    Args:
        file_path: Path to save the configuration file (defaults to ~/.skwaq/config.json)
    """
    config = get_config()
    
    if file_path is None:
        # Use default configuration path
        file_path = Path.home() / ".skwaq" / "config.json"
    
    file_path = Path(file_path)
    file_path.parent.mkdir(parents=True, exist_ok=True)
    
    config.save_to_file(file_path)
    
    # Register or update file config source
    for source in _config_sources:
        if isinstance(source, FileConfigSource) and source.file_path == file_path:
            break
    else:
        # File source not found, register it
        register_config_source(FileConfigSource(file_path, auto_reload=True))
    
    logger.info(f"Saved configuration to: {file_path}")


def reset_config() -> None:
    """Reset configuration to defaults and remove all custom settings."""
    global _config, _config_sources
    
    with _config_lock:
        # Create a new default configuration
        default_config = Config(
            openai_api_key="",
            openai_org_id="",
        )
        
        # Update the global config
        _config = default_config
        
        # Remove all file sources
        _config_sources = [s for s in _config_sources if not isinstance(s, FileConfigSource)]
        
        # Delete user config file if it exists
        config_path = Path.home() / ".skwaq" / "config.json"
        if config_path.exists():
            try:
                config_path.unlink()
                logger.info(f"Deleted configuration file: {config_path}")
            except Exception as e:
                logger.warning(f"Failed to delete configuration file: {e}")
        
        logger.info("Configuration reset to defaults")

"""Configuration management for Skwaq.

This module provides configuration management functionality for the Skwaq
vulnerability assessment copilot.
"""
import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


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
    """

    openai_api_key: str
    openai_org_id: str
    openai_model: Optional[str] = None
    neo4j_uri: str = "bolt://localhost:7687"
    neo4j_user: str = "neo4j"
    neo4j_password: str = "skwaqdev"

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
        return cls(**config_data)

    @classmethod
    def from_env(cls) -> "Config":
        """Load configuration from environment variables.
        
        Returns:
            Config object with values from environment
        """
        return cls(
            openai_api_key=os.getenv("OPENAI_API_KEY", ""),
            openai_org_id=os.getenv("OPENAI_ORG_ID", ""),
            openai_model=os.getenv("OPENAI_MODEL"),
            neo4j_uri=os.getenv("NEO4J_URI", "bolt://localhost:7687"),
            neo4j_user=os.getenv("NEO4J_USER", "neo4j"),
            neo4j_password=os.getenv("NEO4J_PASSWORD", "skwaqdev"),
        )


# Global config instance
_config: Optional[Config] = None


def get_config() -> Config:
    """Get the global configuration instance.
    
    If no configuration has been loaded yet, attempts to load from environment
    variables first, then falls back to default configuration.
    
    Returns:
        The global Config instance
    """
    global _config
    if _config is None:
        try:
            _config = Config.from_env()
        except Exception:
            # Fall back to default configuration
            _config = Config(
                openai_api_key="",
                openai_org_id="",
            )
    return _config


def init_config(config: Config) -> None:
    """Initialize the global configuration with a specific config instance.
    
    Args:
        config: The configuration instance to use
    """
    global _config
    _config = config
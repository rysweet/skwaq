"""Tests for configuration management."""

import json
from pathlib import Path

import pytest

from skwaq.utils.config import Config


def test_config_initialization():
    """Test basic configuration initialization."""
    config = Config(
        openai_api_key="test-key",
        openai_org_id="test-org",
    )
    assert config.openai_api_key == "test-key"
    assert config.openai_org_id == "test-org"
    assert config.openai_model is None
    assert config.neo4j_uri == "bolt://localhost:7687"
    assert config.neo4j_user == "neo4j"
    assert config.neo4j_password == "skwaqdev"


def test_config_from_file(tmp_path):
    """Test loading configuration from file."""
    config_data = {
        "openai_api_key": "file-key",
        "openai_org_id": "file-org",
        "openai_model": "gpt-4",
        "neo4j_uri": "bolt://neo4j:7687",
        "neo4j_user": "test-user",
        "neo4j_password": "test-pass",
    }
    
    config_file = tmp_path / "config.json"
    with open(config_file, "w") as f:
        json.dump(config_data, f)
    
    config = Config.from_file(config_file)
    assert config.openai_api_key == "file-key"
    assert config.openai_org_id == "file-org"
    assert config.openai_model == "gpt-4"
    assert config.neo4j_uri == "bolt://neo4j:7687"
    assert config.neo4j_user == "test-user"
    assert config.neo4j_password == "test-pass"


def test_config_from_env(monkeypatch):
    """Test loading configuration from environment variables."""
    env_vars = {
        "OPENAI_API_KEY": "env-key",
        "OPENAI_ORG_ID": "env-org",
        "OPENAI_MODEL": "gpt-4-turbo",
        "NEO4J_URI": "bolt://testdb:7687",
        "NEO4J_USER": "env-user",
        "NEO4J_PASSWORD": "env-pass",
    }
    
    for key, value in env_vars.items():
        monkeypatch.setenv(key, value)
    
    config = Config.from_env()
    assert config.openai_api_key == "env-key"
    assert config.openai_org_id == "env-org"
    assert config.openai_model == "gpt-4-turbo"
    assert config.neo4j_uri == "bolt://testdb:7687"
    assert config.neo4j_user == "env-user"
    assert config.neo4j_password == "env-pass"


def test_config_from_file_missing():
    """Test error when configuration file is missing."""
    with pytest.raises(FileNotFoundError):
        Config.from_file(Path("nonexistent.json"))


def test_config_from_file_invalid(tmp_path):
    """Test error when configuration file is invalid JSON."""
    config_file = tmp_path / "invalid.json"
    config_file.write_text("{invalid json}")
    
    with pytest.raises(json.JSONDecodeError):
        Config.from_file(config_file)
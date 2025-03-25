"""Tests for Milestone F1: Project Setup and Environment."""

import os
import subprocess
from pathlib import Path

import pytest

from skwaq.utils.config import Config, get_config


def test_project_structure():
    """Test that all required project directories and files exist."""
    root = Path(__file__).parent.parent.parent

    # Check core directories
    assert (root / "skwaq").is_dir()
    assert (root / "tests").is_dir()
    assert (root / "docs").is_dir()
    assert (root / "scripts").is_dir()

    # Check core module structure
    assert (root / "skwaq/utils").is_dir()
    assert (root / "skwaq/db").is_dir()
    assert (root / "skwaq/core").is_dir()
    assert (root / "skwaq/cli").is_dir()
    assert (root / "skwaq/agents").is_dir()
    assert (root / "skwaq/ingestion").is_dir()
    assert (root / "skwaq/workflows").is_dir()

    # Check configuration files
    assert (root / "pyproject.toml").is_file()
    assert (root / ".pre-commit-config.yaml").is_file()
    assert (root / "docker-compose.yml").is_file()
    assert (root / "Dockerfile").is_file()


def test_infrastructure_scripts():
    """Test that infrastructure scripts are executable and properly configured."""
    root = Path(__file__).parent.parent.parent

    # Check Azure scripts
    azure_scripts = [
        "scripts/infrastructure/azure-auth.sh",
        "scripts/infrastructure/deploy-openai.sh",
        "scripts/infrastructure/verify-openai-models.sh",
    ]
    for script in azure_scripts:
        script_path = root / script
        assert script_path.is_file()
        assert os.access(script_path, os.X_OK), f"{script} is not executable"


def test_ci_scripts():
    """Test that CI scripts are executable and properly configured."""
    root = Path(__file__).parent.parent.parent

    # Check CI scripts
    ci_scripts = [
        "scripts/ci/run-local-ci.sh",
    ]
    for script in ci_scripts:
        script_path = root / script
        assert script_path.is_file()
        assert os.access(script_path, os.X_OK), f"{script} is not executable"


def test_development_environment():
    """Test that development environment setup script is executable and configured."""
    root = Path(__file__).parent.parent.parent
    setup_script = root / "scripts/setup/setup_dev_environment.sh"

    assert setup_script.is_file()
    assert os.access(setup_script, os.X_OK), "setup_dev_environment.sh is not executable"


def test_configuration_loading():
    """Test that configuration can be loaded from environment and file."""
    # Test environment configuration
    os.environ["OPENAI_API_KEY"] = "test-key"
    os.environ["OPENAI_ORG_ID"] = "test-org"

    config = Config.from_env()
    assert config.openai_api_key == "test-key"
    assert config.openai_org_id == "test-org"

    # Test global configuration
    global_config = get_config()
    assert isinstance(global_config, Config)


def test_docker_compose():
    """Test that Docker Compose configuration is valid."""
    root = Path(__file__).parent.parent.parent
    result = subprocess.run(
        ["docker", "compose", "config"],
        cwd=root,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, "Docker Compose configuration is invalid"


@pytest.mark.skipif(
    not os.path.exists("/usr/local/bin/act") and not os.path.exists("/usr/bin/act"),
    reason="act is not installed",
)
def test_github_actions():
    """Test that GitHub Actions workflows are valid."""
    root = Path(__file__).parent.parent.parent
    result = subprocess.run(
        ["act", "--dryrun"],
        cwd=root,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, "GitHub Actions workflows are invalid"

"""Installation management functionality for Skwaq.

This module provides functionality for managing installation processes,
including script generation, environment validation, and dependency management.
"""

import os
import sys
import platform
import subprocess
import pkg_resources
import shutil
from typing import Dict, Any, List, Optional, Tuple
from pathlib import Path

from skwaq.utils.config import get_config
from skwaq.utils.logging import get_logger

logger = get_logger(__name__)


class InstallationManager:
    """Manages the installation process for Skwaq."""
    
    def __init__(self) -> None:
        """Initialize the InstallationManager."""
        self.config = get_config()
        
    def get_requirements(self) -> Dict[str, List[str]]:
        """Get the requirement groups for installation.
        
        Returns:
            A dictionary containing requirement groups.
        """
        # Try to parse requirements from pyproject.toml
        try:
            import toml
            project_root = Path(__file__).parent.parent.parent
            pyproject_path = project_root / "pyproject.toml"
            pyproject_data = toml.load(str(pyproject_path))
            
            # Get dependencies from poetry section
            poetry_deps = pyproject_data.get("tool", {}).get("poetry", {}).get("dependencies", {})
            core_deps = []
            for dep_name, dep_spec in poetry_deps.items():
                if dep_name != "python" and not isinstance(dep_spec, dict):
                    core_deps.append(f"{dep_name}{dep_spec}")
            
            # Get dev dependencies
            dev_deps = []
            dev_group = pyproject_data.get("tool", {}).get("poetry", {}).get("group", {}).get("dev", {})
            if not dev_group:  # Handle older poetry format
                dev_group = pyproject_data.get("tool", {}).get("poetry", {}).get("dev-dependencies", {})
            
            if isinstance(dev_group, dict) and "dependencies" in dev_group:
                for dep_name, dep_spec in dev_group["dependencies"].items():
                    if not isinstance(dep_spec, dict):
                        dev_deps.append(f"{dep_name}{dep_spec}")
            
            # Get docs dependencies
            docs_deps = []
            docs_group = pyproject_data.get("tool", {}).get("poetry", {}).get("group", {}).get("docs", {})
            
            if isinstance(docs_group, dict) and "dependencies" in docs_group:
                for dep_name, dep_spec in docs_group["dependencies"].items():
                    if not isinstance(dep_spec, dict):
                        docs_deps.append(f"{dep_name}{dep_spec}")
            
            return {
                "core": core_deps,
                "dev": dev_deps,
                "docs": docs_deps,
            }
            
        except Exception as e:
            logger.error(f"Error getting requirements from pyproject.toml: {e}")
            
            # Fallback to hardcoded minimum requirements
            return {
                "core": [
                    "neo4j>=5.15.0",
                    "rich>=13.7.0",
                    "click>=8.1.7",
                    "pydantic>=2.5.2",
                    "autogen-core>=0.2.2",
                    "loguru>=0.7.2",
                    "typer>=0.9.0",
                    "protobuf>=4.24.4",
                    "azure-identity>=1.15.0",
                    "openai>=1.2.4",
                    "pygithub>=2.1.1",
                ],
                "dev": [
                    "pytest>=7.4.3",
                    "pytest-cov>=4.1.0",
                    "black>=23.11.0",
                    "mypy>=1.7.0",
                ],
                "docs": [
                    "sphinx>=7.2.6",
                    "sphinx-rtd-theme>=1.3.0",
                ],
            }

    def generate_installation_script(self, platform: str = "unix", include_dev: bool = False,
                                    include_docs: bool = False) -> str:
        """Generate an installation script for the specified platform.
        
        Args:
            platform: The target platform ('unix', 'windows').
            include_dev: Whether to include development dependencies.
            include_docs: Whether to include documentation dependencies.
            
        Returns:
            The generated installation script as a string.
        """
        requirements = self.get_requirements()
        
        # Get Python executable - use 'python3' for Unix, 'python' for Windows
        python_cmd = "python3" if platform == "unix" else "python"
        
        if platform == "unix":
            script = "#!/bin/bash\n\n"
            script += "set -e\n\n"
            script += "echo \"Installing Skwaq Vulnerability Assessment Copilot...\"\n\n"
            
            # Check for Python
            script += "# Check for Python installation\n"
            script += "if ! command -v python3 &> /dev/null; then\n"
            script += "    echo \"Python 3.10 or higher is required but not found.\"\n"
            script += "    echo \"Please install Python 3.10+ and try again.\"\n"
            script += "    exit 1\n"
            script += "fi\n\n"
            
            # Check Python version
            script += "# Check Python version\n"
            script += "PYTHON_VERSION=$(python3 --version | cut -d' ' -f2)\n"
            script += "PYTHON_MAJOR=$(echo \"$PYTHON_VERSION\" | cut -d'.' -f1)\n"
            script += "PYTHON_MINOR=$(echo \"$PYTHON_VERSION\" | cut -d'.' -f2)\n"
            script += "if [ \"$PYTHON_MAJOR\" -lt 3 ] || ([ \"$PYTHON_MAJOR\" -eq 3 ] && [ \"$PYTHON_MINOR\" -lt 10 ]); then\n"
            script += "    echo \"Python 3.10 or higher is required. Found: $PYTHON_VERSION\"\n"
            script += "    echo \"Please upgrade your Python installation and try again.\"\n"
            script += "    exit 1\n"
            script += "fi\n\n"
            
            # Check for Neo4j
            script += "# Check for Neo4j\n"
            script += "echo \"Checking for Neo4j...\"\n"
            script += "if command -v docker &> /dev/null; then\n"
            script += "    echo \"Docker found, will use containerized Neo4j.\"\n"
            script += "    docker pull neo4j:latest\n"
            script += "else\n"
            script += "    echo \"Docker not found. Neo4j will need to be installed manually.\"\n"
            script += "    echo \"See https://neo4j.com/docs/operations-manual/current/installation/\"\n"
            script += "fi\n\n"
            
            # Create virtual environment
            script += "# Create virtual environment\n"
            script += "echo \"Creating virtual environment...\"\n"
            script += "python3 -m venv .venv\n"
            script += "source .venv/bin/activate\n\n"
            
            # Upgrade pip
            script += "# Upgrade pip\n"
            script += "pip install --upgrade pip\n\n"
            
            # Install dependencies
            script += "# Install dependencies\n"
            if include_dev:
                script += "pip install .[dev]\n"
            elif include_docs:
                script += "pip install .[docs]\n"
            else:
                script += "pip install .\n"
            
            # Start services
            script += "\n# Start services\n"
            script += "echo \"Starting Neo4j service...\"\n"
            script += "if command -v docker &> /dev/null; then\n"
            script += "    docker run -d --name skwaq-neo4j \\\n"
            script += "        -p 7474:7474 -p 7687:7687 \\\n"
            script += "        -e NEO4J_AUTH=neo4j/skwaqdev \\\n"
            script += "        -e NEO4J_dbms_memory_pagecache_size=1G \\\n"
            script += "        -e NEO4J_dbms_memory_heap_initial__size=1G \\\n"
            script += "        -e NEO4J_dbms_memory_heap_max__size=2G \\\n"
            script += "        neo4j:latest\n"
            script += "fi\n\n"
            
            # Configuration
            script += "# Create default configuration\n"
            script += "mkdir -p ~/.skwaq\n"
            script += "cat > ~/.skwaq/config.json << EOF\n"
            script += "{\n"
            script += "    \"database\": {\n"
            script += "        \"uri\": \"bolt://localhost:7687\",\n"
            script += "        \"user\": \"neo4j\",\n"
            script += "        \"password\": \"skwaqdev\"\n"
            script += "    },\n"
            script += "    \"openai\": {\n"
            script += "        \"provider\": \"azure\",\n"
            script += "        \"api_key\": \"\",\n"
            script += "        \"endpoint\": \"\"\n"
            script += "    }\n"
            script += "}\n"
            script += "EOF\n\n"
            
            # Finalize
            script += "echo \"Installation completed successfully!\"\n"
            script += "echo \"To use Skwaq, activate the virtual environment with:\"\n"
            script += "echo \"    source .venv/bin/activate\"\n"
            script += "echo \"and run the CLI with:\"\n"
            script += "echo \"    skwaq --help\"\n\n"
            script += "echo \"Please edit ~/.skwaq/config.json to configure your OpenAI API settings.\"\n"
            
        else:  # Windows
            script = "@echo off\n\n"
            script += "echo Installing Skwaq Vulnerability Assessment Copilot...\n\n"
            
            # Check for Python
            script += ":: Check for Python installation\n"
            script += "where python >nul 2>&1\n"
            script += "if %ERRORLEVEL% neq 0 (\n"
            script += "    echo Python 3.10 or higher is required but not found.\n"
            script += "    echo Please install Python 3.10+ and try again.\n"
            script += "    exit /b 1\n"
            script += ")\n\n"
            
            # Check Python version
            script += ":: Check Python version\n"
            script += "for /f \"tokens=2\" %%i in ('python --version 2^>^&1') do set PYTHON_VERSION=%%i\n"
            script += "for /f \"tokens=1,2 delims=.\" %%a in (\"%PYTHON_VERSION%\") do (\n"
            script += "    set PYTHON_MAJOR=%%a\n"
            script += "    set PYTHON_MINOR=%%b\n"
            script += ")\n"
            script += "if %PYTHON_MAJOR% LSS 3 (\n"
            script += "    echo Python 3.10 or higher is required. Found: %PYTHON_VERSION%\n"
            script += "    echo Please upgrade your Python installation and try again.\n"
            script += "    exit /b 1\n"
            script += ")\n"
            script += "if %PYTHON_MAJOR% EQU 3 (\n"
            script += "    if %PYTHON_MINOR% LSS 10 (\n"
            script += "        echo Python 3.10 or higher is required. Found: %PYTHON_VERSION%\n"
            script += "        echo Please upgrade your Python installation and try again.\n"
            script += "        exit /b 1\n"
            script += "    )\n"
            script += ")\n\n"
            
            # Check for Neo4j
            script += ":: Check for Neo4j\n"
            script += "echo Checking for Neo4j...\n"
            script += "where docker >nul 2>&1\n"
            script += "if %ERRORLEVEL% equ 0 (\n"
            script += "    echo Docker found, will use containerized Neo4j.\n"
            script += "    docker pull neo4j:latest\n"
            script += ") else (\n"
            script += "    echo Docker not found. Neo4j will need to be installed manually.\n"
            script += "    echo See https://neo4j.com/docs/operations-manual/current/installation/\n"
            script += ")\n\n"
            
            # Create virtual environment
            script += ":: Create virtual environment\n"
            script += "echo Creating virtual environment...\n"
            script += "python -m venv .venv\n"
            script += "call .venv\\Scripts\\activate.bat\n\n"
            
            # Upgrade pip
            script += ":: Upgrade pip\n"
            script += "pip install --upgrade pip\n\n"
            
            # Install dependencies
            script += ":: Install dependencies\n"
            if include_dev:
                script += "pip install .[dev]\n"
            elif include_docs:
                script += "pip install .[docs]\n"
            else:
                script += "pip install .\n"
            
            # Start services
            script += "\n:: Start services\n"
            script += "echo Starting Neo4j service...\n"
            script += "where docker >nul 2>&1\n"
            script += "if %ERRORLEVEL% equ 0 (\n"
            script += "    docker run -d --name skwaq-neo4j ^\n"
            script += "        -p 7474:7474 -p 7687:7687 ^\n"
            script += "        -e NEO4J_AUTH=neo4j/skwaqdev ^\n"
            script += "        -e NEO4J_dbms_memory_pagecache_size=1G ^\n"
            script += "        -e NEO4J_dbms_memory_heap_initial__size=1G ^\n"
            script += "        -e NEO4J_dbms_memory_heap_max__size=2G ^\n"
            script += "        neo4j:latest\n"
            script += ")\n\n"
            
            # Configuration
            script += ":: Create default configuration\n"
            script += "if not exist \"%USERPROFILE%\\.skwaq\" mkdir \"%USERPROFILE%\\.skwaq\"\n"
            script += "(\n"
            script += "    echo {\n"
            script += "    echo     \"database\": {\n"
            script += "    echo         \"uri\": \"bolt://localhost:7687\",\n"
            script += "    echo         \"user\": \"neo4j\",\n"
            script += "    echo         \"password\": \"skwaqdev\"\n"
            script += "    echo     },\n"
            script += "    echo     \"openai\": {\n"
            script += "    echo         \"provider\": \"azure\",\n"
            script += "    echo         \"api_key\": \"\",\n"
            script += "    echo         \"endpoint\": \"\"\n"
            script += "    echo     }\n"
            script += "    echo }\n"
            script += ") > \"%USERPROFILE%\\.skwaq\\config.json\"\n\n"
            
            # Finalize
            script += "echo Installation completed successfully!\n"
            script += "echo To use Skwaq, activate the virtual environment with:\n"
            script += "echo     .venv\\Scripts\\activate.bat\n"
            script += "echo and run the CLI with:\n"
            script += "echo     skwaq --help\n\n"
            script += "echo Please edit %%USERPROFILE%%\\.skwaq\\config.json to configure your OpenAI API settings.\n"
        
        return script
        
    def validate_environment(self) -> Dict[str, Any]:
        """Validate the current environment for running Skwaq.
        
        Returns:
            A dictionary containing validation results.
        """
        result = {
            "python_version": platform.python_version(),
            "os_info": {
                "system": platform.system(),
                "release": platform.release(),
                "version": platform.version(),
            },
            "dependencies": {},
            "neo4j": False,
            "docker": False,
            "is_valid": False,
            "issues": [],
        }
        
        # Check Python version
        python_version = tuple(map(int, platform.python_version_tuple()))
        if python_version < (3, 10):
            result["issues"].append(f"Python 3.10+ required, found {platform.python_version()}")
        
        # Check dependencies
        requirements = self.get_requirements()
        missing_deps = []
        
        try:
            installed_packages = {pkg.key: pkg.version for pkg in pkg_resources.working_set}
            for req in requirements["core"]:
                # Extract package name from requirement string
                pkg_name = req.split(">=")[0].split("==")[0].lower()
                
                if pkg_name not in installed_packages:
                    missing_deps.append(pkg_name)
                
            result["dependencies"] = {
                "installed": installed_packages,
                "missing": missing_deps,
            }
            
            if missing_deps:
                result["issues"].append(f"Missing dependencies: {', '.join(missing_deps)}")
        except Exception as e:
            logger.error(f"Error checking dependencies: {e}")
            result["issues"].append(f"Failed to check dependencies: {e}")
        
        # Check for Neo4j
        try:
            # Check if Neo4j is running via docker
            if shutil.which("docker"):
                result["docker"] = True
                
                # Check for running Neo4j container
                docker_ps = subprocess.run(
                    ["docker", "ps", "--filter", "ancestor=neo4j", "--format", "{{.Names}}"],
                    check=True,
                    capture_output=True,
                    text=True,
                )
                
                if docker_ps.stdout.strip():
                    result["neo4j"] = True
                else:
                    # Check for direct Neo4j installation
                    if shutil.which("neo4j"):
                        result["neo4j"] = True
            elif shutil.which("neo4j"):
                result["neo4j"] = True
                
            if not result["neo4j"]:
                result["issues"].append("Neo4j not detected in environment")
        except Exception as e:
            logger.error(f"Error checking for Neo4j: {e}")
            result["issues"].append(f"Failed to check for Neo4j: {e}")
        
        # Check for config directory and file
        config_dir = Path.home() / ".skwaq"
        config_file = config_dir / "config.json"
        
        if not config_dir.exists():
            result["issues"].append("Configuration directory not found")
        elif not config_file.exists():
            result["issues"].append("Configuration file not found")
        
        # Set overall validation result
        result["is_valid"] = len(result["issues"]) == 0
        
        return result
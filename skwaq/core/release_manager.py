"""Release management functionality for Skwaq.

This module provides functionality for managing releases, including version management,
release notes generation, package creation, and update mechanisms.
"""

import os
import shutil
import subprocess
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional

from skwaq.utils.config import get_config
from skwaq.utils.logging import get_logger

logger = get_logger(__name__)

# Singleton instance
_release_manager_instance = None


def get_release_manager() -> "ReleaseManager":
    """Get the singleton ReleaseManager instance.

    Returns:
        The ReleaseManager instance.
    """
    global _release_manager_instance
    if _release_manager_instance is None:
        _release_manager_instance = ReleaseManager()
    return _release_manager_instance


def create_package(output_dir: Optional[str] = None) -> str:
    """Create a Python package using setuptools/poetry.

    Args:
        output_dir: Optional directory where the package will be created.
            If not provided, a temporary directory will be used.

    Returns:
        The path to the created package.
    """
    # Get the project root directory
    project_root = Path(__file__).parent.parent.parent

    # If no output directory is specified, create a temporary one
    if output_dir is None:
        output_dir = tempfile.mkdtemp()
    else:
        os.makedirs(output_dir, exist_ok=True)

    # Run poetry build to create the package
    try:
        subprocess.run(
            ["poetry", "build"],
            cwd=str(project_root),
            check=True,
            capture_output=True,
        )

        # Copy the generated package to the output directory
        dist_dir = project_root / "dist"
        for file_path in dist_dir.glob("*.tar.gz"):
            dest_path = Path(output_dir) / file_path.name
            shutil.copy2(file_path, dest_path)
            return str(dest_path)

        # If no .tar.gz file is found, check for .whl file
        for file_path in dist_dir.glob("*.whl"):
            dest_path = Path(output_dir) / file_path.name
            shutil.copy2(file_path, dest_path)
            return str(dest_path)

        raise FileNotFoundError("No package files were created in the dist directory")

    except subprocess.CalledProcessError as e:
        logger.error(f"Error building package: {e}")
        logger.debug(f"STDOUT: {e.stdout.decode()}")
        logger.debug(f"STDERR: {e.stderr.decode()}")
        raise RuntimeError(f"Failed to build package: {e}") from e


def check_remote_version() -> str:
    """Check the latest version available on PyPI or GitHub.

    Returns:
        The latest version string.
    """
    # For the initial implementation, this would typically use requests to query
    # PyPI or GitHub API, but we'll return a mock value for now
    try:
        # In a real implementation, we would use requests to query PyPI or GitHub
        import requests

        response = requests.get(
            "https://api.github.com/repos/rysweet/skwaq/releases/latest"
        )
        if response.status_code == 200:
            data = response.json()
            # Remove 'v' prefix if present
            version = data.get("tag_name", "").lstrip("v")
            return version
        else:
            # If the request fails, return the current version
            from skwaq import __version__

            return __version__
    except Exception as e:
        logger.error(f"Error checking for remote version: {e}")
        # If anything fails, return the current version
        from skwaq import __version__

        return __version__


class ReleaseManager:
    """Manages the release process for Skwaq."""

    def __init__(self) -> None:
        """Initialize the ReleaseManager."""
        self.config = get_config()

    def get_version(self) -> str:
        """Get the current version of the Skwaq package.

        Returns:
            The version string in format X.Y.Z.
        """
        try:
            # Import the version from the package
            from skwaq import __version__

            return __version__
        except ImportError:
            logger.error("Failed to import version from skwaq package")
            # Fallback to the version in pyproject.toml
            try:
                import toml

                project_root = Path(__file__).parent.parent.parent
                pyproject_path = project_root / "pyproject.toml"
                pyproject_data = toml.load(str(pyproject_path))
                return (
                    pyproject_data.get("tool", {})
                    .get("poetry", {})
                    .get("version", "0.0.0")
                )
            except Exception as e:
                logger.error(f"Error reading version from pyproject.toml: {e}")
                return "0.0.0"

    def create_release_package(self, output_dir: Optional[str] = None) -> str:
        """Create a release package.

        Args:
            output_dir: Optional directory where the package will be created.
                If not provided, a temporary directory will be used.

        Returns:
            The path to the created package.
        """
        return create_package(output_dir)

    def generate_release_notes(self) -> str:
        """Generate release notes for the current version.

        Returns:
            A formatted string containing the release notes.
        """
        version = self.get_version()
        current_date = datetime.now().strftime("%Y-%m-%d")

        # Get recent changes from git log
        try:
            project_root = Path(__file__).parent.parent.parent
            result = subprocess.run(
                ["git", "log", "--pretty=format:%s", "-n", "20"],
                cwd=str(project_root),
                capture_output=True,
                text=True,
                check=True,
            )

            # Parse commit messages
            commits = result.stdout.strip().split("\n")
            features = []
            bugfixes = []
            other = []

            for commit in commits:
                if commit.lower().startswith(("add", "feature", "feat", "implement")):
                    features.append(commit)
                elif commit.lower().startswith(("fix", "bug", "correct", "resolve")):
                    bugfixes.append(commit)
                else:
                    other.append(commit)

            # Format release notes
            notes = f"# Skwaq {version} Release Notes ({current_date})\n\n"

            if features:
                notes += "## Features\n\n"
                for feature in features:
                    notes += f"- {feature}\n"
                notes += "\n"

            if bugfixes:
                notes += "## Bug Fixes\n\n"
                for bugfix in bugfixes:
                    notes += f"- {bugfix}\n"
                notes += "\n"

            if other:
                notes += "## Other Changes\n\n"
                for change in other:
                    notes += f"- {change}\n"
                notes += "\n"

            notes += "## Installation\n\n"
            notes += "```bash\n"
            notes += "pip install skwaq==" + version + "\n"
            notes += "```\n\n"

            notes += "## Documentation\n\n"
            notes += "For full documentation, visit the project documentation site.\n\n"

            return notes

        except subprocess.CalledProcessError as e:
            logger.error(f"Error generating release notes: {e}")
            # Fallback to a basic template
            notes = f"# Skwaq {version} Release Notes ({current_date})\n\n"
            notes += "## Features\n\n- Various new features\n\n"
            notes += "## Bug Fixes\n\n- Various bug fixes\n\n"
            return notes

    def check_for_updates(self) -> Dict[str, Any]:
        """Check if a newer version of the package is available.

        Returns:
            A dictionary with update information including:
                available (bool): Whether an update is available.
                current_version (str): The currently installed version.
                latest_version (str): The latest available version.
        """
        current_version = self.get_version()
        latest_version = check_remote_version()

        # Parse version strings into components
        current_parts = [int(p) for p in current_version.split(".")]
        latest_parts = [int(p) for p in latest_version.split(".")]

        # Compare versions
        update_available = False
        for i in range(min(len(current_parts), len(latest_parts))):
            if latest_parts[i] > current_parts[i]:
                update_available = True
                break
            elif latest_parts[i] < current_parts[i]:
                break

        # If latest_version has more components than current_version and all preceding components are equal
        if not update_available and len(latest_parts) > len(current_parts):
            if all(
                current_parts[i] == latest_parts[i] for i in range(len(current_parts))
            ):
                update_available = True

        return {
            "available": update_available,
            "current_version": current_version,
            "latest_version": latest_version,
        }

    def apply_update(self, version: Optional[str] = None) -> bool:
        """Apply an update to the specified version.

        Args:
            version: The version to update to. If not provided, updates to the latest version.

        Returns:
            True if the update was successful, False otherwise.
        """
        try:
            if version is None:
                version_spec = ""  # Latest version
            else:
                version_spec = f"=={version}"

            # Use pip to upgrade the package
            subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "pip",
                    "install",
                    "--upgrade",
                    f"skwaq{version_spec}",
                ],
                check=True,
                capture_output=True,
            )

            return True
        except Exception as e:
            logger.error(f"Error applying update: {e}")
            return False


# Import at the end to avoid circular imports
import sys

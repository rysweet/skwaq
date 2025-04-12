"""Utilities for ensuring the database is initialized and running.

This module provides functions to verify Neo4j is running and properly initialized
before executing any database operations.
"""

import subprocess
import sys
from pathlib import Path

from skwaq.utils.logging import get_logger

logger = get_logger(__name__)


def ensure_neo4j_running(use_mock_data=False, clear_data=False):
    """Ensure Neo4j is running with the proper schema.

    Args:
        use_mock_data: Whether to seed the database with mock data
        clear_data: Whether to clear existing data before initialization

    Returns:
        bool: True if Neo4j is running and initialized, False otherwise
    """
    # Get path to the ensure_neo4j.py script
    script_dir = Path(__file__).resolve().parent.parent.parent
    ensure_script = script_dir / "scripts" / "db" / "ensure_neo4j.py"

    if not ensure_script.exists():
        logger.error(f"Neo4j initialization script not found at {ensure_script}")
        return False

    # Build command
    cmd = [sys.executable, str(ensure_script)]

    if use_mock_data:
        cmd.append("--seed")

    if clear_data:
        cmd.append("--clear")

    # Run the script
    try:
        logger.info("Ensuring Neo4j is running...")
        result = subprocess.run(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False
        )

        if result.returncode != 0:
            logger.error(f"Failed to ensure Neo4j is running: {result.stderr}")
            return False

        logger.info("Neo4j is running and initialized")
        return True
    except Exception as e:
        logger.error(f"Error ensuring Neo4j is running: {e}")
        return False

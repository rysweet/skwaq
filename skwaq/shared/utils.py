"""Shared utilities for the Skwaq vulnerability assessment copilot.

This module provides common utility functions used across the application.
"""

from typing import Dict, List, Any, Optional, Set, Callable, TypeVar, Awaitable
from pathlib import Path
from datetime import datetime
import re
import asyncio
import functools
import logging

T = TypeVar('T')
logger = logging.getLogger(__name__)


def get_timestamp() -> str:
    """Get the current timestamp as an ISO 8601 string.
    
    Returns:
        Timestamp string
    """
    return datetime.utcnow().isoformat()


def detect_language(file_path: Path) -> Optional[str]:
    """Detect the programming language of a file based on its extension.
    
    Args:
        file_path: Path to the file
    
    Returns:
        Language name or None if unknown
    """
    ext = file_path.suffix.lower()
    
    # Map of file extensions to languages
    language_map = {
        ".py": "Python",
        ".js": "JavaScript",
        ".ts": "TypeScript",
        ".jsx": "JavaScript/React",
        ".tsx": "TypeScript/React",
        ".java": "Java",
        ".c": "C",
        ".cpp": "C++",
        ".h": "C/C++ Header",
        ".hpp": "C++ Header",
        ".cs": "C#",
        ".go": "Go",
        ".rb": "Ruby",
        ".php": "PHP",
        ".swift": "Swift",
        ".kt": "Kotlin",
        ".rs": "Rust",
        ".sh": "Shell",
        ".bat": "Batch",
        ".ps1": "PowerShell",
        ".sql": "SQL",
        ".html": "HTML",
        ".css": "CSS",
        ".scss": "SCSS",
        ".xml": "XML",
        ".json": "JSON",
        ".yaml": "YAML",
        ".yml": "YAML",
        ".md": "Markdown",
        ".r": "R",
        ".scala": "Scala",
        ".groovy": "Groovy",
        ".pl": "Perl",
        ".lua": "Lua",
        ".m": "Objective-C",
        ".mm": "Objective-C++",
    }
    
    return language_map.get(ext)


async def safe_run(func: Callable[..., Awaitable[T]], *args: Any, **kwargs: Any) -> Optional[T]:
    """Safely run an async function and catch exceptions.
    
    Args:
        func: The async function to run
        *args: Positional arguments to pass to the function
        **kwargs: Keyword arguments to pass to the function
        
    Returns:
        The result of the function call, or None if an exception was raised
    """
    try:
        return await func(*args, **kwargs)
    except Exception as e:
        logger.error(f"Error running {func.__name__}: {e}")
        return None


def is_code_file(file_path: Path) -> bool:
    """Check if a file is a code file that should be analyzed.
    
    Args:
        file_path: Path to the file
    
    Returns:
        True if the file is a code file, False otherwise
    """
    # Known code file extensions
    code_extensions = {
        ".py",
        ".js",
        ".ts",
        ".jsx",
        ".tsx",
        ".java",
        ".c",
        ".cpp",
        ".h",
        ".hpp",
        ".cs",
        ".go",
        ".rb",
        ".php",
        ".swift",
        ".kt",
        ".rs",
        ".sh",
        ".bat",
        ".ps1",
        ".sql",
        ".html",
        ".css",
        ".scss",
        ".xml",
        ".json",
        ".yaml",
        ".yml",
        ".r",
        ".scala",
        ".groovy",
        ".pl",
        ".lua",
        ".m",
        ".mm",
    }
    
    # Check extension
    return file_path.suffix.lower() in code_extensions


def normalize_language(language: str) -> str:
    """Normalize language name for consistent lookup.
    
    Args:
        language: Language name to normalize
        
    Returns:
        Normalized language name
    """
    # Handle common language variants
    if language in ("JavaScript", "TypeScript", "JS", "TS"):
        return "JavaScript"
    elif language in ("C#", "CSharp", "C Sharp"):
        return "C#"
    elif "Python" in language:
        return "Python"
    elif "Java" in language and "Script" not in language:
        return "Java"
    elif "PHP" in language:
        return "PHP"
    
    return language
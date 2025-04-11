"""Abstract summarizer interfaces and registration for code ingestion.

This module provides the base classes and registration system for code summarizers
used in the ingestion process.
"""

import importlib
from abc import ABC, abstractmethod
from typing import Dict, List, Any, Optional, Type

from skwaq.utils.logging import get_logger

logger = get_logger(__name__)

# Registry of available summarizers
_summarizer_registry: Dict[str, Type["CodeSummarizer"]] = {}


class CodeSummarizer(ABC):
    """Abstract base class for code summarizers.

    Code summarizers generate natural language descriptions of code
    that can be stored in the graph database.
    """

    @abstractmethod
    def configure(self, **kwargs) -> None:
        """Configure the summarizer with additional parameters.

        Args:
            **kwargs: Configuration parameters
        """
        pass

    @abstractmethod
    async def summarize_files(
        self, file_nodes: List[Dict[str, Any]], fs: Any, repo_node_id: int
    ) -> Dict[str, Any]:
        """Generate summaries for a list of files.

        Args:
            file_nodes: List of file nodes with IDs and paths
            fs: Filesystem interface for reading file contents
            repo_node_id: ID of the repository node

        Returns:
            Dictionary with summarization results and statistics
        """
        pass


def register_summarizer(name: str, summarizer_class: Type[CodeSummarizer]) -> None:
    """Register a summarizer in the summarizer registry.

    Args:
        name: Name of the summarizer
        summarizer_class: Summarizer class to register
    """
    global _summarizer_registry
    _summarizer_registry[name] = summarizer_class
    logger.debug(f"Registered summarizer: {name}")


def get_summarizer(name: str) -> Optional[CodeSummarizer]:
    """Get a summarizer instance by name.

    Args:
        name: Name of the summarizer

    Returns:
        Summarizer instance or None if not found
    """
    global _summarizer_registry
    if name not in _summarizer_registry:
        logger.warning(f"Summarizer not found: {name}")
        return None

    return _summarizer_registry[name]()


def register_summarizers() -> None:
    """Register all available summarizers.

    This function loads and registers all summarizer implementations.
    """
    # Import standard summarizers
    try:
        from .llm_summarizer import LLMSummarizer

        register_summarizer("llm", LLMSummarizer)
    except ImportError as e:
        logger.warning(f"Could not register LLM summarizer: {e}")

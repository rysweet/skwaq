"""Abstract parser interfaces and registration for code ingestion.

This module provides the base classes and registration system for code parsers
used in the ingestion process.
"""

import importlib
from abc import ABC, abstractmethod
from typing import Dict, List, Any, Optional, Type

from skwaq.utils.logging import get_logger

logger = get_logger(__name__)

# Registry of available parsers
_parser_registry: Dict[str, Type["CodeParser"]] = {}


class CodeParser(ABC):
    """Abstract base class for code parsers.

    Code parsers analyze a codebase and produce a structured representation
    that can be stored in the graph database.
    """

    @abstractmethod
    async def parse(self, codebase_path: str) -> Dict[str, Any]:
        """Parse a codebase and create a graph representation.

        Args:
            codebase_path: Path to the codebase to parse

        Returns:
            Dictionary with parsing results and statistics
        """
        pass

    @abstractmethod
    async def connect_ast_to_files(
        self, repo_node_id: int, file_path_mapping: Dict[str, int]
    ) -> None:
        """Connect AST nodes to their corresponding file nodes.

        Args:
            repo_node_id: ID of the repository node
            file_path_mapping: Mapping of file paths to file node IDs
        """
        pass


def register_parser(name: str, parser_class: Type[CodeParser]) -> None:
    """Register a parser in the parser registry.

    Args:
        name: Name of the parser
        parser_class: Parser class to register
    """
    global _parser_registry
    _parser_registry[name] = parser_class
    logger.debug(f"Registered parser: {name}")


def get_parser(name: str) -> Optional[CodeParser]:
    """Get a parser instance by name.

    Args:
        name: Name of the parser

    Returns:
        Parser instance or None if not found
    """
    global _parser_registry
    if name not in _parser_registry:
        logger.warning(f"Parser not found: {name}")
        return None

    return _parser_registry[name]()


def register_parsers() -> None:
    """Register all available parsers.

    This function loads and registers all parser implementations.
    """
    # Import standard parsers
    try:
        from .blarify_parser import BlarifyParser

        register_parser("blarify", BlarifyParser)
    except ImportError as e:
        logger.warning(f"Could not register Blarify parser: {e}")

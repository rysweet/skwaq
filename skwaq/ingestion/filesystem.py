"""Filesystem handling for code ingestion.

This module provides classes for working with filesystems during the ingestion process.
"""

import mimetypes
import os
from typing import Any, Dict, List, Optional

# Try to import python-magic for better MIME type detection
try:
    import magic

    HAS_MAGIC = True
except ImportError:
    HAS_MAGIC = False

from skwaq.db.neo4j_connector import Neo4jConnector
from skwaq.db.schema import NodeLabels, RelationshipTypes
from skwaq.utils.logging import get_logger

logger = get_logger(__name__)


class CodebaseFileSystem:
    """Handles filesystem operations for a codebase.

    This class provides methods to interact with the codebase filesystem,
    extracting metadata and tracking file information.
    """

    def __init__(self, root_path: str):
        """Initialize the filesystem handler.

        Args:
            root_path: Root directory of the codebase
        """
        self.root_path = os.path.abspath(root_path)
        self._files_cache: List[str] = []
        self._dirs_cache: List[str] = []

        # Initialize magic for mime type detection if available
        self._mime_magic = None
        if HAS_MAGIC:
            try:
                self._mime_magic = magic.Magic(mime=True)
            except Exception as e:
                logger.warning(
                    f"Failed to initialize magic for MIME type detection: {e}"
                )

        # Common extensions to ignore
        self._ignore_extensions = {
            ".pyc",
            ".pyo",
            ".pyd",
            ".obj",
            ".o",
            ".a",
            ".lib",
            ".so",
            ".dll",
            ".exe",
            ".bin",
            ".dat",
            ".db",
            ".sqlite",
            ".sqlite3",
            ".pickle",
            ".pkl",
            ".jpg",
            ".jpeg",
            ".png",
            ".gif",
            ".bmp",
            ".tiff",
            ".ico",
            ".svg",
            ".pdf",
            ".doc",
            ".docx",
            ".ppt",
            ".pptx",
            ".xls",
            ".xlsx",
            ".zip",
            ".tar",
            ".gz",
            ".bz2",
            ".7z",
            ".rar",
        }

        # Common directories to ignore
        self._ignore_dirs = {
            ".git",
            ".svn",
            ".hg",
            "__pycache__",
            "node_modules",
            "venv",
            ".env",
            ".venv",
            "env",
            "virtualenv",
            ".virtualenv",
            "build",
            "dist",
            "target",
            "bin",
            ".idea",
            ".vscode",
            ".vs",
            "tmp",
        }

    def get_relative_path(self, path: str) -> str:
        """Get the path relative to the root directory.

        Args:
            path: Absolute path

        Returns:
            Relative path from root directory
        """
        return os.path.relpath(path, self.root_path)

    def get_all_files(self) -> List[str]:
        """Get all files in the codebase, excluding ignored files.

        Returns:
            List of absolute file paths
        """
        if self._files_cache:
            return self._files_cache

        result = []

        for root, dirs, files in os.walk(self.root_path):
            # Skip ignored directories
            dirs[:] = [d for d in dirs if d not in self._ignore_dirs]

            for file in files:
                file_path = os.path.join(root, file)
                _, ext = os.path.splitext(file_path)

                # Skip ignored extensions
                if ext.lower() in self._ignore_extensions:
                    continue

                result.append(file_path)

        self._files_cache = result
        return result

    def get_all_dirs(self) -> List[str]:
        """Get all directories in the codebase, excluding ignored directories.

        Returns:
            List of absolute directory paths
        """
        if self._dirs_cache:
            return self._dirs_cache

        result = []

        for root, dirs, _ in os.walk(self.root_path):
            # Skip ignored directories
            filtered_dirs = [d for d in dirs if d not in self._ignore_dirs]
            dirs[:] = filtered_dirs

            # Add the current directory
            result.append(root)

            # Add all subdirectories
            for dir_name in filtered_dirs:
                dir_path = os.path.join(root, dir_name)
                result.append(dir_path)

        self._dirs_cache = result
        return result

    def get_file_info(self, file_path: str) -> Dict[str, Any]:
        """Get metadata about a file.

        Args:
            file_path: Path to the file

        Returns:
            Dictionary with file metadata
        """
        _, ext = os.path.splitext(file_path)

        # Infer language from extension
        language = self._get_language_from_extension(ext)

        # Get file size
        try:
            size = os.path.getsize(file_path)
        except (OSError, IOError):
            size = 0

        # Get MIME type
        mime_type = "application/octet-stream"
        try:
            if self._mime_magic:
                mime_type = self._mime_magic.from_file(file_path)
            else:
                mime_type = (
                    mimetypes.guess_type(file_path)[0] or "application/octet-stream"
                )
        except Exception:
            # Fallback to mimetypes if magic fails
            mime_type = mimetypes.guess_type(file_path)[0] or "application/octet-stream"

        # Get encoding (limited detection)
        encoding = "utf-8"  # Default assumption
        try:
            # Try to read the first few bytes to check encoding
            with open(file_path, "rb") as f:
                start_bytes = f.read(4)
                if start_bytes.startswith(b"\xef\xbb\xbf"):
                    encoding = "utf-8-sig"
                elif start_bytes.startswith(b"\xff\xfe"):
                    encoding = "utf-16-le"
                elif start_bytes.startswith(b"\xfe\xff"):
                    encoding = "utf-16-be"
        except Exception:
            pass

        return {
            "extension": ext.lstrip(".").lower() if ext else "",
            "language": language,
            "size": size,
            "mime_type": mime_type,
            "encoding": encoding,
        }

    def read_file(self, file_path: str) -> Optional[str]:
        """Read a file's content as text.

        Args:
            file_path: Path to the file

        Returns:
            File content as string or None if file cannot be read
        """
        try:
            with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                return f.read()
        except Exception as e:
            logger.debug(f"Could not read file {file_path}: {str(e)}")
            return None

    def _get_language_from_extension(self, ext: str) -> str:
        """Infer programming language from file extension.

        Args:
            ext: File extension including the dot (e.g., '.py')

        Returns:
            Inferred programming language or 'unknown'
        """
        ext = ext.lower()

        language_map = {
            ".py": "python",
            ".pyc": "python",
            ".pyd": "python",
            ".pyx": "python",
            ".pyi": "python",
            ".js": "javascript",
            ".jsx": "javascript",
            ".ts": "typescript",
            ".tsx": "typescript",
            ".java": "java",
            ".class": "java",
            ".jar": "java",
            ".c": "c",
            ".h": "c",
            ".cpp": "cpp",
            ".cc": "cpp",
            ".cxx": "cpp",
            ".hpp": "cpp",
            ".hxx": "cpp",
            ".cs": "csharp",
            ".go": "go",
            ".rb": "ruby",
            ".php": "php",
            ".swift": "swift",
            ".rs": "rust",
            ".scala": "scala",
            ".kt": "kotlin",
            ".kts": "kotlin",
            ".html": "html",
            ".htm": "html",
            ".css": "css",
            ".scss": "css",
            ".sass": "css",
            ".less": "css",
            ".xml": "xml",
            ".json": "json",
            ".yml": "yaml",
            ".yaml": "yaml",
            ".toml": "toml",
            ".ini": "ini",
            ".cfg": "ini",
            ".conf": "ini",
            ".md": "markdown",
            ".markdown": "markdown",
            ".rst": "restructuredtext",
            ".sql": "sql",
            ".sh": "shell",
            ".bash": "shell",
            ".zsh": "shell",
            ".bat": "batch",
            ".cmd": "batch",
            ".ps1": "powershell",
        }

        return language_map.get(ext, "unknown")


class FilesystemGraphBuilder:
    """Creates graph representation of a codebase filesystem structure.

    This class is responsible for creating nodes and relationships in the graph
    database that represent the filesystem structure of a codebase.
    """

    def __init__(self, connector: Neo4jConnector):
        """Initialize the filesystem graph builder.

        Args:
            connector: Neo4j connector instance
        """
        self.connector = connector

    async def build_graph(
        self, repo_node_id: int, fs: CodebaseFileSystem
    ) -> Dict[str, int]:
        """Build a graph representation of the filesystem.

        Args:
            repo_node_id: ID of the repository node
            fs: CodebaseFileSystem instance

        Returns:
            Dictionary mapping file paths to their node IDs
        """
        # Get all files and directories
        all_files = fs.get_all_files()
        all_dirs = fs.get_all_dirs()

        # Create a node for each directory
        dir_nodes = {}
        for dir_path in all_dirs:
            rel_path = fs.get_relative_path(dir_path)
            properties = {
                "path": rel_path,
                "name": os.path.basename(dir_path),
                "full_path": dir_path,
                "type": "directory",
            }

            dir_node_id = self.connector.create_node(
                ["Directory", NodeLabels.FILE], properties
            )

            dir_nodes[dir_path] = dir_node_id

            # Create relationship to repository
            self.connector.create_relationship(
                repo_node_id, dir_node_id, RelationshipTypes.CONTAINS
            )

        # Create parent-child relationships for directories
        for dir_path, node_id in dir_nodes.items():
            parent_dir = os.path.dirname(dir_path)
            if parent_dir in dir_nodes and parent_dir != dir_path:
                parent_node_id = dir_nodes[parent_dir]
                self.connector.create_relationship(
                    parent_node_id, node_id, RelationshipTypes.CONTAINS
                )

        # Create a node for each file
        file_nodes = {}
        for file_path in all_files:
            rel_path = fs.get_relative_path(file_path)
            file_info = fs.get_file_info(file_path)

            properties = {
                "path": rel_path,
                "name": os.path.basename(file_path),
                "full_path": file_path,
                "type": "file",
                "language": file_info.get("language", "unknown"),
                "size": file_info.get("size", 0),
                "extension": file_info.get("extension", ""),
                "mime_type": file_info.get("mime_type", ""),
                "encoding": file_info.get("encoding", ""),
            }

            file_node_id = self.connector.create_node(NodeLabels.FILE, properties)

            file_nodes[file_path] = file_node_id

            # Create relationship to parent directory
            parent_dir = os.path.dirname(file_path)
            if parent_dir in dir_nodes:
                parent_node_id = dir_nodes[parent_dir]
                self.connector.create_relationship(
                    parent_node_id, file_node_id, RelationshipTypes.CONTAINS
                )
            else:
                # If parent directory not in dir_nodes, connect directly to repository
                self.connector.create_relationship(
                    repo_node_id, file_node_id, RelationshipTypes.CONTAINS
                )

        # Combine file and directory nodes for the return value
        all_nodes = {**dir_nodes, **file_nodes}
        return all_nodes

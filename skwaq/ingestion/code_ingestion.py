"""Code ingestion module for the Skwaq vulnerability assessment copilot.

This module handles the ingestion of code repositories for vulnerability assessment,
including code parsing, analysis, and graph representation.
"""

import os
import tempfile
import subprocess
from pathlib import Path
from typing import Dict, List, Optional, Any, Union
import asyncio
import json
import shutil

from ..db.neo4j_connector import get_connector
from ..core.openai_client import get_openai_client
from ..utils.logging import get_logger

logger = get_logger(__name__)


class RepositoryIngestor:
    """Repository ingestion handler that processes and analyzes code repositories.

    This class handles the ingestion of source code repositories, including
    parsing, analysis, and graph representation.
    """

    def __init__(self):
        """Initialize the repository ingestor."""
        self.connector = get_connector()
        self.openai_client = get_openai_client(async_mode=True)
        self.temp_dir = None

    async def ingest_from_path(
        self,
        repo_path: str,
        repo_name: Optional[str] = None,
        include_patterns: Optional[List[str]] = None,
        exclude_patterns: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """Ingest a repository from a local path.

        Args:
            repo_path: Path to the repository
            repo_name: Optional name for the repository (defaults to directory name)
            include_patterns: Optional glob patterns for files to include
            exclude_patterns: Optional glob patterns for files to exclude

        Returns:
            Dictionary with ingestion metadata and results
        """
        path = Path(repo_path)
        if not path.exists() or not path.is_dir():
            raise FileNotFoundError(f"Repository path not found: {repo_path}")

        # Use directory name as repo name if not provided
        if repo_name is None:
            repo_name = path.name

        logger.info(f"Ingesting repository from {repo_path} as '{repo_name}'")

        try:
            # Create repository node
            repo_props = {
                "name": repo_name,
                "path": str(path.absolute()),
                "ingest_timestamp": self._get_timestamp(),
            }

            repo_id = self.connector.create_node(
                labels=["Repository"],
                properties=repo_props,
            )

            if repo_id is None:
                raise RuntimeError(f"Failed to create repository node for {repo_name}")

            # Process file system structure
            fs_stats = await self._process_filesystem(
                repo_path, repo_id, include_patterns, exclude_patterns
            )

            # Generate repository summary
            summary = await self._generate_repo_summary(repo_path, repo_name)

            # Update repository node with summary
            self.connector.run_query(
                "MATCH (r:Repository) WHERE id(r) = $repo_id " "SET r.summary = $summary",
                {"repo_id": repo_id, "summary": summary},
            )

            logger.info(f"Repository ingestion complete for {repo_name}")

            return {
                "repository_id": repo_id,
                "repository_name": repo_name,
                "file_count": fs_stats["file_count"],
                "directory_count": fs_stats["directory_count"],
                "code_files_processed": fs_stats["code_files_processed"],
                "summary": summary,
            }

        except Exception as e:
            logger.error(f"Error ingesting repository {repo_path}: {e}")
            raise

    async def ingest_from_github(
        self,
        github_url: str,
        include_patterns: Optional[List[str]] = None,
        exclude_patterns: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """Ingest a repository from a GitHub URL.

        Args:
            github_url: URL of the GitHub repository
            include_patterns: Optional glob patterns for files to include
            exclude_patterns: Optional glob patterns for files to exclude

        Returns:
            Dictionary with ingestion metadata and results
        """
        logger.info(f"Ingesting repository from GitHub URL: {github_url}")

        # Extract repository name from URL
        repo_name = github_url.strip("/").split("/")[-1]
        if repo_name.endswith(".git"):
            repo_name = repo_name[:-4]

        # Create temporary directory
        self.temp_dir = tempfile.mkdtemp(prefix="skwaq_repo_")

        try:
            # Clone the repository
            logger.info(f"Cloning {github_url} to {self.temp_dir}")
            result = subprocess.run(
                ["git", "clone", github_url, self.temp_dir],
                capture_output=True,
                text=True,
                check=True,
            )

            # Process the cloned repository
            return await self.ingest_from_path(
                self.temp_dir,
                repo_name,
                include_patterns,
                exclude_patterns,
            )

        except subprocess.CalledProcessError as e:
            logger.error(f"Git clone failed: {e.stderr}")
            raise RuntimeError(f"Failed to clone repository: {e.stderr}")

        except Exception as e:
            logger.error(f"Error ingesting GitHub repository {github_url}: {e}")
            raise

        finally:
            # Clean up temporary directory
            if self.temp_dir and os.path.exists(self.temp_dir):
                shutil.rmtree(self.temp_dir)
                self.temp_dir = None

    async def _process_filesystem(
        self,
        repo_path: str,
        repo_id: int,
        include_patterns: Optional[List[str]] = None,
        exclude_patterns: Optional[List[str]] = None,
    ) -> Dict[str, int]:
        """Process the filesystem structure of the repository.

        Args:
            repo_path: Path to the repository
            repo_id: ID of the repository node in the graph
            include_patterns: Optional glob patterns for files to include
            exclude_patterns: Optional glob patterns for files to exclude

        Returns:
            Dictionary with filesystem processing statistics
        """
        logger.info(f"Processing filesystem for repository at {repo_path}")

        # Initialize statistics
        stats = {
            "file_count": 0,
            "directory_count": 0,
            "code_files_processed": 0,
        }

        repo_path = Path(repo_path)

        # Create a node for the root directory
        root_dir_id = self.connector.create_node(
            labels=["Directory"],
            properties={
                "name": repo_path.name,
                "path": str(repo_path),
                "is_root": True,
            },
        )

        # Link repository to root directory
        self.connector.create_relationship(repo_id, root_dir_id, "HAS_ROOT_DIRECTORY")

        # Process the root directory
        await self._process_directory(
            repo_path,
            root_dir_id,
            repo_id,
            include_patterns,
            exclude_patterns,
            stats,
        )

        logger.info(
            f"Filesystem processing complete. "
            f"Directories: {stats['directory_count']}, "
            f"Files: {stats['file_count']}, "
            f"Code files: {stats['code_files_processed']}"
        )

        return stats

    async def _process_directory(
        self,
        dir_path: Path,
        dir_node_id: int,
        repo_id: int,
        include_patterns: Optional[List[str]] = None,
        exclude_patterns: Optional[List[str]] = None,
        stats: Dict[str, int] = None,
    ) -> None:
        """Process a directory in the repository.

        Args:
            dir_path: Path to the directory
            dir_node_id: ID of the directory node in the graph
            repo_id: ID of the repository node in the graph
            include_patterns: Optional glob patterns for files to include
            exclude_patterns: Optional glob patterns for files to exclude
            stats: Dictionary to track processing statistics
        """
        # List directory contents
        for item in dir_path.iterdir():
            # Skip hidden files and directories
            if item.name.startswith("."):
                continue

            # Skip directories and files based on exclude patterns
            if exclude_patterns and any(item.match(pattern) for pattern in exclude_patterns):
                continue

            # Process directories
            if item.is_dir():
                stats["directory_count"] += 1

                # Create a node for the subdirectory
                subdir_node_id = self.connector.create_node(
                    labels=["Directory"],
                    properties={
                        "name": item.name,
                        "path": str(item),
                        "is_root": False,
                    },
                )

                # Link parent directory to subdirectory
                self.connector.create_relationship(dir_node_id, subdir_node_id, "CONTAINS")

                # Link repository to subdirectory
                self.connector.create_relationship(repo_id, subdir_node_id, "HAS_DIRECTORY")

                # Recursively process subdirectory
                await self._process_directory(
                    item,
                    subdir_node_id,
                    repo_id,
                    include_patterns,
                    exclude_patterns,
                    stats,
                )

            # Process files
            elif item.is_file():
                stats["file_count"] += 1

                # Check include patterns if provided
                if include_patterns and not any(
                    item.match(pattern) for pattern in include_patterns
                ):
                    continue

                # Create a node for the file
                file_props = {
                    "name": item.name,
                    "path": str(item),
                    "extension": item.suffix,
                    "size": item.stat().st_size,
                }

                file_node_id = self.connector.create_node(
                    labels=["File"],
                    properties=file_props,
                )

                # Link directory to file
                self.connector.create_relationship(dir_node_id, file_node_id, "CONTAINS")

                # Link repository to file
                self.connector.create_relationship(repo_id, file_node_id, "HAS_FILE")

                # Process code files for AST and analysis
                if self._is_code_file(item):
                    await self._process_code_file(item, file_node_id, repo_id)
                    stats["code_files_processed"] += 1

    async def _process_code_file(
        self,
        file_path: Path,
        file_node_id: int,
        repo_id: int,
    ) -> None:
        """Process a code file for vulnerability assessment.

        Args:
            file_path: Path to the code file
            file_node_id: ID of the file node in the graph
            repo_id: ID of the repository node in the graph
        """
        try:
            # Read file content
            code_content = file_path.read_text(encoding="utf-8", errors="ignore")

            # Skip empty files
            if not code_content.strip():
                return

            # Determine language
            language = self._detect_language(file_path)

            # Generate code summary
            summary = await self._generate_code_summary(code_content, language)

            # Update file node with code information
            self.connector.run_query(
                "MATCH (f:File) WHERE id(f) = $file_id "
                "SET f.language = $language, "
                "f.summary = $summary, "
                "f.line_count = $line_count",
                {
                    "file_id": file_node_id,
                    "language": language,
                    "summary": summary,
                    "line_count": code_content.count("\n") + 1,
                },
            )

            # Create code content node
            code_node_id = self.connector.create_node(
                labels=["CodeContent"],
                properties={
                    "content": code_content,
                    "language": language,
                    "summary": summary,
                },
            )

            # Link file to code content
            self.connector.create_relationship(file_node_id, code_node_id, "HAS_CONTENT")

            logger.debug(f"Processed code file: {file_path}")

        except Exception as e:
            logger.error(f"Error processing code file {file_path}: {e}")

    async def _generate_repo_summary(
        self,
        repo_path: str,
        repo_name: str,
    ) -> str:
        """Generate a summary of the repository.

        Args:
            repo_path: Path to the repository
            repo_name: Name of the repository

        Returns:
            Summary text
        """
        logger.info(f"Generating summary for repository: {repo_name}")

        # Get some basic repository stats
        try:
            # Count files by type
            stats = {"total_files": 0, "languages": {}}
            repo_dir = Path(repo_path)

            for file_path in repo_dir.glob("**/*"):
                if file_path.is_file() and not file_path.name.startswith("."):
                    stats["total_files"] += 1
                    lang = self._detect_language(file_path)
                    if lang:
                        stats["languages"][lang] = stats["languages"].get(lang, 0) + 1

            # Check for certain types of files
            has_readme = any(f.name.lower() == "readme.md" for f in repo_dir.glob("*.md"))
            has_license = any(
                f.name.lower() == "license" or f.name.lower() == "license.md"
                for f in repo_dir.glob("*")
            )
            has_gitignore = (repo_dir / ".gitignore").exists()

            # Find build configuration files
            build_files = []
            for pattern in [
                "requirements.txt",
                "setup.py",
                "package.json",
                "Makefile",
                "CMakeLists.txt",
            ]:
                if list(repo_dir.glob(f"**/{pattern}")):
                    build_files.append(pattern)

            # Generate prompt for summary
            prompt = f"""Generate a concise summary (250 words max) of this code repository based on these details:

Repository name: {repo_name}

Statistics:
- Total files: {stats['total_files']}
- Languages: {', '.join([f"{lang} ({count})" for lang, count in stats['languages'].items()])}
- Has README: {has_readme}
- Has LICENSE: {has_license}
- Has .gitignore: {has_gitignore}
- Build files: {', '.join(build_files) if build_files else 'None detected'}

Focus on describing the likely purpose of the repository, its main components, and any 
security-relevant aspects that would be useful for vulnerability assessment.
"""

            # Get summary from OpenAI
            summary = await self.openai_client.get_completion(prompt, temperature=0.3)
            return summary

        except Exception as e:
            logger.error(f"Error generating repository summary: {e}")
            return f"Repository: {repo_name} (Summary generation failed)"

    async def _generate_code_summary(
        self,
        code_content: str,
        language: str,
    ) -> str:
        """Generate a summary of a code file.

        Args:
            code_content: Content of the code file
            language: Programming language of the code

        Returns:
            Summary text
        """
        # Limit code content length for the prompt
        max_chars = 8000
        if len(code_content) > max_chars:
            truncated_code = code_content[:max_chars] + "\n... (truncated)"
        else:
            truncated_code = code_content

        prompt = f"""Provide a brief summary (50 words max) of this {language} code:

```{language}
{truncated_code}
```

Focus on the main functionality and any security-relevant aspects like:
- Authentication/authorization mechanisms
- Data handling and validation
- External integrations
- Cryptographic operations
- Configuration management

Be concise and focus on aspects relevant for security assessment.
"""

        try:
            summary = await self.openai_client.get_completion(prompt, temperature=0.3)
            return summary
        except Exception as e:
            logger.error(f"Error generating code summary: {e}")
            return "Summary generation failed"

    def _detect_language(self, file_path: Path) -> Optional[str]:
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

    def _is_code_file(self, file_path: Path) -> bool:
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

    def _get_timestamp(self) -> str:
        """Get the current timestamp as an ISO 8601 string.

        Returns:
            Timestamp string
        """
        from datetime import datetime

        return datetime.utcnow().isoformat()


async def ingest_repository(
    repo_path_or_url: str,
    is_github_url: bool = False,
    include_patterns: Optional[List[str]] = None,
    exclude_patterns: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """Ingest a repository for vulnerability assessment.

    Args:
        repo_path_or_url: Path to local repository or GitHub URL
        is_github_url: Whether the provided path is a GitHub URL
        include_patterns: Optional glob patterns for files to include
        exclude_patterns: Optional glob patterns for files to exclude

    Returns:
        Dictionary with ingestion metadata and results
    """
    ingestor = RepositoryIngestor()

    if is_github_url:
        return await ingestor.ingest_from_github(
            repo_path_or_url,
            include_patterns,
            exclude_patterns,
        )
    else:
        return await ingestor.ingest_from_path(
            repo_path_or_url,
            None,  # Use directory name
            include_patterns,
            exclude_patterns,
        )

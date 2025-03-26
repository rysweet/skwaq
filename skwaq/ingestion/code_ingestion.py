"""Code ingestion module for the Skwaq vulnerability assessment copilot.

This module handles the ingestion of code repositories for vulnerability assessment,
including code parsing, analysis, and graph representation.
"""

import os
import tempfile
import subprocess
from pathlib import Path
from typing import Dict, List, Optional, Any, Union, Tuple, Set
import asyncio
import json
import shutil
import time
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

# Third-party imports
from github import Github, GithubException, Auth
from github.Repository import Repository
from git import Repo, GitCommandError
from tqdm import tqdm

from ..db.neo4j_connector import get_connector
from ..core.openai_client import get_openai_client
from ..utils.logging import get_logger
from ..shared.utils import safe_run

logger = get_logger(__name__)


class RepositoryIngestor:
    """Repository ingestion handler that processes and analyzes code repositories.

    This class handles the ingestion of source code repositories, including
    parsing, analysis, and graph representation. It supports ingesting from local paths
    and GitHub repositories, with comprehensive error handling and progress reporting.
    """

    def __init__(
        self, 
        github_token: Optional[str] = None,
        max_workers: int = 4,
        progress_bar: bool = True,
    ):
        """Initialize the repository ingestor.
        
        Args:
            github_token: GitHub Personal Access Token for authentication with GitHub API
            max_workers: Maximum number of parallel workers for file processing
            progress_bar: Whether to display progress bars during ingestion
        """
        self.connector = get_connector()
        self.openai_client = get_openai_client(async_mode=True)
        self.temp_dir = None
        self.github_token = github_token or os.getenv("GITHUB_TOKEN")
        self.github_client = None
        self.max_workers = max_workers
        self.show_progress = progress_bar
        self.excluded_dirs = {".git", "__pycache__", "node_modules", ".venv", "venv", "env"}
        
    def _init_github_client(self) -> Github:
        """Initialize the GitHub client with authentication.
        
        Returns:
            Authenticated GitHub client
            
        Raises:
            RuntimeError: If authentication fails
        """
        if self.github_client is None:
            try:
                if self.github_token:
                    auth = Auth.Token(self.github_token)
                    self.github_client = Github(auth=auth)
                    # Test the client with a simple API call
                    self.github_client.get_rate_limit()
                    logger.info("Successfully authenticated with GitHub API")
                else:
                    logger.warning("No GitHub token provided, using unauthenticated client with rate limits")
                    self.github_client = Github()
            except GithubException as e:
                logger.error(f"GitHub authentication error: {e}")
                raise RuntimeError(f"Failed to authenticate with GitHub: {e}")
                
        return self.github_client

    async def ingest_from_path(
        self,
        repo_path: str,
        repo_name: Optional[str] = None,
        include_patterns: Optional[List[str]] = None,
        exclude_patterns: Optional[List[str]] = None,
        existing_repo_id: Optional[int] = None,
    ) -> Dict[str, Any]:
        """Ingest a repository from a local path with enhanced functionality.

        This method processes a local repository directory, analyzing the file structure
        and code files. It supports parallel processing for improved performance on large
        repositories and progress reporting.

        Args:
            repo_path: Path to the repository
            repo_name: Optional name for the repository (defaults to directory name)
            include_patterns: Optional glob patterns for files to include
            exclude_patterns: Optional glob patterns for files to exclude
            existing_repo_id: Optional ID of an existing repository node

        Returns:
            Dictionary with ingestion metadata and results
            
        Raises:
            FileNotFoundError: If the repository path doesn't exist
            RuntimeError: If creating repository node fails
        """
        path = Path(repo_path)
        if not path.exists() or not path.is_dir():
            raise FileNotFoundError(f"Repository path not found: {repo_path}")

        # Use directory name as repo name if not provided
        if repo_name is None:
            repo_name = path.name

        logger.info(f"Ingesting repository from {repo_path} as '{repo_name}'")

        try:
            # Use existing repository node or create a new one
            if existing_repo_id is not None:
                repo_id = existing_repo_id
                logger.info(f"Using existing repository node with ID: {repo_id}")
            else:
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

            # Check for .git directory to identify if this is a Git repository
            git_dir = path / ".git"
            if git_dir.exists() and git_dir.is_dir():
                try:
                    # Get Git repository information
                    repo = Repo(path)
                    
                    # Get current branch
                    branch = repo.active_branch.name
                    
                    # Get latest commit
                    latest_commit = repo.head.commit
                    commit_hash = latest_commit.hexsha
                    commit_author = f"{latest_commit.author.name} <{latest_commit.author.email}>"
                    commit_date = datetime.fromtimestamp(latest_commit.committed_date).isoformat()
                    commit_message = latest_commit.message.strip()
                    
                    # Update repository node with Git information
                    self.connector.run_query(
                        "MATCH (r:Repository) WHERE id(r) = $repo_id "
                        "SET r.is_git_repo = true, "
                        "r.git_branch = $branch, "
                        "r.git_commit_hash = $commit_hash, "
                        "r.git_commit_author = $commit_author, "
                        "r.git_commit_date = $commit_date, "
                        "r.git_commit_message = $commit_message",
                        {
                            "repo_id": repo_id, 
                            "branch": branch,
                            "commit_hash": commit_hash,
                            "commit_author": commit_author,
                            "commit_date": commit_date,
                            "commit_message": commit_message,
                        },
                    )
                    
                    # Add Git labels to the repository node
                    self.connector.run_query(
                        "MATCH (r:Repository) WHERE id(r) = $repo_id "
                        "SET r:GitRepository",
                        {"repo_id": repo_id},
                    )
                    
                except Exception as e:
                    logger.warning(f"Failed to get Git information: {e}")
                    # Continue with ingestion even if Git info extraction fails
            
            # Process file system structure with parallel processing
            start_time = time.time()
            fs_stats = await self._process_filesystem(
                repo_path, repo_id, include_patterns, exclude_patterns
            )
            processing_time = time.time() - start_time
            
            # Generate repository summary
            summary = await self._generate_repo_summary(repo_path, repo_name)

            # Update repository node with summary and statistics
            self.connector.run_query(
                "MATCH (r:Repository) WHERE id(r) = $repo_id "
                "SET r.summary = $summary, "
                "r.file_count = $file_count, "
                "r.directory_count = $directory_count, "
                "r.code_files_count = $code_files_count, "
                "r.processing_time_seconds = $processing_time",
                {
                    "repo_id": repo_id, 
                    "summary": summary,
                    "file_count": fs_stats["file_count"],
                    "directory_count": fs_stats["directory_count"],
                    "code_files_count": fs_stats["code_files_processed"],
                    "processing_time": processing_time,
                },
            )

            logger.info(f"Repository ingestion complete for {repo_name} in {processing_time:.2f} seconds")

            return {
                "repository_id": repo_id,
                "repository_name": repo_name,
                "file_count": fs_stats["file_count"],
                "directory_count": fs_stats["directory_count"],
                "code_files_processed": fs_stats["code_files_processed"],
                "processing_time_seconds": processing_time,
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
        branch: Optional[str] = None,
        depth: int = 1,
        metadata_only: bool = False,
    ) -> Dict[str, Any]:
        """Ingest a repository from a GitHub URL with enhanced functionality.

        This method fetches repository information using the GitHub API, clones the
        repository with progress reporting, and processes it for vulnerability assessment.
        It supports authenticated access for private repositories.

        Args:
            github_url: URL of the GitHub repository
            include_patterns: Optional glob patterns for files to include
            exclude_patterns: Optional glob patterns for files to exclude
            branch: Optional branch to clone (defaults to default branch)
            depth: Git clone depth (1 for shallow clone, 0 for full history)
            metadata_only: If True, only fetch repository metadata without cloning

        Returns:
            Dictionary with ingestion metadata and results
            
        Raises:
            ValueError: If the GitHub URL is invalid
            RuntimeError: If cloning or API access fails
        """
        logger.info(f"Ingesting repository from GitHub URL: {github_url}")
        
        # Initialize GitHub client
        github = self._init_github_client()
        
        # Parse the GitHub URL to get owner and repo name
        try:
            owner, repo_name = self._parse_github_url(github_url)
        except ValueError as e:
            logger.error(f"Invalid GitHub URL: {github_url}")
            raise
            
        # Get repository information from GitHub API
        try:
            repo_info = self._get_github_repo_info(owner, repo_name)
            logger.info(f"Repository info fetched: {repo_info['name']} ({repo_info['description']})")
            
            # Store repository metadata in Neo4j
            repo_props = {
                "name": repo_info["name"],
                "full_name": repo_info["full_name"],
                "description": repo_info["description"],
                "owner": repo_info["owner"],
                "stars": repo_info["stars"],
                "forks": repo_info["forks"],
                "default_branch": repo_info["default_branch"],
                "languages": json.dumps(repo_info["languages"]),
                "size_kb": repo_info["size"],
                "is_private": repo_info["private"],
                "created_at": repo_info["created_at"],
                "updated_at": repo_info["updated_at"],
                "url": github_url,
                "ingest_timestamp": self._get_timestamp(),
            }
            
            repo_id = self.connector.create_node(
                labels=["Repository", "GitHubRepository"],
                properties=repo_props,
            )
            
            if repo_id is None:
                raise RuntimeError(f"Failed to create repository node for {repo_info['name']}")
                
            # If only metadata was requested, return now
            if metadata_only:
                return {
                    "repository_id": repo_id,
                    "repository_name": repo_info["name"],
                    "metadata": repo_props,
                    "content_ingested": False,
                }
                
            # Determine branch to clone
            clone_branch = branch or repo_info["default_branch"]
            
            # Create temporary directory for cloning
            self.temp_dir = tempfile.mkdtemp(prefix="skwaq_repo_")
            
            # Clone the repository with GitPython and progress reporting
            logger.info(f"Cloning {github_url} (branch: {clone_branch}) to {self.temp_dir}")
            
            try:
                # Determine clone URL (use authenticated URL if token is available)
                clone_url = repo_info["clone_url"]
                if self.github_token and "https://" in clone_url:
                    clone_url = clone_url.replace("https://", f"https://{self.github_token}@")
                
                # Create progress reporting callback
                progress_output = None
                if self.show_progress:
                    progress_output = tqdm(
                        total=100, 
                        desc=f"Cloning {repo_info['name']}", 
                        unit="%",
                        leave=True
                    )
                
                # Clone with GitPython
                clone_args = {
                    "url": clone_url,
                    "to_path": self.temp_dir,
                    "branch": clone_branch,
                }
                
                if depth > 0:
                    clone_args["depth"] = depth
                
                # Add progress callback if needed
                if progress_output:
                    def progress_callback(op_code, cur_count, max_count, message):
                        if max_count:
                            progress = int(cur_count / max_count * 100)
                            progress_output.update(progress - progress_output.n)
                    
                    clone_args["progress"] = progress_callback
                
                # Perform the clone operation
                Repo.clone_from(**clone_args)
                
                # Close progress bar if used
                if progress_output:
                    progress_output.close()
                
                logger.info(f"Successfully cloned {github_url} to {self.temp_dir}")
                
                # Update repository node with file system statistics
                repo_props["cloned_branch"] = clone_branch
                repo_props["clone_timestamp"] = self._get_timestamp()
                
                self.connector.run_query(
                    "MATCH (r:Repository) WHERE id(r) = $repo_id "
                    "SET r.cloned_branch = $branch, r.clone_timestamp = $timestamp",
                    {
                        "repo_id": repo_id, 
                        "branch": clone_branch,
                        "timestamp": repo_props["clone_timestamp"]
                    },
                )
                
                # Process the cloned repository
                ingest_result = await self.ingest_from_path(
                    self.temp_dir,
                    repo_info["name"],
                    include_patterns,
                    exclude_patterns,
                    existing_repo_id=repo_id,
                )
                
                # Add GitHub-specific information to the result
                ingest_result.update({
                    "github_url": github_url,
                    "github_metadata": repo_props,
                    "branch": clone_branch,
                })
                
                return ingest_result
                
            except GitCommandError as e:
                logger.error(f"Git clone failed: {e}")
                raise RuntimeError(f"Failed to clone repository: {e}")
            
        except GithubException as e:
            logger.error(f"GitHub API error: {e}")
            if e.status == 404:
                raise RuntimeError(f"Repository not found: {owner}/{repo_name}")
            elif e.status == 403:
                raise RuntimeError("Rate limit exceeded or insufficient permissions")
            else:
                raise RuntimeError(f"GitHub API error: {e}")
                
        except Exception as e:
            logger.error(f"Error ingesting GitHub repository {github_url}: {e}")
            raise
            
        finally:
            # Clean up temporary directory
            if self.temp_dir and os.path.exists(self.temp_dir):
                logger.info(f"Cleaning up temporary directory: {self.temp_dir}")
                shutil.rmtree(self.temp_dir)
                self.temp_dir = None
                
    def _parse_github_url(self, url: str) -> Tuple[str, str]:
        """Parse a GitHub repository URL to extract owner and repo name.
        
        Args:
            url: GitHub repository URL
            
        Returns:
            Tuple of (owner, repo_name)
            
        Raises:
            ValueError: If the URL is not a valid GitHub repository URL
        """
        try:
            parsed = urlparse(url)
            
            # Verify this is a GitHub URL
            if not (parsed.netloc == "github.com" or parsed.netloc.endswith(".github.com")):
                raise ValueError(f"Not a GitHub URL: {url}")
                
            # Remove .git suffix if present
            path = parsed.path.strip("/")
            if path.endswith(".git"):
                path = path[:-4]
                
            # Split path into components
            parts = path.split("/")
            
            # GitHub URLs should have at least owner/repo
            if len(parts) < 2:
                raise ValueError(f"Invalid GitHub repository URL format: {url}")
                
            owner = parts[0]
            repo_name = parts[1]
            
            return owner, repo_name
            
        except Exception as e:
            raise ValueError(f"Error parsing GitHub URL {url}: {e}")
            
    def _get_github_repo_info(self, owner: str, repo_name: str) -> Dict[str, Any]:
        """Get repository information from GitHub API.
        
        Args:
            owner: Repository owner (username or organization)
            repo_name: Repository name
            
        Returns:
            Dictionary with repository metadata
            
        Raises:
            GithubException: If API access fails
        """
        github = self._init_github_client()
        
        try:
            # Get repository object
            repo = github.get_repo(f"{owner}/{repo_name}")
            
            # Get language statistics
            languages = repo.get_languages()
            
            # Format dates as ISO strings
            created_at = repo.created_at.isoformat() if repo.created_at else None
            updated_at = repo.updated_at.isoformat() if repo.updated_at else None
            
            # Build repository info dictionary
            return {
                "name": repo.name,
                "full_name": repo.full_name,
                "description": repo.description or "",
                "owner": owner,
                "stars": repo.stargazers_count,
                "forks": repo.forks_count,
                "default_branch": repo.default_branch,
                "languages": languages,
                "size": repo.size,  # Size in KB
                "private": repo.private,
                "created_at": created_at,
                "updated_at": updated_at,
                "clone_url": repo.clone_url,
                "ssh_url": repo.ssh_url,
                "html_url": repo.html_url,
            }
            
        except GithubException as e:
            logger.error(f"GitHub API error: {e}")
            raise

    async def _process_filesystem(
        self,
        repo_path: str,
        repo_id: int,
        include_patterns: Optional[List[str]] = None,
        exclude_patterns: Optional[List[str]] = None,
    ) -> Dict[str, int]:
        """Process the filesystem structure of the repository with enhanced functionality.

        This method traverses the repository directory structure, creating nodes and
        relationships in the graph database. It supports parallel processing of files
        and progress reporting for improved performance on large repositories.

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

        # Collect all files and directories first
        all_files = []
        all_dirs = []
        
        # Create a progress bar for directory scanning
        logger.info("Scanning repository directory structure...")
        
        # Convert patterns to Path objects for matching
        include_path_patterns = [Path(p) for p in (include_patterns or [])]
        exclude_path_patterns = [Path(p) for p in (exclude_patterns or [])]
        
        # Walk the directory tree
        for root, dirs, files in os.walk(repo_path):
            root_path = Path(root)
            
            # Filter out excluded directories
            dirs[:] = [d for d in dirs if d not in self.excluded_dirs and 
                      not any(Path(d).match(pattern) for pattern in exclude_path_patterns)]
            
            # Track directory
            if root_path != repo_path:  # Skip root as we already created it
                rel_path = root_path.relative_to(repo_path)
                all_dirs.append((root_path, rel_path))
                stats["directory_count"] += 1
            
            # Track files
            for file in files:
                file_path = root_path / file
                rel_path = file_path.relative_to(repo_path)
                
                # Check exclusion patterns
                if exclude_patterns and any(rel_path.match(pattern) for pattern in exclude_path_patterns):
                    continue
                
                # Check inclusion patterns if provided
                if include_patterns and not any(rel_path.match(pattern) for pattern in include_path_patterns):
                    continue
                
                all_files.append(file_path)
                stats["file_count"] += 1
        
        # Create directory nodes and relationships
        logger.info(f"Creating directory structure ({len(all_dirs)} directories)...")
        
        # Show progress bar for directories if enabled
        if self.show_progress and all_dirs:
            dir_progress = tqdm(
                total=len(all_dirs),
                desc="Processing directories",
                unit="dir"
            )
        else:
            dir_progress = None
            
        # Map to store directory path to node ID
        dir_node_map = {str(repo_path): root_dir_id}
        
        # Sort directories by depth to ensure parent directories are processed first
        all_dirs.sort(key=lambda x: len(x[1].parts))
        
        for dir_path, rel_path in all_dirs:
            # Create node for directory
            dir_node_id = self.connector.create_node(
                labels=["Directory"],
                properties={
                    "name": dir_path.name,
                    "path": str(dir_path),
                    "relative_path": str(rel_path),
                    "is_root": False,
                },
            )
            
            # Store node ID in map
            dir_node_map[str(dir_path)] = dir_node_id
            
            # Link to parent directory
            parent_path = str(dir_path.parent)
            parent_id = dir_node_map.get(parent_path)
            
            if parent_id:
                self.connector.create_relationship(parent_id, dir_node_id, "CONTAINS")
            
            # Link repository to directory
            self.connector.create_relationship(repo_id, dir_node_id, "HAS_DIRECTORY")
            
            # Update progress
            if dir_progress:
                dir_progress.update(1)
        
        # Close progress bar
        if dir_progress:
            dir_progress.close()
        
        # Process files with parallel processing
        logger.info(f"Processing {len(all_files)} files...")
        
        # Show progress bar for files if enabled
        if self.show_progress and all_files:
            file_progress = tqdm(
                total=len(all_files),
                desc="Processing files",
                unit="file"
            )
        else:
            file_progress = None
        
        # Define file processing function for parallel execution
        async def process_file(file_path: Path) -> Optional[Dict[str, Any]]:
            try:
                # Skip files that are too large or binary
                if file_path.stat().st_size > 10 * 1024 * 1024:  # 10MB limit
                    logger.debug(f"Skipping large file: {file_path}")
                    return None
                
                # Create file node
                file_props = {
                    "name": file_path.name,
                    "path": str(file_path),
                    "relative_path": str(file_path.relative_to(repo_path)),
                    "extension": file_path.suffix,
                    "size": file_path.stat().st_size,
                }
                
                file_node_id = self.connector.create_node(
                    labels=["File"],
                    properties=file_props,
                )
                
                # Find parent directory
                parent_path = str(file_path.parent)
                parent_id = dir_node_map.get(parent_path)
                
                if parent_id:
                    self.connector.create_relationship(parent_id, file_node_id, "CONTAINS")
                
                # Link repository to file
                self.connector.create_relationship(repo_id, file_node_id, "HAS_FILE")
                
                result = {"file_node_id": file_node_id}
                
                # Process code files
                if self._is_code_file(file_path):
                    await self._process_code_file(file_path, file_node_id, repo_id)
                    result["is_code_file"] = True
                else:
                    result["is_code_file"] = False
                
                return result
                
            except Exception as e:
                logger.error(f"Error processing file {file_path}: {e}")
                return None
            finally:
                # Update progress
                if file_progress:
                    file_progress.update(1)
        
        # Process files in parallel
        tasks = []
        semaphore = asyncio.Semaphore(self.max_workers)
        
        async def process_with_semaphore(file_path: Path) -> Optional[Dict[str, Any]]:
            async with semaphore:
                return await process_file(file_path)
        
        # Create tasks for all files
        for file_path in all_files:
            tasks.append(process_with_semaphore(file_path))
        
        # Execute all tasks
        results = await asyncio.gather(*tasks)
        
        # Close progress bar
        if file_progress:
            file_progress.close()
        
        # Count code files processed
        stats["code_files_processed"] = sum(1 for r in results if r and r.get("is_code_file", False))
        
        logger.info(
            f"Filesystem processing complete. "
            f"Directories: {stats['directory_count']}, "
            f"Files: {stats['file_count']}, "
            f"Code files: {stats['code_files_processed']}"
        )
        
        return stats


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
    github_token: Optional[str] = None,
    branch: Optional[str] = None,
    show_progress: bool = True,
    max_workers: int = 4,
    github_metadata_only: bool = False,
) -> Dict[str, Any]:
    """Ingest a repository for vulnerability assessment with enhanced functionality.

    This function provides a high-level interface for repository ingestion, handling both
    local paths and GitHub URLs. It supports advanced features such as progress reporting,
    parallel file processing, and GitHub API integration.

    Args:
        repo_path_or_url: Path to local repository or GitHub URL
        is_github_url: Whether the provided path is a GitHub URL
        include_patterns: Optional glob patterns for files to include (e.g., ["*.py", "*.js"])
        exclude_patterns: Optional glob patterns for files to exclude (e.g., ["*/test/*", "*/node_modules/*"])
        github_token: Optional GitHub Personal Access Token for private repositories
        branch: Optional branch to clone (only for GitHub repositories)
        show_progress: Whether to display progress bars during ingestion
        max_workers: Maximum number of parallel workers for file processing
        github_metadata_only: If True, only fetch GitHub metadata without cloning (only for GitHub repositories)

    Returns:
        Dictionary with ingestion metadata and results
        
    Raises:
        ValueError: If the path or URL is invalid
        RuntimeError: If repository ingestion fails
    """
    # Detect GitHub URLs automatically if not specified
    if not is_github_url and repo_path_or_url.startswith(("https://github.com/", "http://github.com/")):
        is_github_url = True
        logger.info(f"Automatically detected GitHub URL: {repo_path_or_url}")
    
    # Create repository ingestor with configuration
    ingestor = RepositoryIngestor(
        github_token=github_token,
        max_workers=max_workers,
        progress_bar=show_progress,
    )

    try:
        if is_github_url:
            return await ingestor.ingest_from_github(
                repo_path_or_url,
                include_patterns,
                exclude_patterns,
                branch=branch,
                metadata_only=github_metadata_only,
            )
        else:
            # Validate path exists
            path = Path(repo_path_or_url)
            if not path.exists():
                raise ValueError(f"Repository path does not exist: {repo_path_or_url}")
            
            return await ingestor.ingest_from_path(
                repo_path_or_url,
                None,  # Use directory name
                include_patterns,
                exclude_patterns,
            )
    except Exception as e:
        logger.error(f"Repository ingestion failed: {e}")
        raise


async def get_github_repository_info(
    github_url: str,
    github_token: Optional[str] = None,
) -> Dict[str, Any]:
    """Get metadata for a GitHub repository without ingesting it.
    
    This function fetches repository information from the GitHub API without
    cloning or processing the repository content.
    
    Args:
        github_url: GitHub repository URL
        github_token: Optional GitHub Personal Access Token for private repositories
        
    Returns:
        Dictionary with repository metadata
        
    Raises:
        ValueError: If the GitHub URL is invalid
        RuntimeError: If GitHub API access fails
    """
    ingestor = RepositoryIngestor(github_token=github_token)
    
    try:
        return await ingestor.ingest_from_github(
            github_url,
            metadata_only=True,
        )
    except Exception as e:
        logger.error(f"Failed to get GitHub repository info: {e}")
        raise


async def list_repositories() -> List[Dict[str, Any]]:
    """List all repositories ingested into the system.
    
    Returns:
        List of dictionaries with repository information
    """
    connector = get_connector()
    
    result = connector.run_query(
        "MATCH (r:Repository) "
        "RETURN id(r) as id, r.name as name, r.path as path, r.url as url, "
        "r.ingest_timestamp as ingested_at, r.file_count as files, "
        "r.code_files_count as code_files, r.summary as summary, "
        "labels(r) as labels "
        "ORDER BY r.ingest_timestamp DESC",
        {},
    )
    
    return result

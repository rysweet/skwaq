"""Repository handling for code ingestion.

This module provides classes for interacting with Git repositories during ingestion.
"""

import os
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Dict, Optional, Any, List

import git
from github import Github, Repository as GithubRepo, UnknownObjectException, GithubException

from skwaq.db.neo4j_connector import Neo4jConnector
from skwaq.db.schema import NodeLabels
from skwaq.utils.logging import get_logger
from .exceptions import RepositoryError, DatabaseError

logger = get_logger(__name__)


class RepositoryHandler:
    """Handles Git repository operations for ingestion.

    This class provides methods to clone and extract metadata from Git repositories.
    """

    def __init__(self, github_token: Optional[str] = None):
        """Initialize the repository handler.
        
        Args:
            github_token: Optional GitHub personal access token for API access
        """
        self._temp_dirs = []  # Store the actual TemporaryDirectory objects
        self.github = Github(github_token) if github_token else None

    def clone_repository(self, repo_url: str, branch: Optional[str] = None, depth: Optional[int] = None) -> str:
        """Clone a Git repository to a temporary directory.

        Args:
            repo_url: URL of the Git repository
            branch: Optional branch to checkout
            depth: Optional depth for shallow clones (e.g., depth=1 for minimal history)

        Returns:
            Path to the cloned repository

        Raises:
            RepositoryError: If repository URL is invalid or if cloning fails
        """
        try:
            # Create a temporary directory and save the object (not just the name)
            # to prevent premature garbage collection
            temp_dir = tempfile.TemporaryDirectory()
            self._temp_dirs.append(temp_dir)  # Store the actual object
            
            # Extract repo name for subdirectory
            repo_name = repo_url.split("/")[-1]
            if repo_name.endswith(".git"):
                repo_name = repo_name[:-4]
            
            clone_path = os.path.join(temp_dir.name, repo_name)
            
            # Clone the repository
            logger.info(f"Cloning {repo_url} to {clone_path}")
            
            # Define clone options
            clone_kwargs = {
                "url": repo_url,
                "to_path": clone_path,
                "progress": None,  # No progress reporting
            }
            
            # Add branch if specified
            if branch:
                clone_kwargs["branch"] = branch
                
            # Add depth if specified (for shallow clones)
            if depth is not None:
                clone_kwargs["depth"] = depth
            
            # Perform the clone
            git.Repo.clone_from(**clone_kwargs)
            
            return clone_path
            
        except git.GitCommandError as e:
            error_msg = f"Git error while cloning repository: {str(e)}"
            logger.error(error_msg)
            raise RepositoryError(
                message=error_msg,
                repo_url=repo_url,
                branch=branch,
                details={"git_error": str(e)}
            )
        
        except Exception as e:
            error_msg = f"Failed to clone repository: {str(e)}"
            logger.error(error_msg)
            raise RepositoryError(
                message=error_msg,
                repo_url=repo_url,
                branch=branch,
                details={"error_type": type(e).__name__}
            )

    def get_github_repo(self, repo_url: str) -> Optional[GithubRepo.Repository]:
        """Get GitHub repository object from URL.
        
        Args:
            repo_url: URL of the repository
            
        Returns:
            GitHub repository object or None if not found or GitHub API not available
            
        Raises:
            RepositoryError: If GitHub API access fails
        """
        if not self.github:
            logger.debug("GitHub API not available. No token provided.")
            return None
            
        try:
            # Parse owner and repo name from URL
            parts = repo_url.rstrip("/").split("/")
            if "github.com" in parts:
                idx = parts.index("github.com")
                if len(parts) > idx + 2:
                    owner = parts[idx + 1]
                    repo_name = parts[idx + 2]
                    if repo_name.endswith(".git"):
                        repo_name = repo_name[:-4]
                    
                    # Get the repository
                    return self.github.get_repo(f"{owner}/{repo_name}")
            
            return None
            
        except UnknownObjectException:
            logger.debug(f"Repository not found on GitHub: {repo_url}")
            return None
            
        except GithubException as e:
            logger.warning(f"GitHub API error: {str(e)}")
            return None
            
        except Exception as e:
            logger.error(f"Unexpected error accessing GitHub API: {str(e)}")
            return None

    def get_repository_metadata(self, repo_path: str, repo_url: Optional[str] = None) -> Dict[str, Any]:
        """Extract metadata from a Git repository.

        Args:
            repo_path: Path to the repository
            repo_url: Optional URL of the repository (for GitHub API access)

        Returns:
            Dictionary of repository metadata
        """
        metadata = {
            "name": os.path.basename(repo_path),
            "ingestion_timestamp": datetime.now().isoformat(),
        }
        
        # Try to get GitHub metadata if URL is provided
        if repo_url and self.github:
            github_repo = self.get_github_repo(repo_url)
            if github_repo:
                metadata.update({
                    "github_id": github_repo.id,
                    "github_name": github_repo.name,
                    "github_full_name": github_repo.full_name,
                    "description": github_repo.description,
                    "primary_language": github_repo.language,
                    "stars": github_repo.stargazers_count,
                    "forks": github_repo.forks_count,
                    "open_issues": github_repo.open_issues_count,
                    "created_at": github_repo.created_at.isoformat() if github_repo.created_at else None,
                    "updated_at": github_repo.updated_at.isoformat() if github_repo.updated_at else None,
                    "license": github_repo.license.name if github_repo.license else None,
                })
                
                # Get languages from GitHub API
                try:
                    languages = github_repo.get_languages()
                    if languages:
                        metadata["languages"] = dict(languages)
                except Exception as e:
                    logger.debug(f"Could not get languages from GitHub API: {str(e)}")
        
        # Try to get Git metadata if it's a Git repository
        try:
            repo = git.Repo(repo_path)
            
            # Get branch name
            try:
                metadata["branch"] = repo.active_branch.name
            except TypeError:
                # This happens when in detached HEAD state
                metadata["branch"] = "HEAD detached"
            
            # Get commit info
            if repo.head.is_valid():
                commit = repo.head.commit
                metadata["commit_hash"] = commit.hexsha
                metadata["commit_author"] = f"{commit.author.name} <{commit.author.email}>"
                metadata["commit_date"] = datetime.fromtimestamp(commit.committed_date).isoformat()
                metadata["commit_message"] = commit.message.strip()
            
            # Get remote URL if available
            if repo.remotes:
                metadata["remote_url"] = repo.remotes.origin.url
                
            # Get commit count
            try:
                commit_count = len(list(repo.iter_commits()))
                metadata["commit_count"] = commit_count
            except Exception as e:
                logger.debug(f"Could not get commit count: {str(e)}")
                
        except (git.InvalidGitRepositoryError, git.NoSuchPathError, Exception) as e:
            # Not a Git repository or other error
            logger.debug(f"Could not get Git metadata: {str(e)}")
            
        return metadata

    def get_repository_stats(self, repo_path: str) -> Dict[str, Any]:
        """Generate statistics about the repository's codebase.

        Args:
            repo_path: Path to the repository

        Returns:
            Dictionary of codebase statistics
        """
        stats = {
            "file_count": 0,
            "directory_count": 0,
            "extension_counts": {},
            "total_size_bytes": 0,
        }
        
        try:
            # Walk the file system
            for root, dirs, files in os.walk(repo_path):
                # Skip .git directory
                if '.git' in dirs:
                    dirs.remove('.git')
                
                # Count directories
                stats["directory_count"] += len(dirs)
                
                # Process files
                for file in files:
                    file_path = os.path.join(root, file)
                    
                    # Count files
                    stats["file_count"] += 1
                    
                    # Extract extension
                    _, ext = os.path.splitext(file)
                    if ext:
                        ext = ext[1:]  # Remove the leading dot
                        stats["extension_counts"][ext] = stats["extension_counts"].get(ext, 0) + 1
                    
                    # Count size
                    try:
                        stats["total_size_bytes"] += os.path.getsize(file_path)
                    except Exception:
                        pass
                        
        except Exception as e:
            logger.warning(f"Error generating repository stats: {str(e)}")
            
        return stats

    def cleanup(self) -> None:
        """Clean up temporary directories created for repository cloning."""
        for temp_dir in self._temp_dirs:
            try:
                # Call cleanup on the TemporaryDirectory object
                temp_dir.cleanup()
                logger.debug(f"Cleaned up temporary directory: {temp_dir.name}")
            except Exception as e:
                logger.error(f"Failed to clean up temporary directory {temp_dir.name}: {str(e)}")
        
        self._temp_dirs = []

    def __del__(self):
        """Clean up resources when the object is garbage collected."""
        self.cleanup()


class RepositoryManager:
    """Manages repository nodes in the graph database.

    This class creates and updates repository nodes in the database during ingestion.
    """

    def __init__(self, connector: Neo4jConnector):
        """Initialize the repository manager.

        Args:
            connector: Neo4j connector instance
        """
        self.connector = connector

    def create_repository_node(self, ingestion_id: str, codebase_path: str, 
                               repo_url: Optional[str] = None, 
                               metadata: Optional[Dict[str, Any]] = None) -> int:
        """Create a repository node in the database.

        Args:
            ingestion_id: ID of the ingestion process
            codebase_path: Path to the codebase
            repo_url: URL of the Git repository (optional)
            metadata: Additional repository metadata (optional)

        Returns:
            ID of the created node
        
        Raises:
            DatabaseError: If node creation fails
        """
        # Start with basic properties
        properties = {
            "ingestion_id": ingestion_id,
            "path": codebase_path,
            "ingestion_start_time": datetime.now().isoformat(),
            "state": "processing",
            "name": os.path.basename(codebase_path),
        }
        
        # Add repository URL if provided
        if repo_url:
            properties["url"] = repo_url
        
        # Add additional metadata if provided
        if metadata:
            properties.update(metadata)
        
        try:
            # Create the repository node
            node_id = self.connector.create_node(NodeLabels.REPOSITORY, properties)
            
            if not node_id:
                raise DatabaseError(
                    message="Failed to create repository node in database",
                    details={
                        "ingestion_id": ingestion_id,
                        "codebase_path": codebase_path,
                        "repo_url": repo_url
                    }
                )
            
            return node_id
        except Exception as e:
            # Catch any database-related exceptions and wrap them
            raise DatabaseError(
                message=f"Database error while creating repository node: {str(e)}",
                details={
                    "ingestion_id": ingestion_id,
                    "codebase_path": codebase_path,
                    "repo_url": repo_url,
                    "error_type": type(e).__name__
                },
                db_error=str(e)
            )

    def update_status(self, repo_node_id: int, status_data: Dict[str, Any]) -> None:
        """Update the repository node with status information.

        Args:
            repo_node_id: ID of the repository node
            status_data: Status data to update
            
        Raises:
            DatabaseError: If update query fails
        """
        try:
            # Update the repository node
            query = (
                "MATCH (repo:Repository) "
                "WHERE id(repo) = $repo_id "
                "SET repo += $status, "
                "repo.last_updated = $last_updated"
            )
            
            params = {
                "repo_id": repo_node_id,
                "status": status_data,
                "last_updated": datetime.now().isoformat()
            }
            
            self.connector.run_query(query, params)
        except Exception as e:
            # Wrap any database exception in our custom exception
            raise DatabaseError(
                message=f"Failed to update repository status: {str(e)}",
                query=query,
                db_error=str(e),
                details={
                    "repo_node_id": repo_node_id,
                    "status_keys": list(status_data.keys()) if status_data else []
                }
            )
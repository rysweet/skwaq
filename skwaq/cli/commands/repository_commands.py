"""Command handlers for repository management."""

import argparse
import json
import os
from pathlib import Path
from typing import Dict, List, Optional, Any

from ...ingestion.code_ingestion import ingest_repository, list_repositories
from ...db.neo4j_connector import get_connector
from ..ui.console import console, success, error, info
from ..ui.progress import create_status_indicator, create_progress_bar
from ..ui.formatters import format_repository_table, format_panel
from ..ui.prompts import prompt_for_confirmation
from .base import CommandHandler, handle_command_error

class RepositoryCommandHandler(CommandHandler):
    """Handler for repository commands."""
    
    @handle_command_error
    async def handle(self) -> int:
        """Handle the repository command.
        
        Returns:
            Exit code (0 for success, non-zero for errors)
        """
        if not hasattr(self.args, 'repo_command') or not self.args.repo_command:
            error("No repository command specified")
            return 1
            
        # Dispatch to appropriate subcommand handler
        if self.args.repo_command == "list":
            return await self._handle_list()
        elif self.args.repo_command == "add":
            return await self._handle_add()
        elif self.args.repo_command == "github":
            return await self._handle_github()
        elif self.args.repo_command == "delete":
            return await self._handle_delete()
        else:
            error(f"Unknown repository command: {self.args.repo_command}")
            return 1
    
    async def _handle_list(self) -> int:
        """Handle the list command.
        
        Returns:
            Exit code (0 for success, non-zero for errors)
        """
        output_format = getattr(self.args, "format", "table")
        
        with create_status_indicator("[bold blue]Fetching repository list...", spinner="dots") as status:
            repos = await list_repositories()
            status.update("[bold green]Repositories retrieved!")
        
        if not repos:
            info("No repositories found.")
            return 0
        
        if output_format == "json":
            console.print_json(json.dumps(repos, indent=2))
        else:
            console.print(format_repository_table(repos))
        
        return 0
    
    async def _handle_add(self) -> int:
        """Handle the add command.
        
        Returns:
            Exit code (0 for success, non-zero for errors)
        """
        path = self.args.path
        include_patterns = self.args.include
        exclude_patterns = self.args.exclude
        
        # Verify path exists
        if not os.path.exists(path):
            error(f"Path does not exist: {path}")
            return 1
            
        info(f"Ingesting repository from path: {path}")
        
        # Use progress bar when ingesting
        with create_progress_bar(
            description=f"Ingesting {Path(path).name}",
            unit="files",
            total=100  # Will be updated by the ingest_repository function
        ) as progress:
            task_id = progress.add_task("Ingesting", total=100)
            
            # Define progress callback
            def update_progress(current: int, total: int) -> None:
                progress.update(task_id, completed=current, total=total)
            
            # Ingest repository
            result = await ingest_repository(
                repo_path_or_url=path,
                is_github_url=False,
                include_patterns=include_patterns,
                exclude_patterns=exclude_patterns,
                show_progress=True,
                progress_callback=update_progress
            )
        
        # Display result
        success(f"Repository ingested successfully: {result['repository_name']}")
        info(f"Repository ID: {result['repository_id']}")
        info(f"Files processed: {result['file_count']} ({result['code_files_processed']} code files)")
        
        return 0
    
    async def _handle_github(self) -> int:
        """Handle the github command.
        
        Returns:
            Exit code (0 for success, non-zero for errors)
        """
        url = self.args.url
        token = self.args.token or os.environ.get("GITHUB_TOKEN")
        branch = self.args.branch
        include_patterns = self.args.include
        exclude_patterns = self.args.exclude
        
        if not token:
            info("No GitHub token provided. Using unauthenticated GitHub API (rate limits apply).")
            info("Set GITHUB_TOKEN environment variable or use --token for authenticated access.")
        
        info(f"Ingesting repository from GitHub: {url}")
        
        # Use progress bar when ingesting
        with create_progress_bar(
            description=f"Ingesting {url}",
            unit="files",
            total=100  # Will be updated by the ingest_repository function
        ) as progress:
            task_id = progress.add_task("Ingesting", total=100)
            
            # Define progress callback
            def update_progress(current: int, total: int) -> None:
                progress.update(task_id, completed=current, total=total)
            
            # Ingest repository
            result = await ingest_repository(
                repo_path_or_url=url,
                is_github_url=True,
                include_patterns=include_patterns,
                exclude_patterns=exclude_patterns,
                github_token=token,
                branch=branch,
                show_progress=True,
                progress_callback=update_progress
            )
        
        # Display result
        success(f"Repository ingested successfully: {result['repository_name']}")
        info(f"Repository ID: {result['repository_id']}")
        info(f"Files processed: {result['file_count']} ({result['code_files_processed']} code files)")
        
        return 0
    
    async def _handle_delete(self) -> int:
        """Handle the delete command.
        
        Returns:
            Exit code (0 for success, non-zero for errors)
        """
        repo_id = self.args.id
        force = self.args.force
        
        # Verify repository exists
        connector = get_connector()
        repo = connector.run_query(
            "MATCH (r:Repository) WHERE id(r) = $id RETURN r.name as name",
            {"id": int(repo_id)}
        )
        
        if not repo:
            error(f"Repository not found: {repo_id}")
            return 1
        
        repo_name = repo[0]["name"]
        
        # Confirm deletion
        if not force:
            confirmed = prompt_for_confirmation(
                f"Are you sure you want to delete repository '{repo_name}' (ID: {repo_id})?"
            )
            
            if not confirmed:
                info("Deletion cancelled.")
                return 0
        
        # Delete repository
        with create_status_indicator(f"[bold blue]Deleting repository '{repo_name}'...", spinner="dots") as status:
            # Delete all connected nodes recursively
            connector.run_query(
                """
                MATCH (r:Repository)
                WHERE id(r) = $id
                OPTIONAL MATCH (r)-[*1..2]-(connected)
                DETACH DELETE connected, r
                """,
                {"id": int(repo_id)}
            )
            status.update(f"[bold green]Repository '{repo_name}' deleted!")
        
        success(f"Repository '{repo_name}' deleted successfully.")
        return 0
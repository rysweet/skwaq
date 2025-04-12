"""Command handlers for repository management."""

import asyncio
import json
import os
from pathlib import Path

from ...core.openai_client import get_openai_client
from ...db.neo4j_connector import get_connector
from ...ingestion import Ingestion
from ..ui.console import console, error, info, success
from ..ui.formatters import format_repository_table
from ..ui.progress import create_progress_bar
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
        if not hasattr(self.args, "repo_command") or not self.args.repo_command:
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

        # Query Neo4j for repositories
        info("[bold blue]Fetching repository list...")

        # Get database connector
        db = get_connector()

        # Query repositories
        query = """
        MATCH (r:Repository)
        RETURN r.name as name, 
               r.url as url,
               r.ingestion_id as id,
               r.state as state,
               r.files_processed as file_count,
               r.start_time as created,
               r.end_time as completed
        """

        # Execute the query
        results = db.run_query(query)

        # Format repositories
        repos = []
        for repo in results:
            # Convert to standard format
            repos.append(
                {
                    "name": repo.get("name", "Unknown"),
                    "url": repo.get("url", ""),
                    "id": repo.get("id", ""),
                    "status": repo.get("state", "Unknown"),
                    "file_count": repo.get("file_count", 0),
                    "created": repo.get("created"),
                    "completed": repo.get("completed"),
                }
            )

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

        # Verify path exists
        if not os.path.exists(path):
            error(f"Path does not exist: {path}")
            return 1

        info(f"Ingesting repository from path: {path}")

        # Get OpenAI client for LLM processing if needed
        parse_only = getattr(self.args, "parse_only", False)

        model_client = None
        if not parse_only:
            try:
                model_client = get_openai_client(async_mode=True)
                info("Using LLM for code summarization")
            except Exception as e:
                error(f"Failed to initialize OpenAI client: {str(e)}")
                error("Defaulting to parse-only mode (no code summarization)")
                parse_only = True

        # Create ingestion instance
        ingestion = Ingestion(
            local_path=path,
            model_client=model_client,
            parse_only=parse_only,
            max_parallel=getattr(self.args, "threads", 3),
        )

        # Start ingestion process
        try:
            # Show starting message
            info(f"[bold blue]Preparing repository: {Path(path).name}...")

            # Start the ingestion process
            ingestion_id = await ingestion.ingest()
            info(f"[bold blue]Ingestion started with ID: {ingestion_id}")

            # Create progress tracking
            with create_progress_bar(
                description=f"Ingesting {Path(path).name}", unit="files"
            ) as progress:
                task = progress.add_task("Ingesting", total=100)

                # Poll for status updates
                completed = False
                while not completed:
                    # Get current status
                    status_obj = await ingestion.get_status(ingestion_id)

                    # Update progress bar
                    if status_obj.total_files > 0:
                        progress.update(
                            task,
                            completed=status_obj.files_processed,
                            total=status_obj.total_files,
                            description=f"[cyan]{status_obj.message}",
                        )
                    else:
                        progress.update(
                            task,
                            completed=status_obj.progress,
                            total=100,
                            description=f"[cyan]{status_obj.message}",
                        )

                    # Check if completed or failed
                    if status_obj.state in ["completed", "failed"]:
                        completed = True
                        if status_obj.state == "completed":
                            progress.update(
                                task,
                                completed=100,
                                total=100,
                                description="[green]Completed",
                            )
                        else:
                            progress.update(
                                task, description=f"[red]Failed: {status_obj.error}"
                            )
                    else:
                        # Wait before polling again
                        await asyncio.sleep(1)

            # Get final status
            final_status = await ingestion.get_status(ingestion_id)

            # Show results
            if final_status.state == "completed":
                info("[bold green]Repository ingestion completed successfully!")
                success(f"Repository ingestion completed (ID: {ingestion_id})")
                info(f"Files processed: {final_status.files_processed}")
                info(f"Time elapsed: {final_status.time_elapsed:.2f} seconds")
                return 0
            else:
                error(f"Ingestion failed: {final_status.error}")
                return 1

        except Exception as e:
            error(f"Failed to ingest repository: {str(e)}")
            return 1

    async def _handle_github(self) -> int:
        """Handle the github command.

        Returns:
            Exit code (0 for success, non-zero for errors)
        """
        url = self.args.url
        branch = self.args.branch

        info(f"Ingesting repository from GitHub: {url}")

        # Get OpenAI client for LLM processing if needed
        parse_only = getattr(self.args, "parse_only", False)

        model_client = None
        if not parse_only:
            try:
                model_client = get_openai_client(async_mode=True)
                info("Using LLM for code summarization")
            except Exception as e:
                error(f"Failed to initialize OpenAI client: {str(e)}")
                error("Defaulting to parse-only mode (no code summarization)")
                parse_only = True

        # Create ingestion instance
        ingestion = Ingestion(
            repo=url,
            branch=branch,
            model_client=model_client,
            parse_only=parse_only,
            max_parallel=getattr(self.args, "threads", 3),
        )

        # Start ingestion process
        try:
            # Show starting message
            info(f"[bold blue]Cloning repository: {url}...")

            # Start the ingestion process
            ingestion_id = await ingestion.ingest()
            info(f"[bold blue]Ingestion started with ID: {ingestion_id}")

            # Create progress tracking
            with create_progress_bar(
                description=f"Ingesting {url}", unit="files"
            ) as progress:
                task = progress.add_task("Ingesting", total=100)

                # Poll for status updates
                completed = False
                while not completed:
                    # Get current status
                    status_obj = await ingestion.get_status(ingestion_id)

                    # Update progress bar
                    if status_obj.total_files > 0:
                        progress.update(
                            task,
                            completed=status_obj.files_processed,
                            total=status_obj.total_files,
                            description=f"[cyan]{status_obj.message}",
                        )
                    else:
                        progress.update(
                            task,
                            completed=status_obj.progress,
                            total=100,
                            description=f"[cyan]{status_obj.message}",
                        )

                    # Check if completed or failed
                    if status_obj.state in ["completed", "failed"]:
                        completed = True
                        if status_obj.state == "completed":
                            progress.update(
                                task,
                                completed=100,
                                total=100,
                                description="[green]Completed",
                            )
                        else:
                            progress.update(
                                task, description=f"[red]Failed: {status_obj.error}"
                            )
                    else:
                        # Wait before polling again
                        await asyncio.sleep(1)

            # Get final status
            final_status = await ingestion.get_status(ingestion_id)

            # Show results
            if final_status.state == "completed":
                info("[bold green]Repository ingestion completed successfully!")
                success(f"Repository ingestion completed (ID: {ingestion_id})")
                info(f"Files processed: {final_status.files_processed}")
                info(f"Time elapsed: {final_status.time_elapsed:.2f} seconds")
                return 0
            else:
                error(f"Ingestion failed: {final_status.error}")
                return 1

        except Exception as e:
            error(f"Failed to ingest repository: {str(e)}")
            return 1

    async def _handle_delete(self) -> int:
        """Handle the delete command.

        Returns:
            Exit code (0 for success, non-zero for errors)
        """
        repo_id = self.args.id
        force = self.args.force

        # Verify repository exists
        connector = get_connector()

        # First try to find by ingestion_id
        repo_query = """
        MATCH (r:Repository)
        WHERE r.ingestion_id = $id 
        RETURN r.name as name, r.ingestion_id as ingestion_id
        """

        repo = connector.run_query(repo_query, {"id": repo_id})

        # If not found, try by node ID if it looks like a number
        if not repo and repo_id.isdigit():
            repo = connector.run_query(
                """
                MATCH (r:Repository)
                WHERE elementId(r) = $id
                RETURN r.name as name, r.ingestion_id as ingestion_id
                """,
                {"id": int(repo_id)},
            )

        if not repo:
            error(f"Repository not found: {repo_id}")
            return 1

        repo_name = repo[0]["name"]
        ingestion_id = repo[0]["ingestion_id"]

        # Confirm deletion
        if not force:
            confirmed = prompt_for_confirmation(
                f"Are you sure you want to delete repository '{repo_name}' (ID: {ingestion_id})?"
            )

            if not confirmed:
                info("Deletion cancelled.")
                return 0

        # Delete repository
        info(f"[bold blue]Deleting repository '{repo_name}'...")

        # Delete all connected nodes recursively
        delete_query = """
        MATCH (r:Repository)
        WHERE r.ingestion_id = $id
        OPTIONAL MATCH (r)-[*]-(connected)
        DETACH DELETE connected, r
        """

        connector.run_query(delete_query, {"id": ingestion_id})
        info(f"[bold green]Repository '{repo_name}' deleted!")

        success(f"Repository '{repo_name}' deleted successfully.")
        return 0

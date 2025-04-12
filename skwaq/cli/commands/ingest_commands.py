"""Command handlers for ingestion commands."""

import asyncio
from pathlib import Path
from typing import Optional

from ...core.openai_client import get_openai_client
from ...ingestion import Ingestion
from ..ui.console import error, info, success
from ..ui.progress import create_progress_bar
from .base import CommandHandler, handle_command_error


class IngestCommandHandler(CommandHandler):
    """Handler for the ingest command."""

    @handle_command_error
    async def handle(self) -> int:
        """Handle the ingest command.

        Returns:
            Exit code (0 for success, non-zero for errors)
        """
        source_type = self.args.type
        source_path = Path(self.args.source)

        if source_type == "repo":
            source_str = str(source_path)
            # Fix for URL validation - improve "startswith" check and normalize the URL
            is_url = source_str.startswith(("http://", "https://"))

            # For URLs, perform a basic check for proper format
            info(f"Processing source: {source_str}, is_url={is_url}")
            if source_str.startswith(("http:", "https:")):
                # Normalize URL to ensure double slash after protocol
                if "://" not in source_str:
                    # Fix URLs like "https:/github.com" to "https://github.com"
                    for prefix in ["http:/", "https:/"]:
                        if source_str.startswith(prefix) and not source_str.startswith(
                            prefix + "/"
                        ):
                            fixed_url = prefix + "/" + source_str[len(prefix) :]
                            info(f"Normalized URL from {source_str} to: {fixed_url}")
                            source_str = fixed_url
                            source_path = Path(source_str)
                            is_url = True
                            break
            elif not source_path.exists():
                # Not a URL and path doesn't exist
                error(
                    f"Error: {source_path} does not exist or is not a valid repository URL."
                )
                return 1

            return await self._handle_repo_ingestion(source_path, source_str)
        else:
            error("Currently only 'repo' ingestion type is supported.")
            return 1

    async def _handle_repo_ingestion(
        self, source_path: Path, source_str: Optional[str] = None
    ) -> int:
        """Handle repository ingestion.

        Args:
            source_path: Path to the repository or repository URL
            source_str: Optional normalized string representation of source_path

        Returns:
            Exit code (0 for success, non-zero for errors)
        """
        # Set up parameters for ingestion
        if source_str is None:
            source_str = str(source_path)

        # Check if it's a URL using proper protocol handling
        is_url = "://" in source_str and (
            source_str.startswith("http:") or source_str.startswith("https:")
        )

        # Convert to absolute path if it's a local path (needed for Docker)
        if not is_url and not source_path.is_absolute():
            source_path = source_path.absolute()
            source_str = str(source_path)
            info(f"Using absolute path: {source_str}")

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
        if is_url:
            info(f"Ingesting repository from URL: {source_str}")
            branch = getattr(self.args, "branch", None)
            ingestion = Ingestion(
                repo=source_str,  # Use the normalized URL
                branch=branch,
                model_client=model_client,
                parse_only=parse_only,
                max_parallel=getattr(self.args, "threads", 3),
            )
        else:
            info(f"Ingesting local repository from: {source_str}")
            ingestion = Ingestion(
                local_path=source_str,
                model_client=model_client,
                parse_only=parse_only,
                max_parallel=getattr(self.args, "threads", 3),
            )

        # Start ingestion process
        try:
            # Show starting message
            info("[bold blue]Starting ingestion...")

            # Start the ingestion process
            ingestion_id = await ingestion.ingest()
            info(f"[bold blue]Ingestion started with ID: {ingestion_id}")

            # Create a single progress bar for tracking
            with create_progress_bar(
                description="Ingesting files", unit="files"
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

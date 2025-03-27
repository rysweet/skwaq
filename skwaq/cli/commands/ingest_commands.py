"""Command handlers for ingestion commands."""

import argparse
import os
from pathlib import Path
from typing import Dict, List, Optional, Any

from ...ingestion.code_ingestion import ingest_repository
from ...ingestion.knowledge_ingestion import ingest_knowledge_source
from ...ingestion.cwe_ingestion import ingest_cve_source
from ..ui.console import console, success, error, info
from ..ui.progress import create_status_indicator
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
        
        if not source_path.exists():
            error(f"Error: {source_path} does not exist.")
            return 1
        
        if source_type == "repo":
            return await self._handle_repo_ingestion(source_path)
        elif source_type == "kb":
            return await self._handle_kb_ingestion(source_path)
        elif source_type == "cve":
            return await self._handle_cve_ingestion(source_path)
        else:
            error("Unknown ingestion type.")
            return 1
    
    async def _handle_repo_ingestion(self, source_path: Path) -> int:
        """Handle repository ingestion.
        
        Args:
            source_path: Path to the repository
            
        Returns:
            Exit code (0 for success, non-zero for errors)
        """
        info(f"Ingesting repository from: {source_path}")
        
        with create_status_indicator("[bold blue]Ingesting repository...", spinner="dots") as status:
            # Import here to avoid circular imports
            from ...ingestion.code_ingestion import ingest_repository
            
            try:
                result = await ingest_repository(str(source_path))
                status.update("[bold green]Repository ingestion completed!")
                
                # Display repository information
                success(f"Repository ingested: {result.get('repository_name', 'Unknown')}")
                info(f"Files processed: {result.get('file_count', 0)}")
                info(f"Code files: {result.get('code_files_processed', 0)}")
                
                return 0
            except Exception as e:
                status.update(f"[bold red]Repository ingestion failed: {str(e)}")
                error(f"Failed to ingest repository: {str(e)}")
                return 1
    
    async def _handle_kb_ingestion(self, source_path: Path) -> int:
        """Handle knowledge base ingestion.
        
        Args:
            source_path: Path to the knowledge source
            
        Returns:
            Exit code (0 for success, non-zero for errors)
        """
        info(f"Ingesting knowledge source from: {source_path}")
        
        with create_status_indicator("[bold blue]Ingesting knowledge source...", spinner="dots") as status:
            # Import here to avoid circular imports
            from ...ingestion.knowledge_ingestion import ingest_knowledge_source
            
            try:
                result = await ingest_knowledge_source(str(source_path))
                status.update("[bold green]Knowledge source ingestion completed!")
                
                # Display knowledge information
                success(f"Knowledge source ingested: {result.get('source_name', 'Unknown')}")
                info(f"Documents processed: {result.get('document_count', 0)}")
                
                return 0
            except Exception as e:
                status.update(f"[bold red]Knowledge ingestion failed: {str(e)}")
                error(f"Failed to ingest knowledge source: {str(e)}")
                return 1
    
    async def _handle_cve_ingestion(self, source_path: Path) -> int:
        """Handle CVE/CWE ingestion.
        
        Args:
            source_path: Path to the CVE source
            
        Returns:
            Exit code (0 for success, non-zero for errors)
        """
        info(f"Ingesting CVE/CWE source from: {source_path}")
        
        with create_status_indicator("[bold blue]Ingesting CVE/CWE source...", spinner="dots") as status:
            # Import here to avoid circular imports
            from ...ingestion.cwe_ingestion import ingest_cve_source
            
            try:
                result = await ingest_cve_source(str(source_path))
                status.update("[bold green]CVE/CWE source ingestion completed!")
                
                # Display CVE information
                success(f"CVE/CWE source ingested: {result.get('source_name', 'Unknown')}")
                info(f"Entries processed: {result.get('entry_count', 0)}")
                
                return 0
            except Exception as e:
                status.update(f"[bold red]CVE/CWE ingestion failed: {str(e)}")
                error(f"Failed to ingest CVE/CWE source: {str(e)}")
                return 1
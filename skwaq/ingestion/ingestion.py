"""Code ingestion module for Skwaq."""

import asyncio
import logging
import os
import time
from dataclasses import asdict, dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple, Union

from ..db.neo4j_connector import NodeLabels, RelationshipTypes, get_connector
from .exceptions import IngestionError
from .filesystem import CodebaseFileSystem
from .parsers.blarify_parser import BlarifyParser
from .repository import RepositoryHandler, RepositoryManager
from .summarizers.llm_summarizer import LLMSummarizer

logger = logging.getLogger(__name__)


@dataclass
class IngestionStatus:
    """Status of an ingestion process."""

    id: str
    state: str = "pending"
    progress: float = 0.0
    start_time: float = field(default_factory=time.time)
    end_time: Optional[float] = None
    error: Optional[str] = None
    files_processed: int = 0
    total_files: int = 0
    errors: List[str] = field(default_factory=list)
    message: str = "Pending"
    parsing_stats: Dict[str, Any] = field(default_factory=dict)
    summarization_stats: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert the status to a dictionary.

        Returns:
            Dictionary representation of the status
        """
        return asdict(self)


class IngestionType(str, Enum):
    """Type of ingestion."""

    REPOSITORY = "repository"
    KNOWLEDGE_BASE = "knowledge_base"
    CVE = "cve"
    AST = "ast"


class Ingestion:
    """Ingestion process for code, knowledge, and other data."""

    def __init__(
        self,
        ingestion_type: IngestionType,
        repo: Optional[str] = None,
        local_path: Optional[str] = None,
        branch: Optional[str] = None,
        include_patterns: Optional[List[str]] = None,
        exclude_patterns: Optional[List[str]] = None,
        parse_only: bool = False,
        max_parallel: int = 3,
    ):
        """Initialize the ingestion process.

        Args:
            ingestion_type: Type of ingestion
            repo: Repository URL (for repository ingestion)
            local_path: Local path (for local ingestion)
            branch: Git branch to checkout (for repository ingestion)
            include_patterns: Glob patterns to include
            exclude_patterns: Glob patterns to exclude
            parse_only: Only parse the codebase, don't generate summaries
            max_parallel: Maximum number of parallel tasks
        """
        self.ingestion_type = ingestion_type
        self.repo = repo
        self.local_path = local_path
        self.branch = branch
        self.include_patterns = include_patterns or []
        self.exclude_patterns = exclude_patterns or []
        self.parse_only = parse_only
        self.max_parallel = max_parallel

        # Set up database connector
        self.db_connector = get_connector()

        # Set up repository manager
        self.repo_manager = RepositoryManager(self.db_connector)

        # Set up repository handler if needed
        if ingestion_type == IngestionType.REPOSITORY and repo:
            self.repo_handler = RepositoryHandler()

        # Set up model client for summarization if needed
        if not parse_only:
            from ...core.openai_client import get_client

            self.model_client = get_client()

        # Active ingestion processes
        self._active_ingestions = {}

    def start_ingestion(self) -> str:
        """Start the ingestion process.

        Returns:
            Ingestion ID
        """
        # Generate unique ingestion ID
        ingestion_id = f"ing-{int(time.time())}"

        # Create status
        status = IngestionStatus(id=ingestion_id)
        self._active_ingestions[ingestion_id] = status

        # Launch the ingestion in a background task
        asyncio.create_task(self._run_ingestion(ingestion_id))

        return ingestion_id

    def get_status(self, ingestion_id: str) -> IngestionStatus:
        """Get the status of an ingestion process.

        Args:
            ingestion_id: ID of the ingestion process

        Returns:
            Status of the ingestion process

        Raises:
            ValueError: If the ingestion ID is not found
        """
        if ingestion_id not in self._active_ingestions:
            # Check if the status exists in the database
            status_node = self._load_status_from_db(ingestion_id)
            if status_node:
                # Reconstruct status from database
                status = IngestionStatus(
                    id=ingestion_id,
                    state=status_node.get("state", "unknown"),
                    progress=status_node.get("progress", 0.0),
                    start_time=status_node.get("start_time", 0.0),
                    end_time=status_node.get("end_time"),
                    error=status_node.get("error"),
                    files_processed=status_node.get("files_processed", 0),
                    total_files=status_node.get("total_files", 0),
                    errors=status_node.get("errors", []),
                    message=status_node.get("message", "Unknown status"),
                    parsing_stats=status_node.get("parsing_stats", {}),
                    summarization_stats=status_node.get("summarization_stats", {}),
                )
                return status

            raise ValueError(f"Ingestion ID not found: {ingestion_id}")

        return self._active_ingestions[ingestion_id]

    def _load_status_from_db(self, ingestion_id: str) -> Optional[Dict[str, Any]]:
        """Load ingestion status from the database.

        Args:
            ingestion_id: ID of the ingestion process

        Returns:
            Dictionary of status data or None if not found
        """
        query = (
            f"MATCH (s:{NodeLabels.REPOSITORY}) "
            f"WHERE s.ingestion_id = $ingestion_id "
            f"RETURN s"
        )

        results = self.db_connector.run_query(query, {"ingestion_id": ingestion_id})

        if results and len(results) > 0:
            return results[0]["s"]

        return None

    async def _run_ingestion(self, ingestion_id: str) -> None:
        """Run the ingestion process in the background.

        Args:
            ingestion_id: ID of the ingestion process
        """
        status = self._active_ingestions[ingestion_id]
        codebase_path = None

        try:
            # Update status to processing
            status.state = "processing"
            status.message = "Preparing codebase"

            # Get the codebase
            if self.local_path:
                codebase_path = self.local_path
                status.message = f"Using local codebase at {codebase_path}"
            else:
                # Clone the repo
                status.message = f"Cloning repository {self.repo}"
                codebase_path = self.repo_handler.clone_repository(
                    self.repo, self.branch
                )
                status.message = f"Cloned repository to {codebase_path}"

            # Get repository metadata
            repo_metadata = self.repo_handler.get_repository_metadata(codebase_path)

            # Create repository node
            repo_node_id = self.repo_manager.create_repository_node(
                ingestion_id, codebase_path, self.repo, repo_metadata
            )

            # Create filesystem interface
            fs = CodebaseFileSystem(codebase_path)

            # Count files
            status.message = "Counting files..."
            files_to_process = fs.find_files(
                include_patterns=self.include_patterns,
                exclude_patterns=self.exclude_patterns,
            )
            status.total_files = len(files_to_process)
            status.message = f"Found {status.total_files} files to process"
            status.progress = 10.0

            # Use the Blarify parser
            parser = BlarifyParser()

            # Parse files
            status.message = "Parsing files..."
            status.progress = 20.0

            parse_result = await parser.parse_files(
                files_to_process,
                repo_node_id,
                codebase_path,
                status_callback=lambda parsed, total, path: self._update_parsing_status(
                    status, parsed, total, path
                ),
            )

            # Update status with parsing result
            status.parsing_stats = parse_result.get("stats", {})
            status.files_processed = parse_result.get("files_processed", 0)
            status.errors.extend(parse_result.get("errors", []))
            status.message = f"Parsed {status.files_processed} files"
            status.progress = 50.0

            # Generate summaries if not parse_only
            if not self.parse_only:
                status.message = "Generating summaries..."
                status.progress = 60.0

                # Initialize summarizer
                summarizer = LLMSummarizer(
                    self.db_connector, self.model_client, max_concurrent=self.max_parallel
                )

                # Generate summaries
                summary_result = await summarizer.summarize_repository(
                    repo_node_id,
                    status_callback=lambda summarized, total, path: self._update_summarization_status(
                        status, summarized, total, path
                    ),
                )

                # Get AST nodes for summarization
                status.message = "Generating AST summaries..."
                ast_query = """
                MATCH (repo:Repository)-[:CONTAINS]->(file:File)-[:CONTAINS]->(ast)
                WHERE id(repo) = $repo_id AND 
                      (
                        'Function' IN labels(ast) OR 
                        'Class' IN labels(ast) OR 
                        'Method' IN labels(ast)
                      ) AND
                      NOT EXISTS((ast)<-[:DESCRIBES]-(:CodeSummary))
                RETURN 
                    id(ast) as ast_id,
                    ast.name as name, 
                    ast.code as code,
                    labels(ast) as labels,
                    id(file) as file_id,
                    file.name as file_name,
                    file.path as path
                LIMIT 500
                """
                
                ast_nodes = self.db_connector.run_query(
                    ast_query, {"repo_id": repo_node_id}
                )
                
                # Set up a semaphore to limit concurrent summarization tasks
                semaphore = asyncio.Semaphore(self.max_parallel)
                
                # Create tasks for each AST node
                ast_summary_tasks = []
                for ast_node in ast_nodes:
                    task = self._generate_ast_summary(
                        ast_node, self.db_connector, self.model_client, semaphore
                    )
                    ast_summary_tasks.append(task)
                
                # Run all tasks concurrently with semaphore limiting
                if ast_summary_tasks:
                    ast_results = await asyncio.gather(*ast_summary_tasks)
                    ast_summaries_created = sum(1 for result in ast_results if result and result.get("created"))
                    
                    # Add AST summary stats to summary result
                    if "ast_summaries_created" not in summary_result["stats"]:
                        summary_result["stats"]["ast_summaries_created"] = 0
                    summary_result["stats"]["ast_summaries_created"] += ast_summaries_created
                    
                    status.message = f"Generated {ast_summaries_created} AST summaries"
                
                # Update summarization stats
                status.summarization_stats = summary_result.get("stats", {})
                status.files_processed += summary_result.get("files_processed", 0)
                status.errors.extend(summary_result.get("errors", []))
                status.message = f"Generated summaries for {summary_result.get('files_processed', 0)} files and {summary_result.get('stats', {}).get('ast_summaries_created', 0)} AST nodes"
                status.progress = 90.0

            # Final steps
            status.state = "completed"
            status.progress = 100.0
            status.end_time = time.time()
            status.message = "Ingestion completed successfully"

            # Update the repository node with final status
            self.repo_manager.update_status(repo_node_id, status.to_dict())

        except Exception as e:
            logger.error(f"Ingestion failed: {str(e)}", exc_info=True)
            status.state = "failed"
            status.error = str(e)
            status.end_time = time.time()
            status.message = f"Ingestion failed: {str(e)}"

            # Update the repository node with error status if it was created
            if "repo_node_id" in locals() and repo_node_id:
                self.repo_manager.update_status(repo_node_id, status.to_dict())

        finally:
            # Clean up repository handler resources
            if hasattr(self, "repo_handler"):
                self.repo_handler.cleanup()

    async def _generate_ast_summary(
        self, ast_node: Dict, connector: Any, model_client: Any, semaphore: asyncio.Semaphore
    ) -> Dict:
        """Generate a summary for a single AST node.
        
        Args:
            ast_node: AST node data
            connector: Database connector
            model_client: OpenAI client
            semaphore: Asyncio semaphore for limiting concurrency
            
        Returns:
            Dictionary with result information
        """
        async with semaphore:
            try:
                ast_id = ast_node["ast_id"]
                ast_name = ast_node["name"]
                ast_code = ast_node["code"]
                ast_type = ast_node["labels"][0] if ast_node["labels"] else "Unknown"
                file_name = ast_node["file_name"] or "Unknown"
                
                if not ast_code or len(ast_code.strip()) < 10:
                    return {"processed": True, "created": False, "reason": "insufficient_code"}
                
                # Create prompt
                ast_prompt = f"""
                You are analyzing a specific {ast_type} from a larger file.
                
                File name: {file_name}
                {ast_type} name: {ast_name}
                
                Your task is to create a detailed, accurate summary of this {ast_type.lower()}'s:
                1. Purpose and functionality 
                2. Parameters, return values, and important logic
                3. Role within the larger file
                4. Any potential security implications
                5. How it interacts with other components
                
                {ast_type} code:
                ```
                {ast_code}
                ```
                
                Summary:
                """
                
                # Generate summary
                summary_start_time = time.time()
                ast_summary = await model_client.get_completion(
                    ast_prompt, temperature=0.3
                )
                summary_time = time.time() - summary_start_time
                
                # Create summary node
                summary_node_id = connector.create_node(
                    "CodeSummary",
                    {
                        "summary": ast_summary,
                        "file_name": file_name,
                        "ast_node_id": ast_id,
                        "ast_name": ast_name,
                        "ast_type": ast_type,
                        "created_at": time.time(),
                        "generation_time": summary_time,
                        "summary_type": "ast",
                    },
                )
                
                # Create relationship to AST node
                connector.create_relationship(
                    summary_node_id, ast_id, RelationshipTypes.DESCRIBES
                )
                
                return {"processed": True, "created": True}
                
            except Exception as e:
                logger.error(f"Error creating AST summary: {str(e)}")
                return {"processed": True, "created": False, "error": str(e)}

    def _update_parsing_status(
        self, status: IngestionStatus, parsed: int, total: int, current_file: str
    ) -> None:
        """Update the status during parsing.

        Args:
            status: Status object
            parsed: Number of files parsed
            total: Total number of files
            current_file: Current file being parsed
        """
        status.files_processed = parsed
        progress_ratio = parsed / total if total > 0 else 0
        status.progress = 20 + progress_ratio * 30  # 20-50% progress range
        status.message = f"Parsing files... {parsed}/{total} ({current_file})"

    def _update_summarization_status(
        self, status: IngestionStatus, summarized: int, total: int, current_file: str
    ) -> None:
        """Update the status during summarization.

        Args:
            status: Status object
            summarized: Number of files summarized
            total: Total number of files
            current_file: Current file being summarized
        """
        progress_ratio = summarized / total if total > 0 else 0
        status.progress = 60 + progress_ratio * 30  # 60-90% progress range
        status.message = f"Generating summaries... {summarized}/{total} ({current_file})"
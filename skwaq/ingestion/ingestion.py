"""Core ingestion functionality for Skwaq vulnerability assessment copilot.

This module provides the main Ingestion class that orchestrates the ingestion
of codebases from local file systems or Git repositories.
"""

import asyncio
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from skwaq.db.neo4j_connector import get_connector
from skwaq.db.schema import NodeLabels
from skwaq.utils.logging import get_logger

from .ast_mapper import ASTFileMapper
from .documentation import DocumentationProcessor
from .filesystem import CodebaseFileSystem, FilesystemGraphBuilder
from .parsers import get_parser, register_parsers
from .repository import RepositoryHandler, RepositoryManager
from .summarizers import get_summarizer, register_summarizers

logger = get_logger(__name__)


@dataclass
class IngestionStatus:
    """Status of an ingestion process.

    Attributes:
        id: Unique identifier for the ingestion
        state: Current state of the ingestion process (e.g., "initializing", "processing", "completed", "failed")
        progress: Progress percentage (0-100)
        start_time: Timestamp when ingestion started
        end_time: Timestamp when ingestion completed or failed
        error: Error message if ingestion failed
        files_processed: Number of files processed so far
        total_files: Total number of files to process
        errors: List of errors encountered during ingestion
        message: Current status message
        parsing_stats: Statistics about parsing process
        summarization_stats: Statistics about summarization process
    """

    id: str
    state: str = "initializing"
    progress: float = 0.0
    start_time: float = field(default_factory=time.time)
    end_time: Optional[float] = None
    error: Optional[str] = None
    files_processed: int = 0
    total_files: int = 0
    errors: List[Dict[str, Any]] = field(default_factory=list)
    message: str = "Initializing ingestion process"
    parsing_stats: Dict[str, Any] = field(default_factory=dict)
    summarization_stats: Dict[str, Any] = field(default_factory=dict)

    @property
    def time_elapsed(self) -> float:
        """Calculate time elapsed since ingestion started.

        Returns:
            Time elapsed in seconds
        """
        if self.end_time:
            return self.end_time - self.start_time
        return time.time() - self.start_time

    def to_dict(self) -> Dict[str, Any]:
        """Convert status to dictionary.

        Returns:
            Dictionary representation of the status
        """
        result = {
            "id": self.id,
            "state": self.state,
            "progress": self.progress,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "error": self.error,
            "files_processed": self.files_processed,
            "total_files": self.total_files,
            "time_elapsed": self.time_elapsed,
            "errors": self.errors,
            "message": self.message,
            "parsing_stats": self.parsing_stats,
            "summarization_stats": self.summarization_stats,
        }
        return result


class Ingestion:
    """Main ingestion class for handling codebase ingestion.

    This class orchestrates the process of ingesting a codebase from a local file system
    or Git repository and storing it in a graph database for analysis.

    Attributes:
        local_path: Path to a local codebase directory
        repo: Git repository URL
        branch: Git branch to clone
        model_client: OpenAI model client for code summarization
        max_parallel: Maximum number of parallel threads for processing
        doc_path: Path to additional documentation
        doc_uri: URI to additional documentation
        context_token_limit: Maximum number of tokens to keep in context
        parse_only: Flag to only parse the codebase without LLM summarization
    """

    def __init__(
        self,
        local_path: Optional[str] = None,
        repo: Optional[str] = None,
        branch: Optional[str] = None,
        model_client: Optional[Any] = None,
        max_parallel: int = 3,
        doc_path: Optional[str] = None,
        doc_uri: Optional[str] = None,
        context_token_limit: int = 20000,
        parse_only: bool = False,
    ):
        """Initialize the ingestion process.

        Args:
            local_path: Path to a local codebase directory
            repo: Git repository URL
            branch: Git branch to clone
            model_client: OpenAI model client for code summarization
            max_parallel: Maximum number of parallel threads for processing
            doc_path: Path to additional documentation
            doc_uri: URI to additional documentation
            context_token_limit: Maximum number of tokens to keep in context
            parse_only: Flag to only parse the codebase without LLM summarization

        Raises:
            ValueError: If neither local_path nor repo is provided, or if both are provided
        """
        if not local_path and not repo:
            raise ValueError("Either local_path or repo must be provided")
        if local_path and repo:
            raise ValueError("Only one of local_path or repo can be provided")

        self.local_path = local_path
        self.repo = repo
        self.branch = branch
        self.model_client = model_client
        self.max_parallel = max_parallel
        
        # If parse_only is explicitly set to True by the user, respect that
        # Otherwise, ensure we generate summaries for AST nodes
        self.parse_only = parse_only
        self.summarize_ast = not parse_only
        self.doc_path = doc_path
        self.doc_uri = doc_uri
        self.context_token_limit = context_token_limit

        # Create components
        self.db_connector = get_connector()
        self.repo_handler = RepositoryHandler()
        self.repo_manager = RepositoryManager(self.db_connector)

        # Initialize parsers and summarizers
        register_parsers()
        register_summarizers()

        # Active ingestion processes tracked by ID
        self._active_ingestions: Dict[str, IngestionStatus] = {}

    async def ingest(self) -> str:
        """Start the ingestion process.

        Returns:
            Ingestion ID that can be used to track the process
        """
        # Generate a unique ID for this ingestion
        ingestion_id = str(uuid.uuid4())

        # Create an initial status
        status = IngestionStatus(id=ingestion_id)
        self._active_ingestions[ingestion_id] = status

        # Launch the ingestion in a background task
        asyncio.create_task(self._run_ingestion(ingestion_id))

        return ingestion_id

    async def get_status(self, ingestion_id: str) -> IngestionStatus:
        """Get the current status of an ingestion process.

        Args:
            ingestion_id: ID of the ingestion process

        Returns:
            Current status of the ingestion process

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
            files = fs.get_all_files()
            status.total_files = len(files)
            status.message = f"Found {status.total_files} files in codebase"

            # Create filesystem graph
            fs_graph_builder = FilesystemGraphBuilder(self.db_connector)
            file_nodes = await fs_graph_builder.build_graph(repo_node_id, fs)
            status.message = "Created filesystem graph"
            status.progress = 10.0

            # Parse the codebase
            parser = get_parser("blarify")
            if not parser:
                raise ValueError("Blarify parser not found")

            parse_result = await parser.parse(codebase_path)

            # Map AST nodes to filesystem
            ast_mapper = ASTFileMapper(self.db_connector)
            mapping_result = await ast_mapper.map_ast_to_files(repo_node_id, file_nodes)

            # Update parsing stats
            status.parsing_stats = parse_result.get("stats", {})
            status.parsing_stats.update({"ast_mapping": mapping_result})
            status.files_processed = parse_result.get("files_processed", 0)
            status.message = f"Parsed {status.files_processed} files"
            status.progress = 50.0

            # Process documentation if provided
            if self.doc_path or self.doc_uri:
                doc_processor = DocumentationProcessor(
                    self.model_client, self.db_connector
                )

                if self.doc_path:
                    await doc_processor.process_local_docs(self.doc_path, repo_node_id)

                if self.doc_uri:
                    await doc_processor.process_remote_docs(self.doc_uri, repo_node_id)

                status.message = "Processed documentation"
                status.progress = 60.0

            # Generate code summaries using LLM if not parse_only
            if not self.parse_only and self.model_client:
                # Get the LLM summarizer
                summarizer = get_summarizer("llm")
                if not summarizer:
                    raise ValueError("LLM summarizer not found")

                # Configure the summarizer
                summarizer.configure(
                    model_client=self.model_client,
                    max_parallel=self.max_parallel,
                    context_token_limit=self.context_token_limit,
                )

                # Get file nodes
                file_query = (
                    "MATCH (repo:Repository)-[:CONTAINS*]->(file:File) "
                    "WHERE id(repo) = $repo_id AND file.language in ['python', 'javascript', 'typescript', 'java', 'csharp', 'go', 'cpp', 'c', 'php', 'ruby'] "
                    "RETURN id(file) as file_id, file.path as path, file.language as language"
                )

                file_nodes = self.db_connector.run_query(
                    file_query, {"repo_id": repo_node_id}
                )

                # Summarize files and AST nodes
                status.message = "Generating summaries for files and AST nodes"
                status.progress = 70.0
                summary_result = await summarizer.summarize_files(
                    file_nodes, fs, repo_node_id
                )
                
                # Now find AST nodes that don't have summaries and generate them
                status.message = "Generating summaries for remaining AST nodes"
                status.progress = 80.0
                
                # Get AST nodes without summaries
                ast_query = """
                MATCH (repo:Repository)-[:CONTAINS]->(file:File)
                WHERE id(repo) = $repo_id
                MATCH (ast)-[:PART_OF]->(file)
                WHERE (ast:Function OR ast:Class OR ast:Method) 
                AND ast.code IS NOT NULL
                AND NOT (ast)<-[:DESCRIBES]-(:CodeSummary)
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

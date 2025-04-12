"""LLM-based code summarizer implementation.

This module provides a summarizer implementation that uses Large Language Models
to generate natural language descriptions of code files.
"""

import asyncio
import os
import time
from typing import Any, Dict, List

from skwaq.db.neo4j_connector import get_connector
from skwaq.db.schema import RelationshipTypes
from skwaq.utils.logging import get_logger

from . import CodeSummarizer

logger = get_logger(__name__)


class LLMSummarizer(CodeSummarizer):
    """LLM-based code summarizer implementation.

    This summarizer uses Large Language Models (e.g., GPT-4) to generate
    natural language descriptions of code files.
    """

    def __init__(self):
        """Initialize the LLM summarizer."""
        self.model_client = None
        self.max_parallel = 3
        self.context_token_limit = 20000
        self.connector = get_connector()
        self.semaphore = None

        # Keep track of content to maintain context
        self._context_buffer = []
        self._context_size = 0

    def configure(self, **kwargs) -> None:
        """Configure the summarizer with additional parameters.

        Args:
            model_client: OpenAI model client for generating summaries
            max_parallel: Maximum number of parallel summarization tasks
            context_token_limit: Maximum number of tokens to keep in context
        """
        if "model_client" in kwargs:
            self.model_client = kwargs["model_client"]

        if "max_parallel" in kwargs:
            self.max_parallel = kwargs["max_parallel"]

        if "context_token_limit" in kwargs:
            self.context_token_limit = kwargs["context_token_limit"]

        # Create semaphore for limiting concurrent tasks
        self.semaphore = asyncio.Semaphore(self.max_parallel)

    async def summarize_files(
        self, file_nodes: List[Dict[str, Any]], fs: Any, repo_node_id: int
    ) -> Dict[str, Any]:
        """Generate summaries for a list of files.

        Args:
            file_nodes: List of file nodes with IDs and paths
            fs: Filesystem interface for reading file contents
            repo_node_id: ID of the repository node

        Returns:
            Dictionary with summarization results and statistics

        Raises:
            ValueError: If model client is not configured
        """
        if not self.model_client:
            error_msg = "Model client not configured for LLM summarizer"
            logger.error(error_msg)
            raise ValueError(error_msg)

        # Set up statistics
        stats = {
            "files_processed": 0,
            "errors": 0,
            "total_tokens": 0,
            "total_time": 0,
        }

        # Set up error collection
        errors = []

        # Set up context
        self._context_buffer = []
        self._context_size = 0

        # Create tasks for each file
        tasks = []
        for file_node in file_nodes:
            file_id = file_node["file_id"]
            file_path = file_node["path"]
            language = file_node.get("language", "unknown")

            # Only process certain languages
            if language in [
                "python",
                "javascript",
                "typescript",
                "java",
                "csharp",
                "go",
                "cpp",
                "c",
                "php",
                "ruby",
            ]:
                tasks.append(
                    self._summarize_file(
                        file_id, file_path, language, fs, stats, errors
                    )
                )

        # Run tasks with concurrency limit
        start_time = time.time()
        if tasks:
            await asyncio.gather(*tasks)
        stats["total_time"] = time.time() - start_time

        logger.info(
            f"Summarized {stats['files_processed']} files in {stats['total_time']:.2f} seconds"
        )

        return {
            "stats": stats,
            "files_processed": stats["files_processed"],
            "errors": errors,
        }

    async def _summarize_file(
        self,
        file_id: int,
        file_path: str,
        language: str,
        fs: Any,
        stats: Dict[str, Any],
        errors: List[Dict[str, Any]],
    ) -> None:
        """Summarize a single file using LLM.

        Args:
            file_id: ID of the file node
            file_path: Path of the file to summarize
            language: Programming language of the file
            fs: Filesystem interface for reading file contents
            stats: Dictionary to collect statistics
            errors: List to collect errors
        """
        async with self.semaphore:
            try:
                # Find the full path in the filesystem
                full_paths = [
                    path for path in fs.get_all_files() if path.endswith(file_path)
                ]

                if not full_paths:
                    errors.append(
                        {"file": file_path, "error": "File not found in filesystem"}
                    )
                    return

                full_path = full_paths[0]

                # Read the file content
                content = fs.read_file(full_path)

                if not content:
                    errors.append(
                        {"file": file_path, "error": "Could not read file content"}
                    )
                    return

                # Truncate content if it's too large
                if len(content) > 50000:
                    content = content[:50000] + "... [truncated]"

                # Extract file name and extension
                file_name = os.path.basename(file_path)

                # Add to context buffer
                self._add_to_context(file_name, content)

                # Create the prompt
                prompt = self._create_summary_prompt(file_name, content, language)

                # Generate summary
                summary_start_time = time.time()
                summary = await self.model_client.get_completion(
                    prompt, temperature=0.3
                )
                summary_time = time.time() - summary_start_time

                # Create summary node
                summary_node_id = self.connector.create_node(
                    "CodeSummary",
                    {
                        "summary": summary,
                        "file_name": file_name,
                        "language": language,
                        "created_at": time.time(),
                        "generation_time": summary_time,
                    },
                )

                # Create relationship to file
                self.connector.create_relationship(
                    file_id, summary_node_id, RelationshipTypes.DESCRIBES
                )

                # Update file node with summary
                query = (
                    "MATCH (file:File) "
                    "WHERE id(file) = $file_id "
                    "SET file.summary = $summary"
                )

                self.connector.run_query(
                    query, {"file_id": file_id, "summary": summary}
                )

                # Add to statistics
                stats["files_processed"] += 1
                stats["total_tokens"] += len(prompt.split()) + len(summary.split())

                logger.debug(f"Summarized file: {file_path}")

            except Exception as e:
                logger.error(f"Error summarizing file {file_path}: {str(e)}")
                stats["errors"] += 1
                errors.append({"file": file_path, "error": str(e)})

    def _create_summary_prompt(
        self, file_name: str, content: str, language: str
    ) -> str:
        """Create a prompt for summarizing a code file.

        Args:
            file_name: Name of the file
            content: Content of the file
            language: Programming language of the file

        Returns:
            Prompt string for the LLM
        """
        # Start with basic file information
        prompt = f"""
        Analyze the following {language} code file and provide a comprehensive summary:
        
        File: {file_name}
        Language: {language}
        
        For your summary, include:
        1. Overall purpose and main functionality of the code
        2. Key classes, functions, or components and their roles
        3. Important data structures or algorithms used
        4. Any notable design patterns or architectural approaches
        5. Dependencies and interactions with other components (if evident)
        6. Potential developer intent (what problem is this code solving)
        
        Code content:
        ```{language}
        {content}
        ```
        
        Context from other files already processed (if relevant):
        """

        # Add context from other files if available
        if self._context_buffer:
            prompt += "\n" + "\n".join(self._context_buffer)

        prompt += "\n\nSummary:"

        return prompt

    def _add_to_context(self, file_name: str, content: str) -> None:
        """Add file information to the context buffer, managing token limit.

        Args:
            file_name: Name of the file
            content: Content of the file
        """
        # Create a summary entry for the context
        entry = f"\nFile: {file_name}\nContent summary: {content[:200]}...\n"
        entry_tokens = len(entry.split())

        # Check if we need to remove old context to stay under token limit
        while (
            self._context_size + entry_tokens > self.context_token_limit
            and self._context_buffer
        ):
            removed_entry = self._context_buffer.pop(0)
            self._context_size -= len(removed_entry.split())

        # Add new entry to context
        self._context_buffer.append(entry)
        self._context_size += entry_tokens

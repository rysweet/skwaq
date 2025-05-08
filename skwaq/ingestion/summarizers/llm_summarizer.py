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
            "file_summaries_created": 0,
            "ast_summaries_created": 0,
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
            # Use auto-detection for language instead of explicit filter
            language = "auto"  # Auto-detect language

            # Create task for file summarization
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
            f"Summarized {stats['files_processed']} files ({stats['file_summaries_created']} file summaries, {stats['ast_summaries_created']} AST node summaries) in {stats['total_time']:.2f} seconds"
        )

        return {
            "stats": stats,
            "files_processed": stats["files_processed"],
            "file_summaries_created": stats["file_summaries_created"],
            "ast_summaries_created": stats["ast_summaries_created"],
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
        """Summarize a single file and its AST nodes using LLM.

        Args:
            file_id: ID of the file node
            file_path: Path of the file to summarize
            language: Programming language of the file (or "auto" to detect)
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
                max_content_size = 150000  # Increased from 50000 for more context
                if len(content) > max_content_size:
                    content = content[:max_content_size] + "... [truncated]"

                # Extract file name and extension
                file_name = os.path.basename(file_path)

                # Add to context buffer
                self._add_to_context(file_name, content)

                # 1. First, create a file-level summary
                await self._create_file_summary(file_id, file_name, content, language, stats)
                
                # 2. Then, create AST-level summaries
                await self._create_ast_summaries(file_id, file_name, content, language, stats)
                
                # Increment counter for files processed
                stats["files_processed"] += 1
                logger.debug(f"Summarized file and AST nodes: {file_path}")

            except Exception as e:
                logger.error(f"Error summarizing file {file_path}: {str(e)}")
                stats["errors"] += 1
                errors.append({"file": file_path, "error": str(e)})
    
    async def _create_file_summary(
        self,
        file_id: int,
        file_name: str,
        content: str,
        language: str,
        stats: Dict[str, Any]
    ) -> None:
        """Create a summary for an entire file.

        Args:
            file_id: ID of the file node
            file_name: Name of the file
            content: Content of the file
            language: Programming language or "auto"
            stats: Dictionary to collect statistics
        """
        try:
            # Create the prompt for file-level summary
            prompt = self._create_summary_prompt(file_name, content, language)
            prompt = prompt.replace(
                "Analyze the following", 
                "Analyze the ENTIRE following"
            ).replace(
                "summary, include:",
                "FULL FILE summary, include:"
            )

            # Generate summary
            summary_start_time = time.time()
            summary = await self.model_client.get_completion(
                prompt, temperature=0.3
            )
            summary_time = time.time() - summary_start_time

            # Create summary node for the file
            summary_node_id = self.connector.create_node(
                "CodeSummary",
                {
                    "summary": summary,
                    "file_name": file_name,
                    "language": language if language != "auto" else "detected",
                    "created_at": time.time(),
                    "generation_time": summary_time,
                    "summary_type": "file",  # Mark this as a file-level summary
                },
            )

            # Create relationship to file
            self.connector.create_relationship(
                summary_node_id, file_id, RelationshipTypes.DESCRIBES
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
            stats["file_summaries_created"] += 1
            stats["total_tokens"] += len(prompt.split()) + len(summary.split())

        except Exception as e:
            logger.error(f"Error creating file summary for {file_name}: {str(e)}")
            
    async def _create_ast_summaries(
        self,
        file_id: int,
        file_name: str,
        file_content: str,
        language: str,
        stats: Dict[str, Any]
    ) -> None:
        """Create summaries for AST nodes (functions, classes, methods) in a file.

        Args:
            file_id: ID of the file node
            file_name: Name of the file
            file_content: Content of the file (for context)
            language: Programming language or "auto"
            stats: Dictionary to collect statistics
        """
        try:
            # Query for AST nodes related to this file
            query = """
            MATCH (ast)-[:PART_OF]->(file:File)
            WHERE id(file) = $file_id AND (ast:Function OR ast:Class OR ast:Method) 
            AND ast.code IS NOT NULL
            AND NOT (ast)<-[:DESCRIBES]-(:CodeSummary) 
            RETURN 
                id(ast) as ast_id, 
                ast.name as name, 
                ast.code as code,
                labels(ast) as labels,
                ast.start_line as start_line,
                ast.end_line as end_line
            """
            ast_nodes = self.connector.run_query(query, {"file_id": file_id})
            
            if not ast_nodes:
                logger.debug(f"No AST nodes found for file {file_name}")
                return
                
            logger.debug(f"Found {len(ast_nodes)} AST nodes to summarize for file {file_name}")
            
            # Create summaries for each AST node
            for ast_node in ast_nodes:
                ast_id = ast_node["ast_id"]
                ast_name = ast_node["name"]
                ast_code = ast_node["code"]
                ast_type = ast_node["labels"][0] if ast_node["labels"] else "Unknown"
                
                if not ast_code or len(ast_code.strip()) < 10:
                    logger.debug(f"Skipping AST node {ast_name} due to insufficient code")
                    continue
                
                # Create prompt with file context
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
                
                Context from the file (for reference):
                ```
                {file_content[:1000]}... [truncated]
                ```
                
                Summary:
                """
                
                # Generate summary
                try:
                    summary_start_time = time.time()
                    ast_summary = await self.model_client.get_completion(
                        ast_prompt, temperature=0.3
                    )
                    summary_time = time.time() - summary_start_time
                    
                    # Create summary node
                    summary_node_id = self.connector.create_node(
                        "CodeSummary",
                        {
                            "summary": ast_summary,
                            "file_name": file_name,
                            "ast_name": ast_name,
                            "ast_type": ast_type,
                            "language": language if language != "auto" else "detected",
                            "created_at": time.time(),
                            "generation_time": summary_time,
                            "summary_type": "ast",  # Mark this as an AST-level summary
                        },
                    )
                    
                    # Create relationship to AST node
                    self.connector.create_relationship(
                        summary_node_id, ast_id, RelationshipTypes.DESCRIBES
                    )
                    
                    # Add to statistics
                    stats["ast_summaries_created"] += 1
                    stats["total_tokens"] += len(ast_prompt.split()) + len(ast_summary.split())
                    
                except Exception as e:
                    logger.error(f"Error creating AST summary for {ast_name}: {str(e)}")
                
        except Exception as e:
            logger.error(f"Error during AST summarization for file {file_name}: {str(e)}")

    def _create_summary_prompt(
        self, file_name: str, content: str, language: str
    ) -> str:
        """Create a prompt for summarizing a code file.

        Args:
            file_name: Name of the file
            content: Content of the file
            language: Programming language of the file (or "auto" to detect)

        Returns:
            Prompt string for the LLM
        """
        # Handle case where content is None or empty
        if not content or len(content.strip()) < 10:
            return f"""
            Create a placeholder summary for an empty or minimal code file named '{file_name}'.
            Indicate that the file appears to be empty or contains insufficient code to analyze.
            Summary:
            """
        
        # Detect language if "auto" is specified
        detected_language = language
        if language == "auto" or language == "unknown":
            # Simple language detection based on file extension
            ext = os.path.splitext(file_name)[1].lower()
            language_map = {
                '.py': 'Python',
                '.js': 'JavaScript',
                '.ts': 'TypeScript',
                '.jsx': 'React JavaScript',
                '.tsx': 'React TypeScript',
                '.java': 'Java',
                '.c': 'C',
                '.cpp': 'C++',
                '.h': 'C/C++ Header',
                '.cs': 'C#',
                '.php': 'PHP',
                '.rb': 'Ruby',
                '.go': 'Go',
                '.rs': 'Rust',
                '.swift': 'Swift',
                '.kt': 'Kotlin',
                '.scala': 'Scala',
                '.m': 'Objective-C',
                '.sh': 'Shell',
                '.pl': 'Perl',
                '.pm': 'Perl Module',
                '.r': 'R',
                '.html': 'HTML',
                '.css': 'CSS',
                '.scss': 'SCSS',
                '.sql': 'SQL',
                '.yml': 'YAML',
                '.yaml': 'YAML',
                '.json': 'JSON',
                '.xml': 'XML',
                '.md': 'Markdown',
                '.rst': 'reStructuredText',
                '.csproj': 'C# Project File',
                '.vbproj': 'VB.NET Project File',
                '.sln': 'Visual Studio Solution',
                '.csproj': 'C# Project File',
                '.vbproj': 'VB.NET Project File',
                '.sln': 'Visual Studio Solution',
            }
            
            detected_language = language_map.get(ext, 'Unknown')
            
            # If still unknown, try to detect from content patterns
            if detected_language == 'Unknown' and content:
                # Simple content-based detection
                if "def " in content and ":" in content and "import " in content:
                    detected_language = "Python"
                elif "function " in content and "{" in content and "}" in content:
                    detected_language = "JavaScript"
                elif "class " in content and "extends " in content and "public " in content:
                    detected_language = "Java"
                elif "#include" in content and "{" in content and "}" in content:
                    detected_language = "C/C++"
                elif "namespace " in content and "using " in content:
                    detected_language = "C#"
                elif "<?php" in content:
                    detected_language = "PHP"
                elif "<html" in content or "<!DOCTYPE" in content:
                    detected_language = "HTML"
        
        # Start with basic file information
        prompt = f"""
        You are a highly skilled software developer tasked with analyzing source code to provide comprehensive, accurate summaries.
        
        Analyze the following {detected_language} code from file '{file_name}' and provide a detailed summary.
                
        For your summary, include:
        1. Overall purpose and main functionality of the code
        2. Key classes, functions, or components and their roles
        3. Important data structures or algorithms used
        4. Any notable design patterns or architectural approaches
        5. Dependencies and interactions with other components (if evident)
        6. Potential security implications (if any)
        7. A hierarchical view of how this code fits into the larger system
        
        Make your summary detailed and technically precise. Focus on helping someone understand:
        - What this code does
        - How it works
        - How it interacts with other components
        - What role it plays in the larger system
        
        Code content:
        ```{detected_language}
        {content}
        ```
        
        Context from other related files:
        """

        # Add context from other files if available
        if self._context_buffer:
            prompt += "\n" + "\n".join(self._context_buffer)
        else:
            prompt += "\nNo additional context available."

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

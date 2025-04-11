"""Documentation processing for code ingestion.

This module handles the processing of additional documentation related to the codebase.
"""

import os
import aiohttp
import asyncio
from pathlib import Path
from typing import Dict, List, Any, Optional, Set

from skwaq.db.neo4j_connector import Neo4jConnector
from skwaq.db.schema import NodeLabels, RelationshipTypes
from skwaq.utils.logging import get_logger

logger = get_logger(__name__)


class DocumentationProcessor:
    """Process documentation files and relate them to the codebase.

    This class handles ingesting documentation from various sources and
    creating graph nodes and relationships to connect documentation to code.
    """

    def __init__(self, model_client: Any, connector: Neo4jConnector):
        """Initialize the documentation processor.

        Args:
            model_client: OpenAI model client for processing documentation
            connector: Neo4j connector instance
        """
        self.model_client = model_client
        self.connector = connector

        # Supported documentation file extensions
        self.supported_extensions = {
            ".md",
            ".markdown",  # Markdown
            ".rst",  # reStructuredText
            ".txt",  # Plain text
            ".html",
            ".htm",  # HTML
            ".xml",  # XML
            ".json",  # JSON
            ".yaml",
            ".yml",  # YAML
        }

    async def process_local_docs(
        self, doc_path: str, repo_node_id: int
    ) -> Dict[str, Any]:
        """Process documentation from a local file path.

        Args:
            doc_path: Path to the documentation
            repo_node_id: ID of the repository node

        Returns:
            Dictionary with processing statistics

        Raises:
            ValueError: If documentation path does not exist
        """
        doc_path = os.path.abspath(doc_path)

        if not os.path.exists(doc_path):
            error_msg = f"Documentation path does not exist: {doc_path}"
            logger.error(error_msg)
            raise ValueError(error_msg)

        # Process a single file or a directory of files
        if os.path.isfile(doc_path):
            doc_files = [doc_path]
        else:
            doc_files = []
            for root, _, files in os.walk(doc_path):
                for file in files:
                    file_path = os.path.join(root, file)
                    _, ext = os.path.splitext(file_path)
                    if ext.lower() in self.supported_extensions:
                        doc_files.append(file_path)

        # Process each documentation file
        stats = {"files_processed": 0, "errors": 0}
        for file_path in doc_files:
            try:
                doc_node_id = await self._process_doc_file(file_path, repo_node_id)
                if doc_node_id:
                    stats["files_processed"] += 1
            except Exception as e:
                logger.error(
                    f"Error processing documentation file {file_path}: {str(e)}"
                )
                stats["errors"] += 1

        return stats

    async def process_remote_docs(
        self, doc_uri: str, repo_node_id: int
    ) -> Dict[str, Any]:
        """Process documentation from a remote URI.

        Args:
            doc_uri: URI to the documentation
            repo_node_id: ID of the repository node

        Returns:
            Dictionary with processing statistics

        Raises:
            ValueError: If the URI is invalid or cannot be accessed
        """
        logger.info(f"Processing remote documentation from {doc_uri}")

        try:
            # Download the documentation
            async with aiohttp.ClientSession() as session:
                async with session.get(doc_uri) as response:
                    if response.status != 200:
                        error_msg = (
                            f"Failed to download documentation: {response.status}"
                        )
                        logger.error(error_msg)
                        raise ValueError(error_msg)

                    content = await response.text()

            # Create a document node
            doc_name = doc_uri.split("/")[-1] or "remote_doc"
            properties = {
                "name": doc_name,
                "source": doc_uri,
                "content": content[:10000],  # Limit content size in node properties
                "content_length": len(content),
                "type": "remote",
                "ingestion_timestamp": os.path.basename(doc_uri),
            }

            doc_node_id = self.connector.create_node([NodeLabels.DOCUMENT], properties)

            # Create relationship to repository
            self.connector.create_relationship(
                repo_node_id, doc_node_id, RelationshipTypes.RELATES_TO
            )

            # Process the document with LLM for summaries and sections
            await self._process_doc_content(doc_node_id, content, doc_name)

            return {"files_processed": 1, "errors": 0}

        except aiohttp.ClientError as e:
            error_msg = f"Network error accessing remote documentation: {str(e)}"
            logger.error(error_msg)
            raise ValueError(error_msg)
        except Exception as e:
            error_msg = f"Failed to process remote documentation: {str(e)}"
            logger.error(error_msg)
            raise ValueError(error_msg)

    async def _process_doc_file(
        self, file_path: str, repo_node_id: int
    ) -> Optional[int]:
        """Process a single documentation file.

        Args:
            file_path: Path to the documentation file
            repo_node_id: ID of the repository node

        Returns:
            ID of the created document node, or None if processing failed
        """
        try:
            # Read the file
            with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()

            # Create a document node
            properties = {
                "name": os.path.basename(file_path),
                "path": file_path,
                "content": content[:10000],  # Limit content size in node properties
                "content_length": len(content),
                "type": "file",
                "ingestion_timestamp": os.path.basename(file_path),
            }

            doc_node_id = self.connector.create_node([NodeLabels.DOCUMENT], properties)

            # Create relationship to repository
            self.connector.create_relationship(
                repo_node_id, doc_node_id, RelationshipTypes.RELATES_TO
            )

            # Process the document with LLM for summaries and sections
            await self._process_doc_content(
                doc_node_id, content, os.path.basename(file_path)
            )

            return doc_node_id

        except Exception as e:
            logger.error(f"Failed to process documentation file {file_path}: {str(e)}")
            return None

    async def _process_doc_content(
        self, doc_node_id: int, content: str, doc_name: str
    ) -> None:
        """Process documentation content using LLM.

        Args:
            doc_node_id: ID of the document node
            content: Content of the documentation
            doc_name: Name of the document
        """
        if not self.model_client:
            logger.warning(
                "No model client provided, skipping documentation content processing"
            )
            return

        try:
            # Generate a summary of the document using LLM
            summary_prompt = f"""
            Summarize the following documentation content in a concise paragraph:
            
            Document: {doc_name}
            
            Content:
            {content[:5000]}  # Limit to first 5000 chars for the prompt
            
            Summary:
            """

            summary = await self.model_client.get_completion(
                summary_prompt, temperature=0.3
            )

            # Update the document node with the summary
            query = (
                "MATCH (doc:Document) "
                "WHERE id(doc) = $doc_id "
                "SET doc.summary = $summary"
            )

            self.connector.run_query(query, {"doc_id": doc_node_id, "summary": summary})

            # Extract sections from the document (for longer documents)
            if len(content) > 1000:
                await self._extract_document_sections(doc_node_id, content, doc_name)

        except Exception as e:
            logger.error(f"Error processing document content with LLM: {str(e)}")

    async def _extract_document_sections(
        self, doc_node_id: int, content: str, doc_name: str
    ) -> None:
        """Extract sections from document content and create section nodes.

        Args:
            doc_node_id: ID of the document node
            content: Content of the documentation
            doc_name: Name of the document
        """
        try:
            # Extract sections using LLM
            sections_prompt = f"""
            Identify the main sections in this documentation and list them in the format:
            
            SECTION: <section-title>
            CONTENT: <brief description of section>
            
            Document: {doc_name}
            
            Content:
            {content[:8000]}  # Limit to first 8000 chars for the prompt
            
            Sections:
            """

            sections_text = await self.model_client.get_completion(
                sections_prompt, temperature=0.3
            )

            # Parse the sections
            sections = []
            current_section = None
            current_content = []

            for line in sections_text.split("\n"):
                line = line.strip()
                if line.startswith("SECTION:"):
                    # Save the previous section if there is one
                    if current_section:
                        sections.append(
                            {
                                "title": current_section,
                                "content": "\n".join(current_content),
                            }
                        )

                    # Start a new section
                    current_section = line[len("SECTION:") :].strip()
                    current_content = []
                elif line.startswith("CONTENT:") and current_section:
                    current_content.append(line[len("CONTENT:") :].strip())
                elif current_section and line:
                    current_content.append(line)

            # Add the last section
            if current_section:
                sections.append(
                    {"title": current_section, "content": "\n".join(current_content)}
                )

            # Create section nodes
            for section in sections:
                properties = {
                    "title": section["title"],
                    "content": section["content"],
                    "document_name": doc_name,
                }

                section_node_id = self.connector.create_node(
                    [NodeLabels.DOCUMENT_SECTION], properties
                )

                # Create relationship to document
                self.connector.create_relationship(
                    doc_node_id, section_node_id, RelationshipTypes.CONTAINS
                )

        except Exception as e:
            logger.error(f"Error extracting document sections with LLM: {str(e)}")

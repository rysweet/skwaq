"""Knowledge ingestion module for the Skwaq vulnerability assessment copilot.

This module handles the ingestion of knowledge sources, such as vulnerability
databases, security guidelines, and other expert knowledge, into the system's
knowledge graph.
"""

import os
from pathlib import Path
from typing import Dict, List, Optional, Any
import asyncio
import json

from ..db.neo4j_connector import get_connector
from ..core.openai_client import get_openai_client
from ..utils.logging import get_logger

logger = get_logger(__name__)


async def ingest_markdown_document(
    file_path: str,
    document_type: str = "general",
    tags: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """Ingest a markdown document into the knowledge graph.

    Args:
        file_path: Path to the markdown file
        document_type: Type of document (e.g., "guideline", "tutorial", "vulnerability")
        tags: Optional list of tags to associate with the document

    Returns:
        Dictionary with document metadata and node ID
    """
    logger.info(f"Ingesting markdown document: {file_path}")
    path = Path(file_path)

    if not path.exists() or not path.is_file():
        raise FileNotFoundError(f"File not found: {file_path}")

    try:
        # Read the document content
        content = path.read_text(encoding="utf-8")
        document_name = path.stem
        file_size = path.stat().st_size

        # Generate a summary using OpenAI
        openai_client = get_openai_client(async_mode=True)
        summary_prompt = f"""Summarize the following document about security and vulnerabilities in about 100 words:

{content[:4000]}  # Limit length for API

Focus on the key security concepts, vulnerability patterns, or assessment techniques described.
"""
        summary = await openai_client.get_completion(summary_prompt, temperature=0.3)

        # Generate embeddings for semantic search
        embedding_text = f"{document_name} {summary}\n\n{content[:4000]}"
        embedding = await openai_client.get_embedding(embedding_text)

        # Connect to Neo4j and store the document
        connector = get_connector()

        # Create document node with embedding
        properties = {
            "name": document_name,
            "type": document_type,
            "content": content,
            "summary": summary,
            "file_path": str(path.absolute()),
            "file_size": file_size,
            "embedding": embedding,
            "tags": tags or [],
        }

        # Create document node
        document_id = connector.create_node(
            labels=["Document", "Knowledge"],
            properties=properties,
        )

        if document_id is None:
            raise RuntimeError(f"Failed to create document node for {file_path}")

        # Create vector index if it doesn't exist
        connector.create_vector_index(
            index_name="knowledge_document_embedding",
            node_label="Knowledge",
            vector_property="embedding",
            embedding_dimension=len(embedding),
        )

        logger.info(f"Successfully ingested document: {document_name} (ID: {document_id})")

        return {
            "document_id": document_id,
            "name": document_name,
            "type": document_type,
            "summary": summary,
            "path": str(path.absolute()),
            "tags": tags or [],
        }

    except Exception as e:
        logger.error(f"Error ingesting document {file_path}: {e}")
        raise


async def ingest_cve_data(
    cve_json_path: str,
) -> Dict[str, Any]:
    """Ingest CVE data from a JSON file into the knowledge graph.

    Args:
        cve_json_path: Path to the JSON file containing CVE data

    Returns:
        Dictionary with ingestion statistics
    """
    logger.info(f"Ingesting CVE data from: {cve_json_path}")
    path = Path(cve_json_path)

    if not path.exists() or not path.is_file():
        raise FileNotFoundError(f"File not found: {cve_json_path}")

    try:
        # Read the CVE data
        with open(path, "r", encoding="utf-8") as f:
            cve_data = json.load(f)

        # Connect to Neo4j
        connector = get_connector()

        # Process each CVE
        processed_count = 0
        failed_count = 0

        for cve_item in cve_data.get("CVE_Items", []):
            try:
                cve_info = cve_item.get("cve", {})
                impact = cve_item.get("impact", {})

                # Extract metadata
                cve_id = cve_info.get("CVE_data_meta", {}).get("ID", "Unknown")
                description = ""
                for desc_data in cve_info.get("description", {}).get("description_data", []):
                    if desc_data.get("lang") == "en":
                        description = desc_data.get("value", "")
                        break

                # Extract CVSS scores
                cvss_v3 = impact.get("baseMetricV3", {}).get("cvssV3", {})
                cvss_v2 = impact.get("baseMetricV2", {}).get("cvssV2", {})

                base_score_v3 = cvss_v3.get("baseScore", 0.0)
                base_score_v2 = cvss_v2.get("baseScore", 0.0)

                # Create node properties
                properties = {
                    "cve_id": cve_id,
                    "description": description,
                    "published_date": cve_item.get("publishedDate", ""),
                    "last_modified_date": cve_item.get("lastModifiedDate", ""),
                    "base_score_v3": base_score_v3,
                    "base_score_v2": base_score_v2,
                    "severity_v3": cvss_v3.get("baseSeverity", "UNKNOWN"),
                    "attack_vector_v3": cvss_v3.get("attackVector", ""),
                    "attack_complexity_v3": cvss_v3.get("attackComplexity", ""),
                }

                # Get embedding for the CVE
                openai_client = get_openai_client(async_mode=True)
                embedding_text = f"{cve_id} {description}"
                properties["embedding"] = await openai_client.get_embedding(embedding_text)

                # Create CVE node
                cve_node_id = connector.create_node(
                    labels=["CVE", "Knowledge"],
                    properties=properties,
                )

                if cve_node_id is None:
                    logger.warning(f"Failed to create node for {cve_id}")
                    failed_count += 1
                    continue

                # Process references
                references = cve_info.get("references", {}).get("reference_data", [])
                for ref in references:
                    ref_properties = {
                        "url": ref.get("url", ""),
                        "name": ref.get("name", ""),
                        "source": ref.get("source", ""),
                        "tags": ref.get("tags", []),
                    }

                    # Create reference node
                    ref_node_id = connector.create_node(
                        labels=["Reference"],
                        properties=ref_properties,
                    )

                    if ref_node_id is not None:
                        # Create relationship between CVE and reference
                        connector.create_relationship(cve_node_id, ref_node_id, "HAS_REFERENCE")

                processed_count += 1

                # Log progress periodically
                if processed_count % 100 == 0:
                    logger.info(f"Processed {processed_count} CVEs...")

            except Exception as e:
                logger.error(f"Error processing CVE: {e}")
                failed_count += 1

        # Create vector index if it doesn't exist
        connector.create_vector_index(
            index_name="cve_embedding",
            node_label="CVE",
            vector_property="embedding",
            embedding_dimension=1536,  # Default size for text-embedding-ada-002
        )

        logger.info(f"CVE ingestion complete. Processed: {processed_count}, Failed: {failed_count}")

        return {
            "processed_count": processed_count,
            "failed_count": failed_count,
            "total_count": processed_count + failed_count,
        }

    except Exception as e:
        logger.error(f"Error ingesting CVE data from {cve_json_path}: {e}")
        raise


async def ingest_knowledge_directory(
    directory_path: str,
    recursive: bool = True,
    file_extensions: List[str] = [".md", ".txt"],
) -> Dict[str, Any]:
    """Ingest all knowledge documents in a directory.

    Args:
        directory_path: Path to the directory containing knowledge documents
        recursive: Whether to recursively process subdirectories
        file_extensions: List of file extensions to process

    Returns:
        Dictionary with ingestion statistics
    """
    logger.info(f"Ingesting knowledge directory: {directory_path}")
    path = Path(directory_path)

    if not path.exists() or not path.is_dir():
        raise FileNotFoundError(f"Directory not found: {directory_path}")

    # Find all files matching the extensions
    if recursive:
        files = []
        for ext in file_extensions:
            files.extend(path.glob(f"**/*{ext}"))
    else:
        files = []
        for ext in file_extensions:
            files.extend(path.glob(f"*{ext}"))

    # Process each file
    results = {
        "total": len(files),
        "successful": 0,
        "failed": 0,
        "documents": [],
    }

    for file_path in files:
        try:
            # Determine document type based on parent directory
            document_type = file_path.parent.name.lower()
            if document_type == path.name.lower():
                document_type = "general"

            # Ingest the document
            document_info = await ingest_markdown_document(
                str(file_path),
                document_type=document_type,
                tags=[document_type],
            )

            results["successful"] += 1
            results["documents"].append(document_info)

        except Exception as e:
            logger.error(f"Failed to ingest {file_path}: {e}")
            results["failed"] += 1

    logger.info(
        f"Knowledge directory ingestion complete. "
        f"Successful: {results['successful']}, Failed: {results['failed']}"
    )

    return results

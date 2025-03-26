"""Knowledge ingestion module for the Skwaq vulnerability assessment copilot.

This module handles the ingestion of knowledge sources, such as vulnerability
databases, security guidelines, and other expert knowledge, into the system's
knowledge graph.
"""

import os
import re
from pathlib import Path
from typing import Dict, List, Optional, Any, Set, Tuple
import asyncio
import json

from ..db.neo4j_connector import get_connector
from ..db.schema import NodeLabels, RelationshipTypes, SchemaManager
from ..core.openai_client import get_openai_client
from ..utils.logging import get_logger, LogEvent
from .cwe_ingestion import ingest_cwe_database, download_cwe_database

logger = get_logger(__name__)


class KnowledgeChunker:
    """Process and chunk documents for efficient knowledge ingestion.

    This class handles splitting documents into semantic chunks and extracting
    structural information to enable more effective knowledge retrieval.
    """

    def __init__(self, openai_client=None):
        """Initialize the knowledge chunker.

        Args:
            openai_client: Optional OpenAI client instance. If not provided,
                          a new client will be created.
        """
        self.openai_client = openai_client or get_openai_client(async_mode=True)

    async def chunk_markdown_document(
        self, content: str, max_chunk_size: int = 1000
    ) -> List[Dict[str, Any]]:
        """Split a markdown document into semantic chunks.

        Args:
            content: The markdown document content
            max_chunk_size: Maximum character size for each chunk

        Returns:
            List of chunks with title, content, and level information
        """
        # Parse the document structure (headers and content)
        sections = self._parse_markdown_structure(content)

        # Process sections into chunks
        chunks = []
        current_chunk = {"title": "", "content": "", "level": 0, "headers": []}
        current_size = 0

        for section in sections:
            section_text = f"{section['header']}\n\n{section['content']}"
            section_size = len(section_text)

            # If this section would make the chunk too big, finalize current chunk
            if current_size > 0 and current_size + section_size > max_chunk_size:
                # Finalize current chunk
                if current_chunk["content"]:
                    chunks.append(dict(current_chunk))

                # Start a new chunk with this section
                current_chunk = {
                    "title": section["header"] or "Document Section",
                    "content": section_text,
                    "level": section["level"],
                    "headers": [section["header"]] if section["header"] else [],
                }
                current_size = section_size
            else:
                # Add to current chunk
                if not current_chunk["title"] and section["header"]:
                    current_chunk["title"] = section["header"]

                if (
                    section["header"]
                    and section["header"] not in current_chunk["headers"]
                ):
                    current_chunk["headers"].append(section["header"])

                if current_chunk["content"]:
                    current_chunk["content"] += f"\n\n{section_text}"
                else:
                    current_chunk["content"] = section_text

                current_size += section_size

        # Add the last chunk if it has content
        if current_chunk["content"]:
            chunks.append(current_chunk)

        # Generate embeddings for each chunk
        for chunk in chunks:
            chunk["embedding"] = await self.openai_client.get_embedding(
                f"{chunk['title']}\n\n{chunk['content']}"
            )

            # Extract key concepts
            concepts_prompt = f"""Extract the key security or vulnerability concepts from this text. 
            Return a comma-separated list of concepts (not more than 5):
            
            {chunk['content'][:3000]}
            """
            chunk["concepts"] = (
                await self.openai_client.get_completion(
                    concepts_prompt, temperature=0.3
                )
            ).split(",")
            chunk["concepts"] = [c.strip() for c in chunk["concepts"] if c.strip()]

        return chunks

    def _parse_markdown_structure(self, content: str) -> List[Dict[str, Any]]:
        """Parse the structure of a markdown document.

        Args:
            content: The markdown document content

        Returns:
            List of sections with header, content, and level information
        """
        # Split the document by headers
        header_pattern = r"^(#{1,6})\s+(.+)$"
        lines = content.split("\n")

        sections = []
        current_header = ""
        current_level = 0
        current_content = []

        for line in lines:
            header_match = re.match(header_pattern, line)

            if header_match:
                # Save the previous section
                if current_content or current_header:
                    sections.append(
                        {
                            "header": current_header,
                            "content": "\n".join(current_content),
                            "level": current_level,
                        }
                    )

                # Start a new section
                current_level = len(header_match.group(1))
                current_header = header_match.group(2)
                current_content = []
            else:
                current_content.append(line)

        # Add the last section
        if current_content or current_header:
            sections.append(
                {
                    "header": current_header,
                    "content": "\n".join(current_content),
                    "level": current_level,
                }
            )

        # Handle case where document has no headers
        if not sections:
            sections.append({"header": "", "content": content, "level": 0})

        return sections


@LogEvent("knowledge_ingestion")
async def ingest_markdown_document(
    file_path: str,
    document_type: str = "general",
    tags: Optional[List[str]] = None,
    extract_vulnerability_patterns: bool = True,
) -> Dict[str, Any]:
    """Ingest a markdown document into the knowledge graph.

    Args:
        file_path: Path to the markdown file
        document_type: Type of document (e.g., "guideline", "tutorial", "vulnerability")
        tags: Optional list of tags to associate with the document
        extract_vulnerability_patterns: Whether to extract vulnerability patterns from the document

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
            labels=[NodeLabels.DOCUMENT, NodeLabels.KNOWLEDGE],
            properties=properties,
        )

        if document_id is None:
            raise RuntimeError(f"Failed to create document node for {file_path}")

        # Chunk the document into sections
        chunker = KnowledgeChunker(openai_client)
        sections = await chunker.chunk_markdown_document(content)

        section_ids = []
        for i, section in enumerate(sections):
            # Create section node
            section_properties = {
                "title": section["title"],
                "content": section["content"],
                "level": section["level"],
                "section_index": i,
                "headers": section["headers"],
                "embedding": section["embedding"],
                "concepts": section["concepts"],
            }

            section_id = connector.create_node(
                labels=[NodeLabels.DOCUMENT_SECTION, NodeLabels.KNOWLEDGE],
                properties=section_properties,
            )

            if section_id is not None:
                section_ids.append(section_id)

                # Connect section to document
                connector.create_relationship(
                    document_id, section_id, RelationshipTypes.CONTAINS
                )

                # Extract and link vulnerability patterns if requested
                if extract_vulnerability_patterns and section["content"]:
                    await _extract_vulnerability_patterns(
                        section["content"],
                        section_id,
                        section["concepts"],
                        openai_client,
                        connector,
                    )

        # Create vector index if it doesn't exist
        connector.create_vector_index(
            index_name="knowledge_document_embedding",
            node_label=NodeLabels.DOCUMENT,
            vector_property="embedding",
            embedding_dimension=len(embedding),
        )

        # Create vector index for document sections
        connector.create_vector_index(
            index_name="document_section_embedding",
            node_label=NodeLabels.DOCUMENT_SECTION,
            vector_property="embedding",
            embedding_dimension=len(embedding),
        )

        logger.info(
            f"Successfully ingested document: {document_name} (ID: {document_id}) with {len(section_ids)} sections"
        )

        return {
            "document_id": document_id,
            "name": document_name,
            "type": document_type,
            "summary": summary,
            "path": str(path.absolute()),
            "tags": tags or [],
            "sections": len(section_ids),
        }

    except Exception as e:
        logger.error(f"Error ingesting document {file_path}: {e}")
        raise


async def _extract_vulnerability_patterns(
    content: str,
    section_id: int,
    concepts: List[str],
    openai_client: Any,
    connector: Any,
) -> List[int]:
    """Extract vulnerability patterns from document content.

    Args:
        content: Document content to analyze
        section_id: ID of the document section node
        concepts: List of extracted concepts from the section
        openai_client: OpenAI client instance
        connector: Neo4j connector instance

    Returns:
        List of created vulnerability pattern node IDs
    """
    # Analyze content for vulnerability patterns
    pattern_prompt = f"""Analyze this content for specific vulnerability patterns or security issues.
    If no clear vulnerability patterns are found, return 'None'.
    Otherwise, return a JSON array of objects with 'name', 'description', and 'severity' (Low, Medium, High) for each pattern.
    
    Content:
    {content[:3000]}
    """

    pattern_result = await openai_client.get_completion(pattern_prompt, temperature=0.3)

    # Check if no patterns found
    if (
        pattern_result.strip() == "None"
        or "no clear vulnerability" in pattern_result.lower()
    ):
        return []

    # Parse the JSON response
    try:
        # Handle case where response isn't proper JSON
        if not pattern_result.strip().startswith("["):
            pattern_result = f"[{pattern_result}]"

        patterns = json.loads(pattern_result)
        if not isinstance(patterns, list):
            patterns = [patterns]
    except json.JSONDecodeError:
        logger.warning(
            f"Failed to parse vulnerability patterns from response: {pattern_result}"
        )
        return []

    pattern_ids = []
    for pattern in patterns:
        if not isinstance(pattern, dict):
            continue

        name = pattern.get("name", "Unknown Pattern")
        description = pattern.get("description", "")
        severity = pattern.get("severity", "Medium")

        # Skip if missing essential info
        if not name or not description:
            continue

        # Generate embedding for the pattern
        embedding_text = f"{name}: {description}"
        embedding = await openai_client.get_embedding(embedding_text)

        # Create pattern node
        properties = {
            "name": name,
            "description": description,
            "severity": severity,
            "source": "document_extraction",
            "embedding": embedding,
            "concepts": concepts,
        }

        pattern_id = connector.create_node(
            labels=[NodeLabels.VULNERABILITY_PATTERN, NodeLabels.KNOWLEDGE],
            properties=properties,
        )

        if pattern_id is not None:
            pattern_ids.append(pattern_id)

            # Connect pattern to document section
            connector.create_relationship(
                section_id, pattern_id, RelationshipTypes.DESCRIBES
            )

    if pattern_ids:
        # Create vector index for vulnerability patterns if not exists
        connector.create_vector_index(
            index_name="vulnerability_pattern_embedding",
            node_label=NodeLabels.VULNERABILITY_PATTERN,
            vector_property="embedding",
            embedding_dimension=1536,
        )

    return pattern_ids


@LogEvent("cve_ingestion")
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
        cwe_links = 0

        for cve_item in cve_data.get("CVE_Items", []):
            try:
                cve_info = cve_item.get("cve", {})
                impact = cve_item.get("impact", {})

                # Extract metadata
                cve_id = cve_info.get("CVE_data_meta", {}).get("ID", "Unknown")
                description = ""
                for desc_data in cve_info.get("description", {}).get(
                    "description_data", []
                ):
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
                properties["embedding"] = await openai_client.get_embedding(
                    embedding_text
                )

                # Create CVE node
                cve_node_id = connector.create_node(
                    labels=["CVE", NodeLabels.KNOWLEDGE],
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
                        connector.create_relationship(
                            cve_node_id, ref_node_id, RelationshipTypes.REFERENCES
                        )

                # Extract and link CWE information
                problem_type_data = cve_info.get("problemtype", {}).get(
                    "problemtype_data", []
                )
                for problem_type in problem_type_data:
                    for description in problem_type.get("description", []):
                        if description.get("lang") == "en":
                            cwe_value = description.get("value", "")
                            if cwe_value.startswith("CWE-"):
                                cwe_id = cwe_value.replace("CWE-", "")

                                # Look up the CWE node
                                cwe_query = (
                                    f"MATCH (cwe:{NodeLabels.CWE}) "
                                    f"WHERE cwe.cwe_id = $cwe_id "
                                    f"RETURN id(cwe) as node_id"
                                )
                                cwe_result = connector.run_query(
                                    cwe_query, {"cwe_id": cwe_id}
                                )

                                if cwe_result:
                                    cwe_node_id = cwe_result[0]["node_id"]

                                    # Create relationship between CVE and CWE
                                    relationship_result = connector.create_relationship(
                                        cve_node_id,
                                        cwe_node_id,
                                        RelationshipTypes.RELATES_TO,
                                        {"type": "associated_weakness"},
                                    )

                                    if relationship_result:
                                        cwe_links += 1

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

        logger.info(
            f"CVE ingestion complete. Processed: {processed_count}, "
            f"Failed: {failed_count}, CWE links: {cwe_links}"
        )

        return {
            "processed_count": processed_count,
            "failed_count": failed_count,
            "total_count": processed_count + failed_count,
            "cwe_links": cwe_links,
        }

    except Exception as e:
        logger.error(f"Error ingesting CVE data from {cve_json_path}: {e}")
        raise


@LogEvent("directory_ingestion")
async def ingest_knowledge_directory(
    directory_path: str,
    recursive: bool = True,
    file_extensions: List[str] = [".md", ".txt"],
    extract_vulnerability_patterns: bool = True,
) -> Dict[str, Any]:
    """Ingest all knowledge documents in a directory.

    Args:
        directory_path: Path to the directory containing knowledge documents
        recursive: Whether to recursively process subdirectories
        file_extensions: List of file extensions to process
        extract_vulnerability_patterns: Whether to extract vulnerability patterns

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
        "sections": 0,
        "vulnerability_patterns": 0,
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
                extract_vulnerability_patterns=extract_vulnerability_patterns,
            )

            results["successful"] += 1
            results["documents"].append(document_info)

            # Track sections
            if "sections" in document_info:
                results["sections"] += document_info["sections"]

        except Exception as e:
            logger.error(f"Failed to ingest {file_path}: {e}")
            results["failed"] += 1

    # Get count of vulnerability patterns extracted
    connector = get_connector()
    patterns_query = f"""
    MATCH (d:{NodeLabels.DOCUMENT})-[:{RelationshipTypes.CONTAINS}]->(s:{NodeLabels.DOCUMENT_SECTION})
          -[:{RelationshipTypes.DESCRIBES}]->(p:{NodeLabels.VULNERABILITY_PATTERN})
    WHERE d.file_path STARTS WITH $base_path
    RETURN count(DISTINCT p) as pattern_count
    """
    patterns_result = connector.run_query(patterns_query, {"base_path": str(path)})
    if patterns_result:
        results["vulnerability_patterns"] = patterns_result[0]["pattern_count"]

    logger.info(
        f"Knowledge directory ingestion complete. "
        f"Successful: {results['successful']}, Failed: {results['failed']}, "
        f"Sections: {results['sections']}, Patterns: {results['vulnerability_patterns']}"
    )

    return results


@LogEvent("knowledge_integration")
async def link_related_knowledge(min_similarity: float = 0.75) -> Dict[str, int]:
    """Create relationships between related knowledge items based on similarity.

    Args:
        min_similarity: Minimum cosine similarity threshold for creating relationships

    Returns:
        Dictionary with counts of created relationships
    """
    logger.info(
        f"Linking related knowledge with similarity threshold: {min_similarity}"
    )
    connector = get_connector()
    relationship_counts = {
        "document_to_document": 0,
        "section_to_section": 0,
        "pattern_to_pattern": 0,
        "cwe_to_pattern": 0,
        "cve_to_pattern": 0,
    }

    # Link similar documents
    doc_query = f"""
    MATCH (d1:{NodeLabels.DOCUMENT}), (d2:{NodeLabels.DOCUMENT})
    WHERE id(d1) < id(d2)
    WITH d1, d2, gds.similarity.cosine(d1.embedding, d2.embedding) AS similarity
    WHERE similarity >= $threshold
    MERGE (d1)-[r:{RelationshipTypes.SIMILAR_TO}]->(d2)
    SET r.similarity = similarity
    RETURN count(*) as count
    """
    doc_result = connector.run_query(doc_query, {"threshold": min_similarity})
    if doc_result:
        relationship_counts["document_to_document"] = doc_result[0]["count"]

    # Link similar document sections
    section_query = f"""
    MATCH (s1:{NodeLabels.DOCUMENT_SECTION}), (s2:{NodeLabels.DOCUMENT_SECTION})
    WHERE id(s1) < id(s2)
    WITH s1, s2, gds.similarity.cosine(s1.embedding, s2.embedding) AS similarity
    WHERE similarity >= $threshold
    MERGE (s1)-[r:{RelationshipTypes.SIMILAR_TO}]->(s2)
    SET r.similarity = similarity
    RETURN count(*) as count
    """
    section_result = connector.run_query(section_query, {"threshold": min_similarity})
    if section_result:
        relationship_counts["section_to_section"] = section_result[0]["count"]

    # Link similar vulnerability patterns
    pattern_query = f"""
    MATCH (p1:{NodeLabels.VULNERABILITY_PATTERN}), (p2:{NodeLabels.VULNERABILITY_PATTERN})
    WHERE id(p1) < id(p2)
    WITH p1, p2, gds.similarity.cosine(p1.embedding, p2.embedding) AS similarity
    WHERE similarity >= $threshold
    MERGE (p1)-[r:{RelationshipTypes.SIMILAR_TO}]->(p2)
    SET r.similarity = similarity
    RETURN count(*) as count
    """
    pattern_result = connector.run_query(pattern_query, {"threshold": min_similarity})
    if pattern_result:
        relationship_counts["pattern_to_pattern"] = pattern_result[0]["count"]

    # Link CWEs to vulnerability patterns
    cwe_pattern_query = f"""
    MATCH (cwe:{NodeLabels.CWE}), (pattern:{NodeLabels.VULNERABILITY_PATTERN})
    WHERE cwe.node_type = 'Weakness'
    WITH cwe, pattern, gds.similarity.cosine(cwe.embedding, pattern.embedding) AS similarity
    WHERE similarity >= $threshold
    MERGE (pattern)-[r:{RelationshipTypes.RELATES_TO}]->(cwe)
    SET r.similarity = similarity, r.nature = 'derived_from'
    RETURN count(*) as count
    """
    cwe_pattern_result = connector.run_query(
        cwe_pattern_query, {"threshold": min_similarity}
    )
    if cwe_pattern_result:
        relationship_counts["cwe_to_pattern"] = cwe_pattern_result[0]["count"]

    # Link CVEs to vulnerability patterns
    cve_pattern_query = f"""
    MATCH (cve:CVE), (pattern:{NodeLabels.VULNERABILITY_PATTERN})
    WITH cve, pattern, gds.similarity.cosine(cve.embedding, pattern.embedding) AS similarity
    WHERE similarity >= $threshold
    MERGE (cve)-[r:{RelationshipTypes.RELATES_TO}]->(pattern)
    SET r.similarity = similarity
    RETURN count(*) as count
    """
    cve_pattern_result = connector.run_query(
        cve_pattern_query, {"threshold": min_similarity}
    )
    if cve_pattern_result:
        relationship_counts["cve_to_pattern"] = cve_pattern_result[0]["count"]

    total_relationships = sum(relationship_counts.values())
    logger.info(
        f"Created {total_relationships} knowledge relationships: {relationship_counts}"
    )

    return relationship_counts


async def initialize_knowledge_graph(
    knowledge_dir: str,
    cwe_file_path: Optional[str] = None,
    cve_file_path: Optional[str] = None,
    download_cwe: bool = False,
) -> Dict[str, Any]:
    """Initialize the knowledge graph with base knowledge.

    Args:
        knowledge_dir: Directory containing knowledge documents
        cwe_file_path: Optional path to CWE XML file
        cve_file_path: Optional path to CVE JSON file
        download_cwe: Whether to download the latest CWE database

    Returns:
        Dictionary with initialization statistics
    """
    logger.info("Initializing knowledge graph")
    stats = {
        "schema_initialized": False,
        "documents_ingested": 0,
        "cwe_processed": 0,
        "cve_processed": 0,
        "relationships_created": 0,
    }

    # Initialize schema
    schema_manager = SchemaManager()
    schema_results = schema_manager.initialize_schema_components()
    stats["schema_initialized"] = all(schema_results.values())

    # Ingest knowledge documents
    if knowledge_dir:
        try:
            knowledge_path = Path(knowledge_dir)
            if knowledge_path.exists() and knowledge_path.is_dir():
                directory_results = await ingest_knowledge_directory(
                    str(knowledge_path)
                )
                stats["documents_ingested"] = directory_results["successful"]
                stats["document_sections"] = directory_results.get("sections", 0)
                stats["vulnerability_patterns"] = directory_results.get(
                    "vulnerability_patterns", 0
                )
            else:
                logger.warning(f"Knowledge directory not found: {knowledge_dir}")
        except Exception as e:
            logger.error(f"Error ingesting knowledge directory: {e}")

    # Ingest CWE database
    if cwe_file_path or download_cwe:
        try:
            if download_cwe:
                download_dir = Path(knowledge_dir) / "cwe"
                download_dir.mkdir(exist_ok=True)
                cwe_file_path = await download_cwe_database(str(download_dir))

            if cwe_file_path and Path(cwe_file_path).exists():
                cwe_results = await ingest_cwe_database(cwe_file_path)
                stats["cwe_processed"] = cwe_results.get("processed_cwes", 0)
                stats["cwe_categories"] = cwe_results.get("categories", 0)
                stats["cwe_relationships"] = cwe_results.get("relationships", 0)
            else:
                logger.warning(f"CWE file not found: {cwe_file_path}")
        except Exception as e:
            logger.error(f"Error ingesting CWE database: {e}")

    # Ingest CVE data
    if cve_file_path:
        try:
            if Path(cve_file_path).exists():
                cve_results = await ingest_cve_data(cve_file_path)
                stats["cve_processed"] = cve_results.get("processed_count", 0)
                stats["cve_failed"] = cve_results.get("failed_count", 0)
                stats["cwe_links"] = cve_results.get("cwe_links", 0)
            else:
                logger.warning(f"CVE file not found: {cve_file_path}")
        except Exception as e:
            logger.error(f"Error ingesting CVE data: {e}")

    # Link related knowledge
    try:
        relationship_results = await link_related_knowledge(min_similarity=0.75)
        stats["relationships_created"] = sum(relationship_results.values())
        stats["relationship_details"] = relationship_results
    except Exception as e:
        logger.error(f"Error linking related knowledge: {e}")

    logger.info(f"Knowledge graph initialization complete: {stats}")
    return stats

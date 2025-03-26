"""CWE database ingestion module for the Skwaq vulnerability assessment copilot.

This module handles the ingestion of Common Weakness Enumeration (CWE) data
into the knowledge graph, providing a structured view of common software weaknesses.
"""

import asyncio
import json
import os
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple, Union, Set

from ..db.neo4j_connector import get_connector
from ..db.schema import NodeLabels, RelationshipTypes
from ..core.openai_client import get_openai_client
from ..utils.logging import get_logger, LogEvent

logger = get_logger(__name__)


class CWEProcessor:
    """Processor for CWE (Common Weakness Enumeration) data.

    This class handles the processing and ingestion of CWE data into the knowledge graph,
    providing a structured representation of common software weaknesses.
    """

    def __init__(self):
        """Initialize the CWE processor."""
        self.connector = get_connector()
        self.openai_client = get_openai_client(async_mode=True)
        self.processed_cwes: Set[str] = set()
        self.category_weaknesses: Dict[str, List[str]] = {}

    async def ingest_cwe_xml(self, xml_file_path: str) -> Dict[str, Any]:
        """Ingest CWE data from an XML file into the knowledge graph.

        Args:
            xml_file_path: Path to the CWE XML file

        Returns:
            Dictionary with ingestion statistics
        """
        logger.info(f"Ingesting CWE data from: {xml_file_path}")
        path = Path(xml_file_path)

        if not path.exists() or not path.is_file():
            raise FileNotFoundError(f"File not found: {xml_file_path}")

        try:
            # Track statistics
            stats = {
                "total_cwes": 0,
                "processed_cwes": 0,
                "failed_cwes": 0,
                "categories": 0,
                "relationships": 0,
            }

            # Parse XML file
            tree = ET.parse(xml_file_path)
            root = tree.getroot()

            # Get namespace
            ns = {"cwe": root.tag.split("}")[0].strip("{")} if "}" in root.tag else ""
            ns_prefix = f"{{{ns}}}" if ns else ""

            # Process categories first
            await self._process_categories(root, ns_prefix, stats)

            # Process individual weaknesses
            await self._process_weaknesses(root, ns_prefix, stats)

            # Process relationships between weaknesses
            await self._process_relationships(root, ns_prefix, stats)

            # Create vector indexes for CWE nodes
            self._create_vector_indexes()

            logger.info(
                f"CWE ingestion complete. Processed: {stats['processed_cwes']}, Categories: {stats['categories']}"
            )
            return stats

        except Exception as e:
            logger.error(f"Error ingesting CWE data from {xml_file_path}: {e}")
            raise

    async def _process_categories(
        self, root: ET.Element, ns_prefix: str, stats: Dict[str, Any]
    ) -> None:
        """Process CWE categories from the XML root.

        Args:
            root: XML root element
            ns_prefix: XML namespace prefix
            stats: Statistics dictionary to update
        """
        logger.info("Processing CWE categories")
        categories = root.findall(f".//{ns_prefix}Category")

        for category in categories:
            try:
                # Extract category data
                cwe_id = category.get("ID", "")
                name = category.get("Name", "")

                # Find description
                desc_elem = category.find(f"./{ns_prefix}Description")
                description = (
                    desc_elem.text if desc_elem is not None and desc_elem.text else ""
                )

                # Create category node properties
                properties = {
                    "cwe_id": cwe_id,
                    "name": name,
                    "description": description,
                    "node_type": "Category",
                }

                # Generate embedding for the category
                embedding_text = f"CWE-{cwe_id}: {name}\n\n{description}"
                properties["embedding"] = await self.openai_client.get_embedding(
                    embedding_text
                )

                # Create category node
                category_id = self.connector.create_node(
                    labels=[NodeLabels.CWE, NodeLabels.KNOWLEDGE, "Category"],
                    properties=properties,
                )

                if category_id is None:
                    logger.warning(f"Failed to create node for CWE Category {cwe_id}")
                    continue

                # Track processed category
                self.processed_cwes.add(cwe_id)
                stats["categories"] += 1

                # Process members
                members_elem = category.find(f"./{ns_prefix}Relationships")
                if members_elem is not None:
                    members = members_elem.findall(f"./{ns_prefix}Has_Member")
                    member_ids = [m.get("CWE_ID") for m in members if m.get("CWE_ID")]

                    # Store for later relationship creation
                    self.category_weaknesses[cwe_id] = member_ids

            except Exception as e:
                logger.error(
                    f"Error processing CWE category {category.get('ID', 'unknown')}: {e}"
                )
                stats["failed_cwes"] += 1

        logger.info(f"Processed {stats['categories']} CWE categories")

    async def _process_weaknesses(
        self, root: ET.Element, ns_prefix: str, stats: Dict[str, Any]
    ) -> None:
        """Process CWE weaknesses from the XML root.

        Args:
            root: XML root element
            ns_prefix: XML namespace prefix
            stats: Statistics dictionary to update
        """
        logger.info("Processing CWE weaknesses")
        weaknesses = root.findall(f".//{ns_prefix}Weakness")
        stats["total_cwes"] = len(weaknesses)

        for weakness in weaknesses:
            try:
                # Extract weakness data
                cwe_id = weakness.get("ID", "")
                name = weakness.get("Name", "")
                abstraction = weakness.get("Abstraction", "")
                status = weakness.get("Status", "")

                # Find description
                desc_elem = weakness.find(f"./{ns_prefix}Description")
                description = (
                    desc_elem.text if desc_elem is not None and desc_elem.text else ""
                )

                # Extract likelihood of exploit
                likelihood_elem = weakness.find(f"./{ns_prefix}Likelihood_Of_Exploit")
                likelihood = (
                    likelihood_elem.text if likelihood_elem is not None else "Unknown"
                )

                # Extract consequences
                consequences = []
                for consequence in weakness.findall(f".//{ns_prefix}Consequence"):
                    scope_elem = consequence.find(f"./{ns_prefix}Scope")
                    impact_elem = consequence.find(f"./{ns_prefix}Impact")

                    if scope_elem is not None and impact_elem is not None:
                        consequences.append(
                            {"scope": scope_elem.text, "impact": impact_elem.text}
                        )

                # Extract detection methods
                detection_methods = []
                for method in weakness.findall(f".//{ns_prefix}Detection_Method"):
                    method_elem = method.find(f"./{ns_prefix}Method")
                    desc_elem = method.find(f"./{ns_prefix}Description")

                    if method_elem is not None and desc_elem is not None:
                        detection_methods.append(
                            {"method": method_elem.text, "description": desc_elem.text}
                        )

                # Create weakness node properties
                properties = {
                    "cwe_id": cwe_id,
                    "name": name,
                    "description": description,
                    "abstraction": abstraction,
                    "status": status,
                    "likelihood": likelihood,
                    "consequences": json.dumps(consequences),
                    "detection_methods": json.dumps(detection_methods),
                    "node_type": "Weakness",
                }

                # Generate summary using OpenAI
                summary_prompt = f"""Summarize this Common Weakness Enumeration (CWE) in 2-3 sentences:
                
CWE-{cwe_id}: {name}

Description:
{description}

Focus on what this weakness is, its impact, and how it might be mitigated.
"""
                properties["summary"] = await self.openai_client.get_completion(
                    summary_prompt, temperature=0.3
                )

                # Generate embedding for the weakness
                embedding_text = f"CWE-{cwe_id}: {name}\n\n{description}"
                properties["embedding"] = await self.openai_client.get_embedding(
                    embedding_text
                )

                # Create weakness node
                weakness_id = self.connector.create_node(
                    labels=[
                        NodeLabels.CWE,
                        NodeLabels.VULNERABILITY_PATTERN,
                        NodeLabels.KNOWLEDGE,
                    ],
                    properties=properties,
                )

                if weakness_id is None:
                    logger.warning(f"Failed to create node for CWE-{cwe_id}")
                    stats["failed_cwes"] += 1
                    continue

                # Process code examples if available
                code_examples = weakness.findall(f".//{ns_prefix}Example")
                for i, example in enumerate(code_examples):
                    await self._process_code_example(
                        example, weakness_id, cwe_id, i, ns_prefix
                    )

                # Track processed weakness
                self.processed_cwes.add(cwe_id)
                stats["processed_cwes"] += 1

                # Log progress periodically
                if stats["processed_cwes"] % 50 == 0:
                    logger.info(f"Processed {stats['processed_cwes']} CWEs...")

            except Exception as e:
                logger.error(
                    f"Error processing CWE-{weakness.get('ID', 'unknown')}: {e}"
                )
                stats["failed_cwes"] += 1

        logger.info(f"Processed {stats['processed_cwes']} CWE weaknesses")

    async def _process_code_example(
        self,
        example: ET.Element,
        weakness_id: int,
        cwe_id: str,
        example_index: int,
        ns_prefix: str,
    ) -> None:
        """Process a code example for a CWE weakness.

        Args:
            example: XML element containing the code example
            weakness_id: Neo4j node ID of the weakness
            cwe_id: CWE ID string
            example_index: Index of the example
            ns_prefix: XML namespace prefix
        """
        try:
            # Extract code example data
            nature_elem = example.find(f"./{ns_prefix}Nature")
            nature = nature_elem.text if nature_elem is not None else "Unknown"

            # Extract code snippets
            code_snippets = []
            for snippet in example.findall(f".//{ns_prefix}Code_Block"):
                lang_elem = snippet.get("Language", "")
                code_text = snippet.text if snippet.text else ""

                if code_text:
                    code_snippets.append({"language": lang_elem, "code": code_text})

            if not code_snippets:
                return  # Skip if no code snippets found

            # Create example node properties
            properties = {
                "cwe_id": cwe_id,
                "example_index": example_index,
                "nature": nature,
                "code_snippets": json.dumps(code_snippets),
            }

            # Create code example node
            example_id = self.connector.create_node(
                labels=["CodeExample", NodeLabels.KNOWLEDGE],
                properties=properties,
            )

            if example_id is not None:
                # Link weakness to code example
                self.connector.create_relationship(
                    weakness_id, example_id, RelationshipTypes.HAS_EXAMPLE
                )

        except Exception as e:
            logger.error(f"Error processing code example for CWE-{cwe_id}: {e}")

    async def _process_relationships(
        self, root: ET.Element, ns_prefix: str, stats: Dict[str, Any]
    ) -> None:
        """Process relationships between CWEs.

        Args:
            root: XML root element
            ns_prefix: XML namespace prefix
            stats: Statistics dictionary to update
        """
        logger.info("Processing CWE relationships")

        # Process direct relationships in weaknesses
        weaknesses = root.findall(f".//{ns_prefix}Weakness")

        for weakness in weaknesses:
            try:
                cwe_id = weakness.get("ID", "")
                if not cwe_id or cwe_id not in self.processed_cwes:
                    continue

                # Process related weaknesses
                related_elem = weakness.find(f"./{ns_prefix}Related_Weaknesses")
                if related_elem is not None:
                    for related in related_elem.findall(
                        f"./{ns_prefix}Related_Weakness"
                    ):
                        related_id = related.get("CWE_ID", "")
                        nature = related.get("Nature", "")

                        if related_id and related_id in self.processed_cwes:
                            # Find nodes
                            source_query = (
                                f"MATCH (source:{NodeLabels.CWE}) "
                                f"WHERE source.cwe_id = $source_id "
                                f"RETURN id(source) as node_id"
                            )
                            source_result = self.connector.run_query(
                                source_query, {"source_id": cwe_id}
                            )

                            target_query = (
                                f"MATCH (target:{NodeLabels.CWE}) "
                                f"WHERE target.cwe_id = $target_id "
                                f"RETURN id(target) as node_id"
                            )
                            target_result = self.connector.run_query(
                                target_query, {"target_id": related_id}
                            )

                            if source_result and target_result:
                                source_id = source_result[0]["node_id"]
                                target_id = target_result[0]["node_id"]

                                # Create relationship with nature as property
                                result = self.connector.create_relationship(
                                    source_id,
                                    target_id,
                                    RelationshipTypes.RELATES_TO,
                                    {"nature": nature},
                                )

                                if result:
                                    stats["relationships"] += 1

            except Exception as e:
                logger.error(
                    f"Error processing relationships for CWE-{weakness.get('ID', 'unknown')}: {e}"
                )

        # Process category-weakness relationships
        for category_id, member_ids in self.category_weaknesses.items():
            try:
                # Find category node
                category_query = (
                    f"MATCH (category:{NodeLabels.CWE}) "
                    f"WHERE category.cwe_id = $category_id "
                    f"RETURN id(category) as node_id"
                )
                category_result = self.connector.run_query(
                    category_query, {"category_id": category_id}
                )

                if not category_result:
                    continue

                category_node_id = category_result[0]["node_id"]

                # Link to each member
                for member_id in member_ids:
                    if member_id in self.processed_cwes:
                        member_query = (
                            f"MATCH (member:{NodeLabels.CWE}) "
                            f"WHERE member.cwe_id = $member_id "
                            f"RETURN id(member) as node_id"
                        )
                        member_result = self.connector.run_query(
                            member_query, {"member_id": member_id}
                        )

                        if member_result:
                            member_node_id = member_result[0]["node_id"]

                            # Create relationship
                            result = self.connector.create_relationship(
                                category_node_id,
                                member_node_id,
                                RelationshipTypes.CONTAINS,
                            )

                            if result:
                                stats["relationships"] += 1

            except Exception as e:
                logger.error(
                    f"Error processing category relationships for CWE-{category_id}: {e}"
                )

        logger.info(f"Created {stats['relationships']} CWE relationships")

    def _create_vector_indexes(self) -> None:
        """Create vector indexes for CWE nodes."""
        # Create vector index for CWE embeddings
        self.connector.create_vector_index(
            index_name="cwe_embedding",
            node_label=NodeLabels.CWE,
            vector_property="embedding",
            embedding_dimension=1536,  # Default size for OpenAI embeddings
        )


@LogEvent("cwe_ingestion")
async def ingest_cwe_database(xml_file_path: str) -> Dict[str, Any]:
    """Ingest the CWE database from an XML file.

    Args:
        xml_file_path: Path to the CWE XML file

    Returns:
        Dictionary with ingestion statistics
    """
    processor = CWEProcessor()
    return await processor.ingest_cwe_xml(xml_file_path)


async def download_cwe_database(output_path: str) -> str:
    """Download the latest CWE database XML file.

    Args:
        output_path: Directory to save the downloaded file

    Returns:
        Path to the downloaded file
    """
    import aiohttp
    from datetime import datetime

    # CWE download URL - official source
    CWE_URL = "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip"

    logger.info(f"Downloading CWE database from: {CWE_URL}")
    output_dir = Path(output_path)
    output_dir.mkdir(parents=True, exist_ok=True)

    # Create timestamped filename
    timestamp = datetime.now().strftime("%Y%m%d")
    zip_path = output_dir / f"cwe_{timestamp}.xml.zip"
    xml_path = output_dir / f"cwe_{timestamp}.xml"

    try:
        # Download the zip file
        async with aiohttp.ClientSession() as session:
            async with session.get(CWE_URL) as response:
                if response.status != 200:
                    raise RuntimeError(
                        f"Failed to download CWE database: {response.status}"
                    )

                with open(zip_path, "wb") as f:
                    f.write(await response.read())

        logger.info(f"Downloaded CWE database to: {zip_path}")

        # Extract the XML file
        import zipfile

        with zipfile.ZipFile(zip_path, "r") as zip_ref:
            # Find the XML file in the zip
            xml_files = [f for f in zip_ref.namelist() if f.endswith(".xml")]
            if not xml_files:
                raise RuntimeError(f"No XML files found in {zip_path}")

            # Extract the first XML file
            with zip_ref.open(xml_files[0]) as src, open(xml_path, "wb") as dst:
                dst.write(src.read())

        logger.info(f"Extracted CWE database to: {xml_path}")

        # Clean up the zip file
        zip_path.unlink()

        return str(xml_path)

    except Exception as e:
        logger.error(f"Error downloading CWE database: {e}")
        # Clean up if files exist
        if zip_path.exists():
            zip_path.unlink()
        if xml_path.exists():
            xml_path.unlink()
        raise

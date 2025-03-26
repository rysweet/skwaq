"""Ingestion module for the Skwaq vulnerability assessment copilot.

This module handles the ingestion of code repositories and background knowledge
into the system for analysis.

Note: The code_analysis functionality is now available in the skwaq.code_analysis module.
Legacy compatibility functions are still provided in skwaq.ingestion.code_analysis,
but new code should use the new module structure.
"""


def ingest_repository(repo_path: str) -> None:
    """Ingest a repository by parsing code, filesystem and creating graph entries."""
    # TODO: Implement repository ingestion logic
    pass


def ingest_knowledge_source(source_path: str) -> None:
    """Ingest knowledge sources (e.g. background docs) into the knowledge graph."""
    # TODO: Implement knowledge ingestion logic
    pass


def ingest_cve_source(source_path: str) -> None:
    """Ingest CVE data from the specified source path."""
    # TODO: Implement CVE ingestion logic
    pass

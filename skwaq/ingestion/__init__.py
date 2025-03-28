"""Ingestion module for Skwaq vulnerability assessment copilot.

This module provides functionality to ingest codebases from local file systems
or Git repositories into the Neo4j graph database for vulnerability assessment.
"""

from .ingestion import Ingestion, IngestionStatus

__all__ = ["Ingestion", "IngestionStatus"]

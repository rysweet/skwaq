#!/usr/bin/env python3
"""Example of using the Sources and Sinks workflow.

This example demonstrates how to use the Sources and Sinks workflow to analyze a repository
for potential data flow vulnerabilities.
"""

import os
import sys
import asyncio
import json
from pathlib import Path

# Add the parent directory to the path to import skwaq
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from skwaq.core.openai_client import OpenAIClient
from skwaq.db.neo4j_connector import Neo4jConnector, get_connector
from skwaq.workflows.sources_and_sinks import (
    SourcesAndSinksWorkflow,
    CodeSummaryFunnel,
    LLMAnalyzer,
    DocumentationAnalyzer,
)
from skwaq.utils.config import Config


async def main():
    """Run the sources and sinks workflow on a sample repository."""
    # Load configuration
    config = Config()

    # Connect to Neo4j
    neo4j_connector = Neo4jConnector(
        uri=config.get("neo4j.uri", "bolt://localhost:7687"),
        username=config.get("neo4j.username", "neo4j"),
        password=config.get("neo4j.password", "password"),
    )

    # Set as the global connector
    get_connector.connector = neo4j_connector

    # Initialize OpenAI client
    openai_client = OpenAIClient(
        model=config.get("openai.model", "gpt-4-turbo"),
        api_key=config.get("openai.api_key"),
        api_type=config.get("openai.api_type", "azure"),
        api_base=config.get("openai.api_base"),
        api_version=config.get("openai.api_version", "2023-07-01-preview"),
    )

    # Get a list of investigations
    investigations = neo4j_connector.run_query(
        "MATCH (i:Investigation) RETURN i.id AS id, i.name AS name LIMIT 10"
    )

    if not investigations:
        print("No investigations found. Please ingest a repository first.")
        return

    # Print available investigations
    print("Available investigations:")
    for i, inv in enumerate(investigations):
        print(f"{i+1}. {inv['name']} (ID: {inv['id']})")

    # Select an investigation (in a real application, you might prompt the user)
    investigation_id = investigations[0]["id"]
    print(f"\nUsing investigation: {investigation_id}")

    # Create the workflow
    workflow = SourcesAndSinksWorkflow(
        llm_client=openai_client,
        investigation_id=investigation_id,
        name="Sources and Sinks Analysis",
        description="Identifies potential sources and sinks in code repositories",
    )

    # Optional: Register custom funnels or analyzers
    # workflow.register_funnel(CustomFunnel())
    # workflow.register_analyzer(CustomAnalyzer())

    # Run the workflow
    print("\nRunning Sources and Sinks workflow...")
    result = await workflow.run()

    # Print the results
    print("\nWorkflow completed!")
    print(f"Found {len(result.sources)} sources and {len(result.sinks)} sinks")
    print(f"Identified {len(result.data_flow_paths)} potential data flow paths")

    # Print summary
    print("\nSummary:")
    print(result.summary)

    # Export results
    output_dir = Path(__file__).parent / "outputs"
    output_dir.mkdir(exist_ok=True)

    # Save JSON results
    json_path = output_dir / f"sources_and_sinks_{investigation_id}.json"
    with open(json_path, "w") as f:
        f.write(result.to_json())
    print(f"\nJSON results saved to: {json_path}")

    # Save Markdown report
    md_path = output_dir / f"sources_and_sinks_{investigation_id}.md"
    with open(md_path, "w") as f:
        f.write(result.to_markdown())
    print(f"Markdown report saved to: {md_path}")


if __name__ == "__main__":
    asyncio.run(main())

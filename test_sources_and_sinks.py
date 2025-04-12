#!/usr/bin/env python3
"""Test script for the Sources and Sinks workflow.

This script creates a simple test to verify that the Sources and Sinks workflow
can be initialized and run using the updated OpenAI client implementation.
"""

import asyncio
import logging

from skwaq.core.openai_client import get_openai_client
from skwaq.utils.config import get_config
from skwaq.workflows.sources_and_sinks import SourcesAndSinksWorkflow

# Set up logging
logging.basicConfig(level=logging.INFO)


async def main():
    # Get OpenAI client
    print("Initializing OpenAI client...")
    config = get_config()
    openai_client = get_openai_client(async_mode=True)

    # Create workflow
    print("Creating Sources and Sinks workflow...")
    workflow = SourcesAndSinksWorkflow(
        llm_client=openai_client,
        investigation_id="inv-test",  # Use a dummy investigation ID
        name="Test Sources and Sinks Workflow",
        description="Test workflow for sources and sinks",
    )

    # Setup the workflow
    print("Setting up workflow...")
    await workflow.setup()

    # Print information about the workflow
    print(
        f"Workflow initialized with {len(workflow.funnels)} funnels and {len(workflow.analyzers)} analyzers"
    )
    print("Analyzers:")
    for analyzer in workflow.analyzers:
        print(f"- {analyzer.__class__.__name__}")

    print("Test successful!")


if __name__ == "__main__":
    asyncio.run(main())

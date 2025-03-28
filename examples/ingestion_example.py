"""Example of using the Skwaq Ingestion module.

This example demonstrates how to ingest a codebase from a Git repository 
and track the progress of the ingestion process.
"""
import asyncio
import time
from skwaq.core.openai_client import get_openai_client
from skwaq.ingestion import Ingestion
from skwaq.utils.logging import get_logger

logger = get_logger(__name__)

async def ingest_repository():
    """Ingest a GitHub repository as an example."""
    # Get OpenAI client for the LLM processing
    openai_client = get_openai_client(async_mode=True)
    
    # Initialize ingestion with repo URL and branch
    repo = "https://github.com/dotnet/eShop"
    branch = "main"
    
    # Create ingestion instance
    ingestion = Ingestion(repo=repo, branch=branch, model_client=openai_client)
    
    # Start ingestion and get ID
    ingestion_id = await ingestion.ingest()
    logger.info(f"Started ingestion with ID: {ingestion_id}")
    
    # Poll for status updates until complete
    completed = False
    while not completed:
        status = await ingestion.get_status(ingestion_id)
        logger.info(f"Status: {status.state} - Progress: {status.progress}%")
        logger.info(f"Files processed: {status.files_processed}/{status.total_files}")
        
        if status.errors:
            logger.warning(f"Encountered {len(status.errors)} errors")
        
        # Check if ingestion is complete
        if status.state in ["completed", "failed"]:
            completed = True
            logger.info(f"Ingestion {status.state} in {status.time_elapsed} seconds")
        else:
            # Wait before polling again
            await asyncio.sleep(10)
    
    return ingestion_id, status

async def ingest_local_codebase():
    """Ingest a local codebase as an example."""
    # Get OpenAI client for the LLM processing
    openai_client = get_openai_client(async_mode=True)
    
    # Set path to local codebase
    local_path = "/path/to/local/codebase"
    
    # Create ingestion instance with local path
    ingestion = Ingestion(local_path=local_path, model_client=openai_client)
    
    # Start ingestion and get ID
    ingestion_id = await ingestion.ingest()
    logger.info(f"Started ingestion with ID: {ingestion_id}")
    
    # Poll for status updates until complete
    completed = False
    while not completed:
        status = await ingestion.get_status(ingestion_id)
        logger.info(f"Status: {status.state} - Progress: {status.progress}%")
        
        # Check if ingestion is complete
        if status.state in ["completed", "failed"]:
            completed = True
            logger.info(f"Ingestion {status.state} in {status.time_elapsed} seconds")
        else:
            # Wait before polling again
            await asyncio.sleep(5)
    
    return ingestion_id, status

if __name__ == "__main__":
    asyncio.run(ingest_repository())
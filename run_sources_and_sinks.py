#!/usr/bin/env python3
"""Script to run sources and sinks workflow on a repository"""

import asyncio
import sys
import time
from typing import Any, Dict

from skwaq.db.neo4j_connector import get_connector
from skwaq.utils.logging import get_logger
from skwaq.workflows.sources_and_sinks import SourcesAndSinksWorkflow
from skwaq.core.openai_client import get_openai_client

logger = get_logger(__name__)

async def run_workflow(repo_id: str) -> Dict[str, Any]:
    """Run the sources and sinks workflow on a repository.
    
    Args:
        repo_id: Repository ID
        
    Returns:
        Dictionary with workflow results
    """
    # Get repository info
    connector = get_connector()
    
    repo_query = """
    MATCH (r:Repository {ingestion_id: $id})
    RETURN r
    """
    
    results = connector.run_query(repo_query, {"id": repo_id})
    if not results:
        logger.error(f"Repository with ID {repo_id} not found")
        return {"error": "Repository not found"}
    
    repo_node = results[0]["r"]
    repo_name = repo_node.get("name", "Unknown Repository")
    
    # Create investigation
    investigation_id = f"inv-{repo_id[:8]}"
    create_investigation_query = """
    CREATE (i:Investigation {
        id: $id,
        title: $title,
        description: $description,
        status: 'In Progress',
        created_at: datetime()
    })
    RETURN elementId(i) as investigation_id
    """
    
    investigation_params = {
        "id": investigation_id,
        "title": f"{repo_name} Security Analysis",
        "description": f"Sources and sinks analysis for {repo_name}"
    }
    
    investigation_result = connector.run_query(create_investigation_query, investigation_params)
    if not investigation_result:
        logger.error("Failed to create investigation")
        return {"error": "Failed to create investigation"}
    
    # Link investigation to repository
    link_query = """
    MATCH (i:Investigation {id: $investigation_id}),
          (r:Repository {ingestion_id: $repo_id})
    CREATE (i)-[:ANALYZES]->(r)
    """
    
    connector.run_query(link_query, {
        "investigation_id": investigation_id,
        "repo_id": repo_id
    })
    
    # Initialize LLM client
    openai_client = get_openai_client(async_mode=True)
    
    # Initialize workflow
    workflow = SourcesAndSinksWorkflow(llm_client=openai_client, investigation_id=investigation_id)
    
    # Run workflow
    logger.info(f"Running sources and sinks workflow for {repo_name}")
    start_time = time.time()
    
    result = await workflow.run()
    
    end_time = time.time()
    logger.info(f"Workflow completed in {end_time - start_time:.2f} seconds")
    
    # Get sources and sinks
    sources_query = """
    MATCH (i:Investigation {id: $id})-[:HAS_SOURCE]->(s:Source)
    RETURN COUNT(s) as source_count
    """
    
    sources_result = connector.run_query(sources_query, {"id": investigation_id})
    source_count = sources_result[0]["source_count"] if sources_result else 0
    
    sinks_query = """
    MATCH (i:Investigation {id: $id})-[:HAS_SINK]->(s:Sink)
    RETURN COUNT(s) as sink_count
    """
    
    sinks_result = connector.run_query(sinks_query, {"id": investigation_id})
    sink_count = sinks_result[0]["sink_count"] if sinks_result else 0
    
    # Get flows
    flows_query = """
    MATCH (i:Investigation {id: $id})-[:HAS_DATA_FLOW_PATH]->(p:DataFlowPath)
    RETURN COUNT(p) as flow_count
    """
    
    flows_result = connector.run_query(flows_query, {"id": investigation_id})
    flow_count = flows_result[0]["flow_count"] if flows_result else 0
    
    return {
        "investigation_id": investigation_id,
        "repository_id": repo_id,
        "repository_name": repo_name,
        "source_count": source_count,
        "sink_count": sink_count,
        "flow_count": flow_count,
        "execution_time": end_time - start_time
    }

async def main():
    """Main function."""
    if len(sys.argv) < 2:
        print("Usage: python run_sources_and_sinks.py <repository_id>")
        
        # List repositories
        connector = get_connector()
        query = """
        MATCH (r:Repository)
        RETURN r.ingestion_id as id, r.name as name
        """
        
        repo_results = connector.run_query(query)
        
        if repo_results:
            print("\nAvailable repositories:")
            for result in repo_results:
                print(f"  {result.get('name', 'Unknown')}: {result['id']}")
        
        sys.exit(1)
    
    repo_id = sys.argv[1]
    
    # Run workflow
    results = await run_workflow(repo_id)
    
    if "error" in results:
        print(f"Error: {results['error']}")
        sys.exit(1)
    
    # Print results
    print("\nWorkflow Results:")
    print(f"- Investigation ID: {results['investigation_id']}")
    print(f"- Repository: {results['repository_name']} ({results['repository_id']})")
    print(f"- Sources found: {results['source_count']}")
    print(f"- Sinks found: {results['sink_count']}")
    print(f"- Data flows identified: {results['flow_count']}")
    print(f"- Execution time: {results['execution_time']:.2f} seconds")
    
    # Visualize results
    print("\nTo visualize the results, run:")
    print(f"python direct_visualize.py {results['investigation_id']}")

if __name__ == "__main__":
    asyncio.run(main())
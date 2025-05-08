#\!/usr/bin/env python3
"""Create a visualization for an investigation."""

import asyncio
import sys
from datetime import datetime
import uuid
from skwaq.db.neo4j_connector import get_connector
from skwaq.cli.commands.workflow_commands import InvestigationCommandHandler

class MockArgs:
    def __init__(self, investigation_id):
        self.investigation_command = "visualize"
        self.id = investigation_id
        self.format = "html"
        self.output = f"investigation-{investigation_id}.html"
        self.include_findings = True
        self.include_vulnerabilities = True
        self.include_files = True
        self.max_nodes = 1000

async def main():
    """Create a visualization for the most recent investigation."""
    print("Creating visualization for investigation...")
    
    # Get the most recent investigation
    connector = get_connector()
    query = """
    MATCH (i:Investigation)
    RETURN i.id as id
    ORDER BY i.created_at DESC
    LIMIT 1
    """
    
    results = connector.run_query(query)
    if not results:
        print("No investigations found\!")
        return 1
    
    investigation_id = results[0]["id"]
    print(f"Found investigation: {investigation_id}")
    
    # Create the command handler
    args = MockArgs(investigation_id)
    handler = InvestigationCommandHandler(args)
    
    # Run the visualization handler
    print("Generating visualization...")
    result = await handler._handle_visualize()
    
    if result == 0:
        print(f"Visualization created successfully: investigation-{investigation_id}.html")
    else:
        print("Visualization failed.")
    
    return result

if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code)

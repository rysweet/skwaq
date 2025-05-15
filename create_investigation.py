#\!/usr/bin/env python3
"""Create an investigation for a repository and visualize it."""

import asyncio
import sys
from datetime import datetime
import uuid
from rich.console import Console
from skwaq.db.neo4j_connector import get_connector
from skwaq.cli.commands.workflow_commands import InvestigationCommandHandler
from skwaq.cli.ui.console import success, error, info
from skwaq.cli.ui.progress import create_status_indicator

console = Console()

async def create_investigation(status):
    """Create an investigation for the repository."""
    connector = get_connector()
    
    status.update("[bold blue]Finding repository...")
    # Find repository node
    repo_query = """
    MATCH (r:Repository)
    RETURN elementId(r) as repo_id, r.name as name
    LIMIT 1
    """
    
    repos = connector.run_query(repo_query)
    if not repos:
        status.update("[bold red]No repositories found in database\!")
        return None
        
    repo_id = repos[0]["repo_id"]
    repo_name = repos[0]["name"]
    status.update(f"[bold green]Found repository: {repo_name} (ID: {repo_id})")
    
    # Get all file nodes for the repository
    file_query = """
    MATCH (f:File)
    WHERE NOT f:Directory
    RETURN DISTINCT elementId(f) as file_id, f.path as path
    LIMIT 500
    """
    
    files = connector.run_query(file_query)
    status.update(f"[bold blue]Found {len(files)} files to include in investigation...")
    
    # Generate investigation ID
    investigation_id = f"inv-{uuid.uuid4().hex[:8]}"
    
    # Create investigation node
    investigation_props = {
        "id": investigation_id,
        "title": "AttackBot Analysis",
        "description": "Comprehensive analysis of the AttackBot repository",
        "status": "In Progress",
        "created_at": datetime.now().isoformat(),
        "updated_at": datetime.now().isoformat(),
        "finding_count": 0,
    }
    
    investigation_node_id = connector.create_node(
        labels=["Investigation"], properties=investigation_props
    )
    
    # Link investigation to repository
    connector.create_relationship(
        repo_id, investigation_node_id, "HAS_INVESTIGATION"
    )
    
    # Include files in investigation (limit to 300 to keep visualization manageable)
    for i, file in enumerate(files[:300]):
        if i % 50 == 0:
            status.update(f"[bold blue]Adding files to investigation: {i}/{len(files[:300])}")
            
        file_id = file["file_id"]
        
        # Create relationship between investigation and file
        rel_query = """
        MATCH (i:Investigation {id: $investigation_id})
        MATCH (f:File) WHERE elementId(f) = $file_id
        MERGE (i)-[r:INCLUDES]->(f)
        RETURN type(r) as rel_type
        """
        
        connector.run_query(
            rel_query, {"investigation_id": investigation_id, "file_id": file_id}
        )
    
    status.update(f"[bold green]Investigation created\! ID: {investigation_id}")
    
    return investigation_id

async def visualize_investigation(investigation_id, status):
    """Visualize an investigation using the CLI handler."""
    # Create a mock args object for the command handler
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
    
    # Create the command handler
    args = MockArgs(investigation_id)
    handler = InvestigationCommandHandler(args)
    
    # Run the visualization handler
    status.update("[bold blue]Generating visualization...")
    result = await handler._handle_visualize()
    
    if result == 0:
        status.update(f"[bold green]Visualization created: investigation-{investigation_id}.html")
    else:
        status.update("[bold red]Visualization failed\!")

async def main():
    """Main function to run the test."""
    console.print("[bold cyan]Create Investigation and Visualization[/bold cyan]")
    
    # Create investigation and visualization
    with create_status_indicator("[bold blue]Starting...", spinner="dots") as status:
        # Create investigation
        investigation_id = await create_investigation(status)
        if not investigation_id:
            return 1
        
        # Visualize the investigation
        await visualize_investigation(investigation_id, status)
        
        # Display success message
        status.update(f"[bold green]Investigation {investigation_id} created and visualized\!")
    
    info(f"Visualization file: investigation-{investigation_id}.html")
    
    return 0

if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code)
EOF < /dev/null
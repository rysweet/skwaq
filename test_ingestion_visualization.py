#!/usr/bin/env python3
"""Test script for ingesting a repository and visualizing it with the fixed AST mapper."""

import asyncio
import sys
import os
from skwaq.ingestion.ingestion import Ingestion
from skwaq.ingestion.repository import RepositoryManager
from skwaq.db.neo4j_connector import get_connector
from skwaq.cli.commands.workflow_commands import InvestigationCommandHandler
from skwaq.cli.ui.console import console, success, error, info
from skwaq.cli.ui.progress import create_status_indicator
from rich.prompt import Confirm

async def reset_database():
    """Clear all nodes and relationships from the database."""
    connector = get_connector()
    
    with create_status_indicator("[bold red]Clearing database...", spinner="dots") as status:
        # Delete all nodes and relationships
        connector.run_query("MATCH (n) DETACH DELETE n")
        
        # Verify database is empty
        count = connector.run_query("MATCH (n) RETURN count(n) as count")[0]["count"]
        if count == 0:
            status.update("[bold green]Database cleared successfully!")
            return True
        else:
            status.update("[bold red]Failed to clear database!")
            return False

async def ingest_repository(repo_path, use_blarify=True, generate_summaries=True):
    """Ingest a repository into the Neo4j database."""
    # Create the repository manager with the connector
    connector = get_connector()
    repo_manager = RepositoryManager(connector)
    
    # Generate a unique ingestion ID
    import uuid
    ingestion_id = str(uuid.uuid4())
    
    # Add the repository
    with create_status_indicator(f"[bold blue]Adding repository {repo_path}...", spinner="dots") as status:
        # Create repository node directly
        repo_metadata = {
            "name": "AttackBot",
            "url": "none",
            "branch": "master",
            "repo_type": "local"
        }
        
        repo_id = repo_manager.create_repository_node(
            ingestion_id=ingestion_id,
            codebase_path=repo_path,
            metadata=repo_metadata
        )
        
        status.update(f"[bold green]Repository added! ID: {repo_id}")
    
    # Initialize ingestion
    ingestion = Ingestion(local_path=repo_path)
    
    # Start ingestion
    with create_status_indicator("[bold blue]Starting ingestion...", spinner="dots") as status:
        # Import OpenAI client for summarization
        if generate_summaries:
            from skwaq.core.openai_client import get_openai_client
            try:
                ingestion.model_client = get_openai_client(async_mode=True)
            except Exception as e:
                console.print(f"[bold red]Warning: Failed to initialize OpenAI client: {str(e)}")
                console.print("[bold yellow]Proceeding without code summarization...")
                ingestion.parse_only = True
        else:
            ingestion.parse_only = True
        
        # Run ingestion
        ingestion_id = await ingestion.ingest()
        
        # Wait for ingestion to complete
        while True:
            status_data = await ingestion.get_status(ingestion_id)
            status.update(f"[bold blue]{status_data.message} ({status_data.progress:.1f}%)")
            
            if status_data.state in ["completed", "failed"]:
                break
                
            await asyncio.sleep(2)
        
        if status_data.state == "completed":
            status.update("[bold green]Ingestion completed successfully!")
        else:
            status.update(f"[bold red]Ingestion failed: {status_data.error}")
            return None
    
    return repo_id

async def create_investigation(repo_id):
    """Create an investigation for the repository."""
    connector = get_connector()
    
    with create_status_indicator("[bold blue]Creating investigation...", spinner="dots") as status:
        # Check if repository exists
        repo = connector.run_query(
            "MATCH (r:Repository) WHERE id(r) = $id RETURN r.name as name",
            {"id": int(repo_id)},
        )
        
        if not repo:
            status.update(f"[bold red]Repository not found: {repo_id}")
            return None
        
        # Get all file nodes for the repository
        file_query = """
        MATCH (r:Repository)-[:CONTAINS*]->(f:File)
        WHERE id(r) = $repo_id AND NOT f:Directory
        RETURN DISTINCT elementId(f) as file_id, f.path as path
        LIMIT 500
        """
        
        files = connector.run_query(file_query, {"repo_id": int(repo_id)})
        status.update(f"[bold blue]Found {len(files)} files to include in investigation...")
        
        # Create an investigation node
        from datetime import datetime
        import uuid
        
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
            int(repo_id), investigation_node_id, "HAS_INVESTIGATION"
        )
        
        # Include files in investigation (limit to 300 to keep visualization manageable)
        for file in files[:300]:
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
        
        status.update(f"[bold green]Investigation created! ID: {investigation_id}")
        
        return investigation_id

async def visualize_investigation(investigation_id):
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
    result = await handler._handle_visualize()
    
    if result == 0:
        success(f"Visualization completed successfully: investigation-{investigation_id}.html")
    else:
        error("Visualization failed.")

async def check_ast_relationships():
    """Check if AST nodes have both PART_OF and DEFINES relationships."""
    connector = get_connector()
    
    # Count AST nodes
    ast_count_query = """
    MATCH (n) WHERE n:Function OR n:Class OR n:Method
    RETURN count(n) as ast_count
    """
    ast_count = connector.run_query(ast_count_query)[0]["ast_count"]
    
    # Count PART_OF relationships
    part_of_query = """
    MATCH (ast)-[:PART_OF]->(file:File)
    WHERE ast:Function OR ast:Class OR ast:Method
    RETURN count(ast) as part_of_count
    """
    part_of_count = connector.run_query(part_of_query)[0]["part_of_count"]
    
    # Count DEFINES relationships
    defines_query = """
    MATCH (file:File)-[:DEFINES]->(ast)
    WHERE ast:Function OR ast:Class OR ast:Method
    RETURN count(ast) as defines_count
    """
    defines_count = connector.run_query(defines_query)[0]["defines_count"]
    
    # Check AI summaries
    summary_query = """
    MATCH (s:CodeSummary)-[r]->(ast)
    WHERE ast:Function OR ast:Class OR ast:Method
    RETURN count(s) as summary_count, type(r) as rel_type
    """
    summary_results = connector.run_query(summary_query)
    summary_count = summary_results[0]["summary_count"] if summary_results else 0
    
    # Check for nodes with both relationships
    both_rel_query = """
    MATCH (ast)-[:PART_OF]->(file:File)-[:DEFINES]->(ast)
    WHERE ast:Function OR ast:Class OR ast:Method
    RETURN count(ast) as both_count
    """
    both_count = connector.run_query(both_rel_query)[0]["both_count"]
    
    return {
        "ast_count": ast_count,
        "part_of_count": part_of_count,
        "defines_count": defines_count,
        "summary_count": summary_count,
        "both_count": both_count
    }

async def main():
    """Main function to run the test."""
    console.print("[bold cyan]AttackBot Repository Ingestion and Visualization Test[/bold cyan]")
    
    # Use absolute path for Docker
    repo_path = "../../msec/red/AttackBot"
    abs_repo_path = os.path.abspath(repo_path)
    
    if not os.path.exists(abs_repo_path):
        error(f"Repository path not found: {abs_repo_path}")
        console.print(f"Please update the script with the correct path to the AttackBot repository.")
        return 1
        
    console.print(f"Using repository at: {abs_repo_path}")
    
    # Automatically clear the database without asking
    console.print("[bold blue]Clearing database before ingestion...[/bold blue]")
    success = await reset_database()
    if not success:
        return 1
    
    # Start ingestion
    repo_id = await ingest_repository(abs_repo_path, use_blarify=True, generate_summaries=True)
    if not repo_id:
        return 1
    
    # Check AST relationships
    info("Checking AST relationships...")
    relationship_stats = await check_ast_relationships()
    
    console.print("[bold green]AST Relationship Statistics:[/bold green]")
    console.print(f"Total AST nodes: {relationship_stats['ast_count']}")
    console.print(f"Nodes with PART_OF relationships: {relationship_stats['part_of_count']}")
    console.print(f"Nodes with DEFINES relationships: {relationship_stats['defines_count']}")
    console.print(f"Nodes with both relationships: {relationship_stats['both_count']}")
    console.print(f"AI summary nodes: {relationship_stats['summary_count']}")
    
    # Create an investigation
    investigation_id = await create_investigation(repo_id)
    if not investigation_id:
        return 1
    
    # Visualize the investigation
    await visualize_investigation(investigation_id)
    
    # Also create direct visualization with our custom script
    console.print("[bold blue]Creating custom visualization with ast_to_files script...[/bold blue]")
    os.system(f"python visualize_ast_to_files.py > /tmp/attackbot_final.html && echo 'Visualization created at /tmp/attackbot_final.html'")
    
    return 0

if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code)
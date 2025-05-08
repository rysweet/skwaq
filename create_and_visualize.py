#!/usr/bin/env python3

"""
Create an investigation and visualize it with AI summaries.
This script will:
1. Create a new investigation for the latest repository
2. Update AST nodes with code property
3. Generate AI summaries for AST nodes
4. Visualize the investigation with AI summaries
"""

import asyncio
import os
import subprocess
import sys
from typing import Optional

async def main():
    print("Starting investigation and visualization process...")
    
    # 1. Get the latest repository ID
    repo_info = get_latest_repository_id()
    if not repo_info:
        print("Error: No repository found. Please ingest a repository first.")
        return
    
    print(f"Using repository: ingestion_id={repo_info['ingestion_id']}, int_id={repo_info['int_id']}")
    
    # 2. Create a new investigation
    investigation_id = await create_investigation(repo_info['int_id'])
    if not investigation_id:
        print("Error: Failed to create investigation.")
        return
    
    print(f"Created investigation with ID: {investigation_id}")
    
    # 3. Fix AST nodes to have code property
    print("Updating AST nodes with code property from files...")
    await update_ast_nodes_with_code(repo_info)
    
    # 4. Generate AI summaries
    print("Generating AI summaries for AST nodes...")
    await generate_ai_summaries(repo_info)
    
    # 5. Visualize the investigation with AI summaries
    print("Creating visualization...")
    await visualize_investigation(investigation_id)
    
    print("Process completed!")

def get_latest_repository_id() -> Optional[dict]:
    """Get the ID of the latest repository with both ingestion_id and Neo4j node ID."""
    try:
        # Query the database directly
        from skwaq.db.neo4j_connector import get_connector
        connector = get_connector()
        
        query = """
        MATCH (r:Repository)
        WHERE r.name = 'AttackBot'
        RETURN r.ingestion_id as ingestion_id, elementId(r) as node_id, id(r) as int_id, r.path as path
        ORDER BY r.ingestion_start_time DESC
        LIMIT 1
        """
        
        results = connector.run_query(query)
        
        if results and len(results) > 0:
            return {
                'ingestion_id': results[0]['ingestion_id'],
                'node_id': results[0]['node_id'],
                'int_id': results[0]['int_id'],
                'path': results[0]['path']
            }
        
        print("No AttackBot repositories found in the database")
        return None
    
    except Exception as e:
        print(f"Error getting repository ID: {e}")
        import traceback
        traceback.print_exc()
        return None

async def create_investigation(node_id: str) -> Optional[str]:
    """Create a new investigation for the repository using Neo4j node ID."""
    try:
        # Create investigation using the node ID
        output = subprocess.check_output([
            "python", "-m", "skwaq", "investigations", "create",
            "--repo", str(node_id),
            "--description", "Analysis of AttackBot codebase with AI code summaries",
            "AttackBot Analysis"
        ], text=True)
        
        # Extract investigation ID from the output
        for line in output.splitlines():
            if "Investigation ID:" in line:
                return line.split(":")[-1].strip()
        
        return None
    
    except Exception as e:
        print(f"Error creating investigation: {e}")
        import traceback
        traceback.print_exc()
        return None

async def update_ast_nodes_with_code(repo_info: dict) -> bool:
    """Update AST nodes with code property from files."""
    try:
        from neo4j import GraphDatabase
        from skwaq.db.neo4j_connector import get_connector
        
        # Use the repository path from repo_info
        repo_path = repo_info['path']
        print(f"Repository path: {repo_path}")
        
        # Find AST nodes without code property that have PART_OF relationships to files
        connector = get_connector()
        ast_query = """
        MATCH (ast)-[:PART_OF]->(file:File)
        WHERE (ast:Function OR ast:Class OR ast:Method) AND ast.code IS NULL
            AND ast.start_line IS NOT NULL AND ast.end_line IS NOT NULL
        RETURN 
            elementId(ast) as ast_id,
            elementId(file) as file_id,
            file.path as file_path,
            ast.start_line as start_line,
            ast.end_line as end_line,
            labels(ast) as ast_labels,
            ast.name as ast_name
        LIMIT 1000
        """
        
        ast_results = connector.run_query(ast_query)
        print(f"Found {len(ast_results)} AST nodes to update")
        
        updated_count = 0
        
        # Process each AST node
        for node in ast_results:
            ast_id = node["ast_id"]
            file_path = node["file_path"]
            start_line = node["start_line"]
            end_line = node["end_line"]
            
            # Skip if missing line information
            if start_line is None or end_line is None:
                continue
            
            # Try to find the file
            possible_paths = [
                os.path.join(repo_path, file_path),
                file_path
            ]
            
            # For Windows compatibility
            normalized_paths = []
            for p in possible_paths:
                normalized_paths.append(p)
                normalized_paths.append(p.replace('/', '\\'))
                normalized_paths.append(p.replace('\\', '/'))
            
            possible_paths = list(set(normalized_paths))  # Remove duplicates
            
            content = None
            for path in possible_paths:
                if os.path.isfile(path):
                    try:
                        with open(path, 'r', encoding='utf-8') as f:
                            lines = f.readlines()
                        
                        # Extract code between start and end lines
                        line_start = max(0, start_line - 1)  # Convert 1-based to 0-based
                        line_end = min(len(lines), end_line)
                        
                        if line_start < len(lines) and line_start <= line_end:
                            content = ''.join(lines[line_start:line_end])
                            break
                    except Exception as e:
                        print(f"Error reading {path}: {e}")
            
            # Update the AST node with code
            if content:
                update_query = """
                MATCH (ast)
                WHERE elementId(ast) = $ast_id
                SET ast.code = $code
                """
                
                connector.run_query(update_query, {"ast_id": ast_id, "code": content})
                updated_count += 1
                
                if updated_count % 100 == 0:
                    print(f"Updated {updated_count} nodes so far...")
        
        print(f"Updated {updated_count} AST nodes with code property")
        return updated_count > 0
    
    except Exception as e:
        print(f"Error updating AST nodes: {e}")
        import traceback
        traceback.print_exc()
        return False

async def generate_ai_summaries(repo_info: dict) -> bool:
    """Generate AI summaries for AST nodes with code property."""
    try:
        # Import necessary modules
        from skwaq.core.openai_client import get_openai_client
        from skwaq.db.neo4j_connector import get_connector
        from skwaq.ingestion.summarizers.llm_summarizer import LLMSummarizer
        
        # Get the OpenAI client
        openai_client = get_openai_client(async_mode=True)
        
        # Test the connection
        test_prompt = "Return only the word 'OK' if you can see this message."
        response = await openai_client.get_completion(test_prompt, temperature=0.0)
        
        if "OK" not in response:
            print(f"Error: OpenAI API connection test failed. Response: {response}")
            return False
        
        print("OpenAI connection test successful!")
        
        # Use repository information directly from repo_info
        repo_path = repo_info['path']
        repo_node_id = repo_info['node_id']
        
        # Get AST nodes with code property but no summary
        connector = get_connector()
        ast_query = """
        MATCH (ast)
        WHERE (ast:Function OR ast:Class OR ast:Method)
            AND ast.code IS NOT NULL
            AND NOT (ast)<-[:DESCRIBES]-(:CodeSummary)
        RETURN elementId(ast) as ast_id, 
               ast.name as name,
               ast.code as code,
               labels(ast)[0] as node_type
        LIMIT 20  // Limit to 20 for initial testing
        """
        
        ast_results = connector.run_query(ast_query)
        print(f"Found {len(ast_results)} AST nodes to summarize")
        
        if not ast_results:
            print("No AST nodes with code property found. Please run the update_ast_nodes_with_code function first.")
            return False
        
        # Initialize the summarizer
        summarizer = LLMSummarizer()
        summarizer.configure(
            model_client=openai_client,
            max_parallel=3,
            context_token_limit=20000
        )
        
        # Process each AST node
        for node in ast_results:
            ast_id = node["ast_id"]
            name = node["name"]
            code = node["code"]
            node_type = node["node_type"]
            
            if not code:
                print(f"Skipping {name} - no code content")
                continue
            
            print(f"Generating summary for {node_type} {name}...")
            
            # Create the prompt
            prompt = summarizer._create_summary_prompt(
                file_name=name,
                content=code,
                language="python"  # Assume Python for simplicity
            )
            
            # Generate summary
            try:
                summary = await openai_client.get_completion(prompt, temperature=0.3)
                
                # Create summary node
                summary_node_id = connector.create_node(
                    "CodeSummary",
                    {
                        "summary": summary,
                        "file_name": name,
                        "language": "python",
                        "created_at": 0,
                        "generation_time": 0,
                    },
                )
                
                # Create relationship to AST node
                connector.create_relationship(
                    summary_node_id, ast_id, "DESCRIBES"
                )
                
                print(f"Created summary for {name}")
            
            except Exception as e:
                print(f"Error generating summary for {name}: {e}")
        
        # Verify summaries were created
        summary_query = """
        MATCH (s:CodeSummary)
        RETURN count(s) as count
        """
        
        summary_count = connector.run_query(summary_query)[0]["count"]
        print(f"Total CodeSummary nodes: {summary_count}")
        
        return True
    
    except Exception as e:
        print(f"Error generating AI summaries: {e}")
        import traceback
        traceback.print_exc()
        return False

async def visualize_investigation(investigation_id: str) -> bool:
    """Create a visualization for the investigation with AI summaries."""
    try:
        output_path = f"investigation-{investigation_id}-with-summaries.html"
        
        subprocess.run([
            "python", "-m", "skwaq", "investigations", "visualize",
            investigation_id,
            "--format", "html",
            "--output", output_path,
            "--include-files",
            "--max-nodes", "500"
        ], check=True)
        
        print(f"Visualization saved to: {output_path}")
        return True
    
    except Exception as e:
        print(f"Error creating visualization: {e}")
        return False

if __name__ == "__main__":
    asyncio.run(main())
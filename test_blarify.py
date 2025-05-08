#!/usr/bin/env python3
"""Script to test Blarify parser."""

import asyncio
import os
import sys
import time
from typing import Dict, Any

from skwaq.db.neo4j_connector import get_connector
from skwaq.db.schema import RelationshipTypes
from skwaq.ingestion.parsers import register_parsers, get_parser
from skwaq.ingestion.filesystem import CodebaseFileSystem, FilesystemGraphBuilder
from skwaq.ingestion.ast_mapper import ASTFileMapper
from skwaq.utils.logging import get_logger
from skwaq.core.openai_client import OpenAIClient

logger = get_logger(__name__)

async def test_blarify_parser(codebase_path: str) -> Dict[str, Any]:
    """Test the Blarify parser on a local codebase.
    
    Args:
        codebase_path: Path to the codebase to parse
        
    Returns:
        Dictionary with parsing results and statistics
    """
    logger.info(f"Testing Blarify parser on {codebase_path}")
    
    # Create a unique ingestion ID
    ingestion_id = f"test-blarify-{int(time.time())}"
    
    # Create Neo4j connector
    connector = get_connector()
    
    # Initialize parsers
    register_parsers()
    
    # Get the Blarify parser
    parser = get_parser("blarify")
    if not parser:
        logger.error("Blarify parser not found")
        return {"success": False, "error": "Blarify parser not found"}
    
    # Create repository node
    repo_metadata = {
        "name": "TestBlarify",
        "description": "Test repository for Blarify parser",
        "url": None,
        "language": "python",
        "size": 0,
        "ingestion_start_time": time.time(),
    }
    
    query = """
    CREATE (r:Repository {
        name: $name,
        description: $description,
        url: $url,
        ingestion_id: $ingestion_id,
        language: $language,
        size: $size,
        ingestion_start_time: $start_time
    })
    RETURN id(r) as repo_id
    """
    
    repo_result = connector.run_query(
        query,
        {
            "name": repo_metadata["name"],
            "description": repo_metadata["description"],
            "url": repo_metadata["url"],
            "ingestion_id": ingestion_id,
            "language": repo_metadata["language"],
            "size": repo_metadata["size"],
            "start_time": repo_metadata["ingestion_start_time"],
        },
    )
    
    if not repo_result:
        logger.error("Failed to create repository node")
        return {"success": False, "error": "Failed to create repository node"}
    
    repo_node_id = repo_result[0]["repo_id"]
    logger.info(f"Created repository node with ID {repo_node_id}")
    
    # Create filesystem
    fs = CodebaseFileSystem(codebase_path)
    
    # Count files
    files = fs.get_all_files()
    logger.info(f"Found {len(files)} files in codebase")
    
    # Create filesystem graph
    fs_graph_builder = FilesystemGraphBuilder(connector)
    file_nodes = await fs_graph_builder.build_graph(repo_node_id, fs)
    logger.info(f"Created filesystem graph with {len(file_nodes)} file nodes")
    
    # Parse the codebase
    logger.info("Parsing codebase with Blarify")
    try:
        parse_result = await parser.parse(codebase_path)
        logger.info(f"Parsing result: {parse_result}")
    except Exception as e:
        logger.error(f"Error parsing codebase: {str(e)}", exc_info=True)
        return {"success": False, "error": f"Error parsing codebase: {str(e)}"}
    
    # Map AST nodes to filesystem
    logger.info("Mapping AST nodes to files")
    ast_mapper = ASTFileMapper(connector)
    mapping_result = await ast_mapper.map_ast_to_files(repo_node_id, file_nodes)
    logger.info(f"Mapping result: {mapping_result}")
    
    # Check for AST nodes
    ast_query = """
    MATCH (n) 
    WHERE (n:Function OR n:Method OR n:Class)
    RETURN count(n) as ast_count
    """
    
    ast_result = connector.run_query(ast_query)
    ast_count = ast_result[0]["ast_count"] if ast_result else 0
    logger.info(f"Found {ast_count} AST nodes in database")
    
    # Check for AST nodes that have been mapped to files
    mapped_query = """
    MATCH (n)-[r:PART_OF]->(f:File)
    WHERE (n:Function OR n:Method OR n:Class)
    RETURN count(n) as mapped_count
    """
    
    mapped_result = connector.run_query(mapped_query)
    mapped_count = mapped_result[0]["mapped_count"] if mapped_result else 0
    logger.info(f"Found {mapped_count} AST nodes mapped to files")
    
    # Debug: Check what nodes were actually created by the parser
    debug_query = """
    MATCH (n)
    WHERE elementId(n) IS NOT NULL
    RETURN DISTINCT labels(n) as node_labels, count(n) as count
    """
    
    debug_result = connector.run_query(debug_query)
    logger.info("Nodes created by the parser:")
    for record in debug_result:
        logger.info(f"Labels: {record['node_labels']}, Count: {record['count']}")
    
    # Look at some nodes we expect to be AST nodes
    sample_query = """
    MATCH (n)
    WHERE 'Node' in labels(n) OR 'Class' in labels(n) OR 'Function' in labels(n) 
       OR 'Method' in labels(n) OR 'File' in labels(n) OR n.type in ['class', 'function', 'method']
    RETURN n, labels(n) as labels LIMIT 5
    """
    
    sample_result = connector.run_query(sample_query)
    logger.info("Sample nodes created by the parser:")
    for i, record in enumerate(sample_result):
        logger.info(f"Node {i+1}: {record['n']}")
    
    # If we have LLM client, test summarization
    try:
        from skwaq.core.openai_client import get_openai_client
        from skwaq.ingestion.summarizers import register_summarizers, get_summarizer
        
        # Initialize summarizers
        register_summarizers()
        
        # Create OpenAI client
        model_client = get_openai_client()
        
        # Get AST nodes for summarization
        # Simply get the AST nodes that have been mapped
        ast_query = """
        MATCH (n)-[:PART_OF]->(f:File)
        WHERE (n:Function OR n:Method OR n:Class) 
          AND f.path IS NOT NULL
        RETURN elementId(n) as node_id, elementId(f) as file_id, 
               f.path as path, 
               COALESCE(f.language, 'python') as language, 
               COALESCE(n.name, 'Unknown') as name
        LIMIT 5
        """
        
        ast_nodes = connector.run_query(ast_query, {"repo_id": repo_node_id})
        logger.info(f"Found {len(ast_nodes)} AST nodes for summarization")
        
        # Get the LLM summarizer
        summarizer = get_summarizer("llm")
        if summarizer:
            logger.info("Testing LLM summarization")
            
            # Configure the summarizer
            summarizer.configure(
                model_client=model_client,
                max_parallel=3,
                context_token_limit=20000,
            )
            
            # Summarize AST nodes
            if ast_nodes:
                # We need to create our own summarization logic since the standard summarizer
                # is designed for files, not AST nodes
                for node in ast_nodes:
                    node_id = node["node_id"]
                    file_id = node["file_id"]
                    name = node["name"]
                    path = node["path"]
                    language = node["language"]
                    
                    logger.info(f"Summarizing {language} {name} in {path}")
                    
                    # Get the file content
                    full_paths = [p for p in fs.get_all_files() if p.endswith(path)]
                    if not full_paths:
                        logger.warning(f"Could not find file {path}")
                        continue
                        
                    full_path = full_paths[0]
                    content = fs.read_file(full_path)
                    
                    if not content:
                        logger.warning(f"Could not read file content for {path}")
                        continue
                    
                    # Create a prompt for summarizing the AST node
                    prompt = f"""
                    Analyze the following {language} code and provide a summary for the {name} object:
                    
                    File: {path}
                    {name} definition:
                    
                    ```{language}
                    {content}
                    ```
                    
                    Please provide a concise summary of what this {name} does, focusing on:
                    1. Purpose and functionality
                    2. Key features or behaviors
                    3. Important methods or properties (if applicable)
                    4. Relationships with other components
                    5. Potential security considerations
                    
                    Summary:
                    """
                    
                    try:
                        # Generate summary
                        summary = await model_client.get_completion(prompt, temperature=0.3)
                        
                        # Create summary node
                        summary_node_id = connector.create_node(
                            "CodeSummary",
                            {
                                "summary": summary,
                                "name": name,
                                "language": language,
                                "created_at": time.time(),
                            },
                        )
                        
                        # Create relationship from AST node to summary
                        connector.create_relationship(
                            node_id, summary_node_id, RelationshipTypes.HAS_SUMMARY
                        )
                        
                        logger.info(f"Created summary for {name}: {summary[:100]}..." if len(summary) > 100 else summary)
                    except Exception as e:
                        logger.error(f"Error summarizing {name}: {str(e)}")
                
                summary_result = {
                    "stats": {
                        "nodes_processed": len(ast_nodes),
                        "errors": 0,
                    },
                    "files_processed": len(ast_nodes)
                }
            else:
                summary_result = {
                    "stats": {"files_processed": 0, "errors": 0, "total_tokens": 0, "total_time": 0.0},
                    "files_processed": 0,
                    "errors": []
                }
            
            logger.info(f"Summarization result: {summary_result}")
        else:
            logger.warning("LLM summarizer not found")
    
    except ImportError as e:
        logger.warning(f"Could not test summarization: {e}")
    
    return {
        "success": True,
        "ingestion_id": ingestion_id,
        "repo_node_id": repo_node_id,
        "files_processed": len(files),
        "file_nodes": len(file_nodes),
        "ast_nodes": ast_count,
        "mapped_ast_nodes": mapped_count,
        "parse_result": parse_result,
        "mapping_result": mapping_result,
    }

async def main():
    """Main function."""
    if len(sys.argv) < 2:
        print("Usage: python test_blarify.py <codebase_path>")
        sys.exit(1)
    
    codebase_path = sys.argv[1]
    
    if not os.path.exists(codebase_path) or not os.path.isdir(codebase_path):
        print(f"Invalid codebase path: {codebase_path}")
        sys.exit(1)
    
    result = await test_blarify_parser(codebase_path)
    
    if result["success"]:
        print("\nTest successful:")
        print(f"- Ingestion ID: {result['ingestion_id']}")
        print(f"- Repository node ID: {result['repo_node_id']}")
        print(f"- Files processed: {result['files_processed']}")
        print(f"- File nodes created: {result['file_nodes']}")
        print(f"- AST nodes detected: {result['ast_nodes']}")
        print(f"- AST nodes mapped to files: {result.get('mapped_ast_nodes', 0)}")
        
        if result['ast_nodes'] == 0:
            print("\nWARNING: No AST nodes were detected. This may indicate an issue with the Blarify parser.")
            print("Check if Docker is running and properly configured for macOS.")
        elif result.get('mapped_ast_nodes', 0) == 0:
            print("\nWARNING: AST nodes were created but none were mapped to files.")
            print("Check the relationship types and properties in the AST mapper.")
    else:
        print(f"\nTest failed: {result.get('error', 'Unknown error')}")

if __name__ == "__main__":
    asyncio.run(main())
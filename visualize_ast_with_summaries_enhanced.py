#!/usr/bin/env python
"""
Enhanced AST Visualization with Code Summaries

This script creates an interactive visualization of AST nodes with
AI-generated code summaries for better code understanding.
"""

import argparse
import asyncio
import os
import sys
from pathlib import Path

# Add the project root to the Python path
sys.path.append(str(Path(__file__).parent))

from skwaq.db.neo4j_connector import get_connector
from skwaq.utils.logging import get_logger
from skwaq.visualization.ast_visualizer import ASTVisualizer

logger = get_logger(__name__)


async def main():
    """Create an enhanced AST visualization with code summaries."""
    parser = argparse.ArgumentParser(
        description="Create an interactive visualization of AST nodes with code summaries"
    )
    parser.add_argument(
        "--investigation",
        "-i",
        help="Investigation ID to visualize AST nodes for",
    )
    parser.add_argument(
        "--repo",
        "-r",
        help="Repository ID to visualize AST nodes for (alternative to investigation)",
    )
    parser.add_argument(
        "--output",
        "-o",
        help="Path to save the visualization file (default: auto-generated based on source ID)",
    )
    parser.add_argument(
        "--max-nodes",
        "-m",
        type=int,
        default=1000,
        help="Maximum number of nodes to include in the visualization (default: 1000)",
    )
    parser.add_argument(
        "--no-files",
        action="store_true",
        help="Exclude file nodes from the visualization",
    )
    parser.add_argument(
        "--no-summaries",
        action="store_true",
        help="Exclude code summary nodes from the visualization",
    )
    parser.add_argument(
        "--title",
        "-t",
        default="AST Visualization with Code Summaries",
        help="Title for the visualization",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Check for AST nodes and summaries in the database without creating visualization",
    )
    parser.add_argument(
        "--open",
        action="store_true",
        help="Open the visualization in a web browser after creation",
    )

    args = parser.parse_args()
    
    try:
        # Initialize the AST visualizer
        visualizer = ASTVisualizer()
        
        # Check if we need to check for AST nodes and summaries
        if args.check:
            id_to_check = args.investigation or args.repo
            if id_to_check:
                logger.info(f"Checking AST nodes and summaries for ID: {id_to_check}")
                counts = visualizer.check_ast_summaries(id_to_check)
                print(f"\nAST Node Summary for {'investigation' if args.investigation else 'repository'} {id_to_check}:")
                print(f"AST Nodes: {counts['ast_count']}")
                print(f"AST Nodes with code: {counts['ast_with_code_count']}")
                print(f"Summary count: {counts['summary_count']}")
                print(f"AST nodes with summary: {counts['ast_with_summary_count']}")
            else:
                logger.info("Checking AST nodes and summaries in the entire database")
                counts = visualizer.check_ast_summaries()
                print("\nAST Node Summary for entire database:")
                print(f"AST Nodes: {counts['ast_count']}")
                print(f"AST Nodes with code: {counts['ast_with_code_count']}")
                print(f"Summary count: {counts['summary_count']}")
                print(f"AST nodes with summary: {counts['ast_with_summary_count']}")
            return
        
        # Create the AST visualization
        if not args.investigation and not args.repo:
            parser.error("Either --investigation or --repo must be specified")
        
        logger.info("Creating enhanced AST visualization with code summaries")
        output_path = visualizer.visualize_ast(
            investigation_id=args.investigation,
            repo_id=args.repo,
            include_files=not args.no_files,
            include_summaries=not args.no_summaries,
            max_nodes=args.max_nodes,
            output_path=args.output,
            title=args.title,
        )
        
        print(f"\nVisualization created successfully: {output_path}")
        
        # Open in browser if requested
        if args.open:
            try:
                import webbrowser
                logger.info(f"Opening visualization in web browser: {output_path}")
                webbrowser.open(f"file://{os.path.abspath(output_path)}")
            except Exception as e:
                logger.error(f"Failed to open visualization in browser: {str(e)}")
    
    except Exception as e:
        logger.error(f"Error creating AST visualization: {str(e)}")
        import traceback
        traceback.print_exc()
        return 1
    
    return 0


if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code)
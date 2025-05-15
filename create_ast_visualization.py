#!/usr/bin/env python3
"""
Create interactive AST visualization with filtering and search capabilities.

This script generates a comprehensive visualization of a codebase's Abstract Syntax Tree (AST)
with file relationships and AI-generated code summaries.

Usage:
    python create_ast_visualization.py <repo_id_or_investigation_id> [--type <repo|investigation>] [--output <path>] [--no-summaries] [--open]

Options:
    --type TYPE             Specify the input ID type: 'repo' or 'investigation' (default: auto-detect)
    --output PATH           Path to save the visualization (default: ast_visualization.html)
    --no-summaries          Exclude AI-generated code summaries from the visualization
    --open                  Open the visualization in a browser after creation
"""

import argparse
import os
import sys
import webbrowser
from typing import Optional

from skwaq.db.neo4j_connector import get_connector
from skwaq.visualization.ast_visualizer import ASTVisualizer
from skwaq.utils.logging import get_logger

logger = get_logger(__name__)

def main():
    """Generate an interactive AST visualization."""
    parser = argparse.ArgumentParser(
        description="Create interactive AST visualization with filtering and search capabilities."
    )
    parser.add_argument(
        "id", 
        help="Repository ID or Investigation ID to visualize"
    )
    parser.add_argument(
        "--type", 
        choices=["repo", "investigation"],
        help="Specify the input ID type: 'repo' or 'investigation' (default: auto-detect)"
    )
    parser.add_argument(
        "--output", 
        help="Path to save the visualization (default: ast_visualization.html)"
    )
    parser.add_argument(
        "--no-summaries", 
        action="store_true",
        help="Exclude AI-generated code summaries from the visualization"
    )
    parser.add_argument(
        "--open", 
        action="store_true",
        help="Open the visualization in a browser after creation"
    )
    
    args = parser.parse_args()
    
    # Determine ID type if not specified
    id_type = args.type
    input_id = args.id
    
    if not id_type:
        # Auto-detect ID type based on format
        if input_id.startswith("inv-"):
            id_type = "investigation"
            print(f"Auto-detected ID type: investigation (ID: {input_id})")
        else:
            id_type = "repo"
            print(f"Auto-detected ID type: repository (ID: {input_id})")
    
    # Determine output path
    output_path = args.output
    if not output_path:
        if id_type == "investigation":
            output_path = f"investigation-{input_id}-ast-visualization.html"
        else:
            output_path = f"repository-{input_id}-ast-visualization.html"
    
    # Create visualizer
    visualizer = ASTVisualizer()
    
    print(f"Creating AST visualization for {id_type} {input_id}...")
    print(f"Include summaries: {not args.no_summaries}")
    
    try:
        # Generate visualization
        if id_type == "investigation":
            result_path = visualizer.visualize_ast(
                investigation_id=input_id,
                include_files=True,
                include_summaries=not args.no_summaries,
                output_path=output_path,
                title=f"AST Visualization for Investigation: {input_id}"
            )
        else:
            result_path = visualizer.visualize_ast(
                repo_id=input_id,
                include_files=True,
                include_summaries=not args.no_summaries,
                output_path=output_path,
                title=f"AST Visualization for Repository: {input_id}"
            )
        
        print(f"Visualization created: {result_path}")
        
        # Show AST summary statistics
        counts = visualizer.check_ast_summaries(input_id if id_type == "investigation" else None)
        print(f"AST Nodes: {counts['ast_count']}")
        print(f"AST Nodes with code: {counts['ast_with_code_count']}")
        print(f"AI summaries: {counts['summary_count']}")
        print(f"AST nodes with summaries: {counts['ast_with_summary_count']}")
        
        # Open in browser if requested
        if args.open:
            try:
                webbrowser.open(f"file://{os.path.abspath(result_path)}")
                print(f"Visualization opened in browser")
            except Exception as e:
                print(f"Could not open browser: {str(e)}")
                print(f"Please open the file manually: {os.path.abspath(result_path)}")
        
        return 0
    except Exception as e:
        print(f"Error creating visualization: {str(e)}")
        import traceback
        traceback.print_exc()
        return 1

if __name__ == "__main__":
    sys.exit(main())
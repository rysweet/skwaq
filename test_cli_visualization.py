#!/usr/bin/env python3
"""Test the CLI visualization functionality for investigations."""

import argparse
import os
import sys
from typing import Any, Dict

from skwaq.cli.commands.workflow_commands import InvestigationCommandHandler
from skwaq.cli.ui.console import console


def main():
    """Run the CLI visualization test."""
    # Parse arguments
    parser = argparse.ArgumentParser(description="Test CLI visualization for investigations")
    parser.add_argument("investigation_id", help="Investigation ID to visualize")
    parser.add_argument("--output", "-o", help="Output file path", default=None)
    parser.add_argument(
        "--format", "-f", 
        help="Visualization format", 
        default="html", 
        choices=["html", "json", "svg"]
    )
    args = parser.parse_args()

    # Create a namespace with the arguments needed for the visualization handler
    class Args:
        """Arguments for the visualization handler."""
        id = args.investigation_id
        format = args.format
        output = args.output
        include_findings = True
        include_vulnerabilities = True
        include_files = True
        include_sources_sinks = True
        max_nodes = 1000

    # Create the investigation command handler
    handler = InvestigationCommandHandler(Args())
    
    # Set the investigation_command attribute manually
    handler.args.investigation_command = "visualize"
    
    console.print(f"[cyan]Visualizing investigation {args.investigation_id}...[/cyan]")
    
    # Run the visualization handler
    import asyncio
    result = asyncio.run(handler._handle_visualize())
    
    if result == 0:
        console.print("[green]Visualization completed successfully.[/green]")
    else:
        console.print("[red]Visualization failed.[/red]")
    
    return result


if __name__ == "__main__":
    sys.exit(main())
"""Command line interface for the Skwaq vulnerability assessment copilot.

This module provides the main entry point for the CLI application.
"""

import argparse
import sys
from pathlib import Path
from typing import Dict, List, Optional

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from skwaq.utils.config import get_config
from skwaq.utils.logging import get_logger, setup_logging

# Set up logging
logger = setup_logging(module_name="skwaq.cli")
console = Console()


def print_banner() -> None:
    """Print the Skwaq banner."""
    banner = r"""
    ███████╗██╗  ██╗██╗    ██╗ █████╗  ██████╗ 
    ██╔════╝██║ ██╔╝██║    ██║██╔══██╗██╔═══██╗
    ███████╗█████╔╝ ██║ █╗ ██║███████║██║   ██║
    ╚════██║██╔═██╗ ██║███╗██║██╔══██║██║▄▄ ██║
    ███████║██║  ██╗╚███╔███╔╝██║  ██║╚██████╔╝
    ╚══════╝╚═╝  ╚═╝ ╚══╝╚══╝ ╚═╝  ╚═╝ ╚══▀▀═╝ 
                            Vulnerability Assessment Copilot
    """
    console.print(Panel(banner, border_style="blue", title="[bold cyan]Skwaq[/bold cyan]"))
    console.print("[dim]'Raven' - A clever digital assistant for uncovering security vulnerabilities[/dim]")
    console.print()


def cmd_version(args: argparse.Namespace) -> None:
    """Display version information."""
    from skwaq import __version__
    
    console.print(f"[bold]Skwaq[/bold] version: [cyan]{__version__}[/cyan]")


def cmd_config(args: argparse.Namespace) -> None:
    """Manage configuration settings."""
    config = get_config()
    
    if args.show:
        # Create a table to display configuration
        table = Table(title="Skwaq Configuration")
        table.add_column("Section", style="cyan")
        table.add_column("Setting", style="green")
        table.add_column("Value", style="yellow")
        
        # Add Neo4j configuration
        neo4j_config = config.neo4j
        for key, value in neo4j_config.items():
            # Mask password
            if key == "password":
                value = "********"
            table.add_row("neo4j", key, str(value))
        
        # Add OpenAI configuration
        openai_config = config.openai
        for key, value in openai_config.items():
            # Mask API key
            if key == "api_key":
                value = "********"
            table.add_row("openai", key, str(value))
        
        # Add Telemetry configuration
        telemetry_config = config.telemetry
        for key, value in telemetry_config.items():
            table.add_row("telemetry", key, str(value))
        
        console.print(table)
    
    elif args.edit:
        # Not implemented yet
        console.print("[yellow]Configuration editing not implemented yet.[/yellow]")
        console.print("You can manually edit the config files in the [bold]config/[/bold] directory.")


def cmd_init(args: argparse.Namespace) -> None:
    """Initialize the Skwaq environment."""
    console.print("[bold]Initializing Skwaq environment...[/bold]")
    
    # Check Neo4j connection
    console.print("[cyan]Checking Neo4j database connection...[/cyan]")
    from skwaq.db.neo4j_connector import get_connector
    try:
        connector = get_connector()
        if connector.connect():
            server_info = connector.get_server_info()
            if server_info:
                console.print(f"[green]✓[/green] Connected to Neo4j {server_info.get('version', 'Unknown')}")
            else:
                console.print(f"[green]✓[/green] Connected to Neo4j database")
        else:
            console.print("[red]✗[/red] Failed to connect to Neo4j database. Please check your configuration.")
    except Exception as e:
        console.print(f"[red]✗[/red] Error connecting to Neo4j: {e}")
    
    # Check OpenAI API connection
    console.print("[cyan]Checking OpenAI API connection...[/cyan]")
    from skwaq.core.openai_client import get_openai_client
    try:
        client = get_openai_client()
        # Try a simple API call
        response = client.get_chat_completion(
            messages=[
                {"role": "system", "content": "You are a helpful assistant."},
                {"role": "user", "content": "Hello"}
            ],
            max_tokens=5
        )
        console.print("[green]✓[/green] Successfully connected to OpenAI API")
    except Exception as e:
        console.print(f"[red]✗[/red] Error connecting to OpenAI API: {e}")
    
    console.print("\n[bold green]Initialization complete![/bold green]")


def cmd_ingest(args: argparse.Namespace) -> None:
    """Ingest a repository or knowledge source."""
    source_path = Path(args.source)
    if not source_path.exists():
        console.print(f"[red]Error:[/red] Source '{args.source}' does not exist.")
        return
    
    console.print(f"[bold]Ingesting from [cyan]{args.source}[/cyan]...[/bold]")
    console.print("[yellow]Repository ingestion not implemented yet.[/yellow]")


def cmd_query(args: argparse.Namespace) -> None:
    """Query the knowledge base and run the vulnerability assessment."""
    console.print(f"[bold]Running query: [cyan]{args.query}[/cyan][/bold]")
    console.print("[yellow]Query functionality not implemented yet.[/yellow]")


def create_parser() -> argparse.ArgumentParser:
    """Create the command-line argument parser."""
    parser = argparse.ArgumentParser(
        description="Skwaq - Vulnerability Assessment Copilot",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug logging"
    )
    
    subparsers = parser.add_subparsers(
        title="commands",
        dest="command",
        help="Command to run"
    )
    
    # Version command
    version_parser = subparsers.add_parser(
        "version",
        help="Display version information"
    )
    version_parser.set_defaults(func=cmd_version)
    
    # Config command
    config_parser = subparsers.add_parser(
        "config",
        help="Manage configuration settings"
    )
    config_parser.add_argument(
        "--show",
        action="store_true",
        help="Show current configuration"
    )
    config_parser.add_argument(
        "--edit",
        action="store_true",
        help="Edit configuration"
    )
    config_parser.set_defaults(func=cmd_config)
    
    # Init command
    init_parser = subparsers.add_parser(
        "init",
        help="Initialize the Skwaq environment"
    )
    init_parser.set_defaults(func=cmd_init)
    
    # Ingest command
    ingest_parser = subparsers.add_parser(
        "ingest",
        help="Ingest a repository or knowledge source"
    )
    ingest_parser.add_argument(
        "source",
        help="Path to the repository or knowledge source to ingest"
    )
    ingest_parser.add_argument(
        "--type",
        choices=["repo", "cve", "kb"],
        default="repo",
        help="Type of source to ingest (default: repo)"
    )
    ingest_parser.set_defaults(func=cmd_ingest)
    
    # Query command
    query_parser = subparsers.add_parser(
        "query",
        help="Query the knowledge base"
    )
    query_parser.add_argument(
        "query",
        help="Query to run"
    )
    query_parser.add_argument(
        "--interactive",
        action="store_true",
        help="Run in interactive mode"
    )
    query_parser.set_defaults(func=cmd_query)
    
    return parser


def main() -> int:
    """Main entry point for the CLI application."""
    parser = create_parser()
    args = parser.parse_args()
    
    # Configure logging level
    if args.debug:
        logger.setLevel("DEBUG")
        logger.debug("Debug logging enabled")
    
    # Print banner
    print_banner()
    
    # Run the command
    if hasattr(args, "func"):
        args.func(args)
    else:
        parser.print_help()
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
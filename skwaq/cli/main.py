"""Command line interface for the Skwaq vulnerability assessment copilot.

This module provides the main entry point for the CLI application.
"""

import argparse
import sys
from skwaq.ingestion import ingest_repository, ingest_knowledge_source
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
    config = get_config()
    if args.show:
        console.print("[bold]Current Configuration:[/bold]")
        console.print(config)
    elif args.edit:
        console.print("[yellow]Configuration editing not implemented yet.[/yellow]")


def cmd_init(args: argparse.Namespace) -> None:
    console.print("[bold]Initializing Skwaq environment...[/bold]")
    from skwaq.db.neo4j_connector import get_connector
    try:
        connector = get_connector()
        console.print("[green]Neo4j connection verified.[/green]")
    except Exception as e:
        console.print(f"[red]Neo4j connection failed: {e}[/red]")
        return

    from skwaq.core.openai_client import get_openai_client
    try:
        client = get_openai_client()
        console.print("[green]OpenAI API connection verified.[/green]")
    except Exception as e:
        console.print(f"[red]OpenAI API connection failed: {e}[/red]")
        return

    console.print("\n[bold green]Initialization complete![/bold green]")


def cmd_ingest(args: argparse.Namespace) -> None:
    source_path = Path(args.source)
    if not source_path.exists():
        console.print(f"[red]Error: {source_path} does not exist.[/red]")
        return

    if args.type == "repo":
        ingest_repository(str(source_path))
    elif args.type == "kb":
        ingest_knowledge_source(str(source_path))
    elif args.type == "cve":
        from skwaq.ingestion import ingest_cve_source
        ingest_cve_source(str(source_path))
    else:
        console.print("[red]Unknown ingestion type.[/red]")
        return

    console.print("[bold green]Ingestion completed.[/bold green]")


def cmd_query(args: argparse.Namespace) -> None:
    console.print(f"[bold]Running query: [cyan]{args.query}[/cyan][/bold]")
    try:
        console.print("[yellow]Query functionality not yet implemented.[/yellow]")
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        return 1
    return 0


def create_parser() -> argparse.ArgumentParser:
    import argparse
    parser = argparse.ArgumentParser(
        description="Skwaq - Vulnerability Assessment Copilot",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    subparsers = parser.add_subparsers(title="commands", dest="command", help="Command to run")

    version_parser = subparsers.add_parser("version", help="Display version information")
    version_parser.set_defaults(func=cmd_version)

    config_parser = subparsers.add_parser("config", help="Manage configuration settings")
    config_parser.add_argument("--show", action="store_true", help="Show current configuration")
    config_parser.add_argument("--edit", action="store_true", help="Edit configuration")
    config_parser.set_defaults(func=cmd_config)

    init_parser = subparsers.add_parser("init", help="Initialize the Skwaq environment")
    init_parser.set_defaults(func=cmd_init)

    ingest_parser = subparsers.add_parser("ingest", help="Ingest a repository or knowledge source")
    ingest_parser.add_argument("source", help="Path to the repository or knowledge source to ingest")
    ingest_parser.add_argument("--type", choices=["repo", "cve", "kb"], default="repo",
                               help="Type of source to ingest")
    ingest_parser.set_defaults(func=cmd_ingest)

    query_parser = subparsers.add_parser("query", help="Run a query in the knowledge base")
    query_parser.add_argument("query", help="The query string")
    query_parser.set_defaults(func=cmd_query)

    return parser


def main() -> int:
    parser = create_parser()
    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        return 0
    return args.func(args) or 0


if __name__ == "__main__":
    sys.exit(main())
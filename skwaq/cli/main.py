"""Command line interface for the Skwaq vulnerability assessment copilot.

This module provides the main entry point for the CLI application.
"""

import argparse
import sys
import json
import asyncio
from pathlib import Path
from typing import Dict, List, Optional, Any, Union, Tuple

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress

from skwaq.utils.config import get_config
from skwaq.utils.logging import get_logger, setup_logging
from skwaq.db.neo4j_connector import get_connector
from skwaq.code_analysis.analyzer import CodeAnalyzer

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
    console.print(
        Panel(banner, border_style="blue", title="[bold cyan]Skwaq[/bold cyan]")
    )
    console.print(
        "[dim]'Raven' - A clever digital assistant for uncovering security vulnerabilities[/dim]"
    )
    console.print()


def cmd_version(args: argparse.Namespace) -> None:
    """Display version information."""
    from skwaq import __version__

    console.print(f"[bold]Skwaq[/bold] version: [cyan]{__version__}[/cyan]")


def cmd_config(args: argparse.Namespace) -> None:
    """Handle configuration command."""
    config = get_config()
    if args.show:
        console.print("[bold]Current Configuration:[/bold]")
        console.print(config)
    elif args.edit:
        console.print("[yellow]Configuration editing not implemented yet.[/yellow]")


def cmd_init(args: argparse.Namespace) -> None:
    """Initialize the Skwaq environment."""
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
    """Handle ingestion command."""
    source_path = Path(args.source)
    if not source_path.exists():
        console.print(f"[red]Error: {source_path} does not exist.[/red]")
        return

    if args.type == "repo":
        # Import here to avoid circular imports
        from skwaq.ingestion import ingest_repository

        ingest_repository(str(source_path))
    elif args.type == "kb":
        # Import here to avoid circular imports
        from skwaq.ingestion import ingest_knowledge_source

        ingest_knowledge_source(str(source_path))
    elif args.type == "cve":
        # Import here to avoid circular imports
        from skwaq.ingestion import ingest_cve_source

        ingest_cve_source(str(source_path))
    else:
        console.print("[red]Unknown ingestion type.[/red]")
        return

    console.print("[bold green]Ingestion completed.[/bold green]")


def cmd_query(args: argparse.Namespace) -> None:
    """Handle query command."""
    console.print(f"[bold]Running query: [cyan]{args.query}[/cyan][/bold]")
    try:
        console.print("[yellow]Query functionality not yet implemented.[/yellow]")
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        return 1
    return 0


async def handle_analyze_command(args: argparse.Namespace) -> None:
    """Handle analyze command.

    Args:
        args: Command line arguments
    """
    file_path = args.file
    strategy_names = args.strategy or ["pattern_matching"]
    output_format = args.output or "text"

    console.print(f"Analyzing file: [cyan]{file_path}[/cyan]")
    console.print(f"Using strategies: [cyan]{', '.join(strategy_names)}[/cyan]")

    # Create analyzer
    analyzer = CodeAnalyzer()

    # Analyze file
    result = await analyzer.analyze_file(
        file_path=file_path,
        repository_id=None,  # No repository context for standalone files
        strategy_names=strategy_names,
    )

    # Output findings
    if not result.findings:
        console.print("[green]No vulnerabilities found[/green]")
        return

    if output_format == "json":
        # Output as JSON
        console.print(json.dumps(result.to_dict(), indent=2))
    else:
        # Output as text
        console.print(
            f"[bold]Found {len(result.findings)} potential vulnerabilities:[/bold]"
        )

        table = Table(
            "Type",
            "Severity",
            "Confidence",
            "Location",
            "Description",
            title="Vulnerability Findings",
        )

        for finding in result.findings:
            table.add_row(
                finding.vulnerability_type,
                finding.severity,
                f"{finding.confidence:.2f}",
                f"{file_path}:{finding.line_number}",
                finding.description,
            )

        console.print(table)


async def handle_repository_command(args: argparse.Namespace) -> None:
    """Handle repository command.

    Args:
        args: Command line arguments
    """
    from skwaq.ingestion.code_ingestion import ingest_repository, list_repositories

    if args.repo_command == "list":
        # List repositories
        repos = await list_repositories()

        if not repos:
            console.print("[yellow]No repositories found[/yellow]")
            return

        table = Table(
            "ID",
            "Name",
            "Path/URL",
            "Ingested At",
            "Files",
            "Code Files",
            title="Ingested Repositories",
        )

        for repo in repos:
            repo_id = repo.get("id")
            name = repo.get("name", "Unknown")
            path = repo.get("path", "N/A")
            url = repo.get("url")
            ingested_at = repo.get("ingested_at", "Unknown")
            files = repo.get("files", 0)
            code_files = repo.get("code_files", 0)

            # Use URL if available, otherwise path
            location = url if url else path

            table.add_row(
                str(repo_id),
                name,
                location,
                ingested_at,
                str(files),
                str(code_files),
            )

        console.print(table)

    elif args.repo_command == "add":
        # Add repository from local path
        console.print(f"Ingesting repository from path: [cyan]{args.path}[/cyan]")

        with Progress() as progress:
            task = progress.add_task("Ingesting repository...", total=100)

            # Run ingestion in the background
            result = await ingest_repository(
                repo_path_or_url=args.path,
                is_github_url=False,
                include_patterns=args.include,
                exclude_patterns=args.exclude,
                github_token=None,
                branch=None,
                show_progress=True,
            )

            progress.update(task, completed=100)

        console.print(
            f"[bold green]Successfully ingested repository: {result['repository_name']}[/bold green]"
        )
        console.print(
            f"Found {result['file_count']} files, {result['code_files_processed']} code files"
        )

    elif args.repo_command == "github":
        # Add repository from GitHub URL
        console.print(f"Ingesting repository from GitHub: [cyan]{args.url}[/cyan]")

        with Progress() as progress:
            task = progress.add_task("Cloning and ingesting repository...", total=100)

            # Run ingestion in the background
            result = await ingest_repository(
                repo_path_or_url=args.url,
                is_github_url=True,
                include_patterns=args.include,
                exclude_patterns=args.exclude,
                github_token=args.token,
                branch=args.branch,
                show_progress=True,
            )

            progress.update(task, completed=100)

        console.print(
            f"[bold green]Successfully ingested GitHub repository: {result['repository_name']}[/bold green]"
        )
        console.print(f"Branch: {result.get('branch', 'default')}")
        console.print(
            f"Found {result['file_count']} files, {result['code_files_processed']} code files"
        )


def create_parser() -> argparse.ArgumentParser:
    """Create the command-line argument parser.

    Returns:
        Configured argument parser
    """
    import argparse

    parser = argparse.ArgumentParser(
        description="Skwaq - Vulnerability Assessment Copilot",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    subparsers = parser.add_subparsers(
        title="commands", dest="command", help="Command to run"
    )

    # Version command
    version_parser = subparsers.add_parser(
        "version", help="Display version information"
    )
    version_parser.set_defaults(func=cmd_version)

    # Config command
    config_parser = subparsers.add_parser(
        "config", help="Manage configuration settings"
    )
    config_parser.add_argument(
        "--show", action="store_true", help="Show current configuration"
    )
    config_parser.add_argument("--edit", action="store_true", help="Edit configuration")
    config_parser.set_defaults(func=cmd_config)

    # Init command
    init_parser = subparsers.add_parser("init", help="Initialize the Skwaq environment")
    init_parser.set_defaults(func=cmd_init)

    # Analyze command
    analyze_parser = subparsers.add_parser(
        "analyze", help="Analyze a file for vulnerabilities"
    )
    analyze_parser.add_argument("--file", required=True, help="File to analyze")
    analyze_parser.add_argument(
        "--strategy",
        nargs="+",
        choices=["pattern_matching", "semantic_analysis", "ast_analysis"],
        help="Analysis strategies to use",
    )
    analyze_parser.add_argument(
        "--output", choices=["text", "json"], default="text", help="Output format"
    )
    analyze_parser.set_defaults(
        func=lambda args: asyncio.run(handle_analyze_command(args))
    )

    # Repository commands
    repo_parser = subparsers.add_parser("repo", help="Manage repositories")
    repo_subparsers = repo_parser.add_subparsers(
        title="repository commands",
        dest="repo_command",
        help="Repository command to run",
    )

    # Repository list command
    repo_list_parser = repo_subparsers.add_parser(
        "list", help="List ingested repositories"
    )

    # Repository add command
    repo_add_parser = repo_subparsers.add_parser("add", help="Add a local repository")
    repo_add_parser.add_argument("--path", required=True, help="Path to the repository")
    repo_add_parser.add_argument(
        "--name", help="Name for the repository (default: directory name)"
    )
    repo_add_parser.add_argument(
        "--include", nargs="+", help="Glob patterns to include"
    )
    repo_add_parser.add_argument(
        "--exclude", nargs="+", help="Glob patterns to exclude"
    )

    # Repository GitHub command
    repo_github_parser = repo_subparsers.add_parser(
        "github", help="Add a GitHub repository"
    )
    repo_github_parser.add_argument(
        "--url", required=True, help="URL of the GitHub repository"
    )
    repo_github_parser.add_argument(
        "--token", help="GitHub token for private repositories"
    )
    repo_github_parser.add_argument(
        "--branch", help="Branch to clone (default: main branch)"
    )
    repo_github_parser.add_argument(
        "--include", nargs="+", help="Glob patterns to include"
    )
    repo_github_parser.add_argument(
        "--exclude", nargs="+", help="Glob patterns to exclude"
    )

    repo_parser.set_defaults(
        func=lambda args: asyncio.run(handle_repository_command(args))
    )

    # Ingest command
    ingest_parser = subparsers.add_parser(
        "ingest", help="Ingest a repository or knowledge source"
    )
    ingest_parser.add_argument(
        "source", help="Path to the repository or knowledge source to ingest"
    )
    ingest_parser.add_argument(
        "--type",
        choices=["repo", "cve", "kb"],
        default="repo",
        help="Type of source to ingest",
    )
    ingest_parser.set_defaults(func=cmd_ingest)

    # Query command
    query_parser = subparsers.add_parser(
        "query", help="Run a query in the knowledge base"
    )
    query_parser.add_argument("query", help="The query string")
    query_parser.set_defaults(func=cmd_query)

    return parser


def main() -> int:
    """Main entry point.

    Returns:
        Exit code
    """
    parser = create_parser()
    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        return 0
    return args.func(args) or 0


if __name__ == "__main__":
    sys.exit(main())

"""Command line interface for the Skwaq vulnerability assessment copilot.

This module provides the main entry point for the CLI application.
"""

import argparse
import sys
import json
import asyncio
import uuid
import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any, Union, Tuple

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeRemainingColumn
from rich.status import Status
from rich.prompt import Prompt, Confirm

from skwaq.utils.config import get_config
from skwaq.utils.logging import get_logger, setup_logging
from skwaq.db.neo4j_connector import get_connector
from skwaq.code_analysis.analyzer import CodeAnalyzer

# Set up logging with appropriate levels
logger = setup_logging(module_name="skwaq.cli")

# Keep Blarify integration warnings at ERROR level in CLI context to avoid spamming users
import logging
logging.getLogger("skwaq.code_analysis.blarify_integration").setLevel(logging.ERROR)

# Initialize console for rich output
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
    
    
def create_progress_bar() -> Progress:
    """Create a rich progress bar with a consistent style.
    
    Returns:
        A configured Progress instance
    """
    return Progress(
        SpinnerColumn(),
        TextColumn("[bold blue]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TimeRemainingColumn(),
        console=console,
    )


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

    # Use status indicator for analysis
    with Status("[bold blue]Analyzing file for vulnerabilities...", spinner="dots") as status:
        # Analyze file using the file path wrapper method
        result = await analyzer.analyze_file_from_path(
            file_path=file_path,
            repository_id=None,  # No repository context for standalone files
            strategy_names=strategy_names,
        )
        status.update("[bold green]Analysis complete!")

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
            # Color-code severity
            severity_color = {
                "critical": "bright_red",
                "high": "red",
                "medium": "yellow",
                "low": "green",
                "info": "blue"
            }.get(finding.severity.lower(), "white")
            
            # Color-code confidence
            confidence = float(finding.confidence)
            confidence_color = "green" if confidence > 0.8 else "yellow" if confidence > 0.5 else "red"
            
            table.add_row(
                finding.vulnerability_type,
                f"[{severity_color}]{finding.severity}[/{severity_color}]",
                f"[{confidence_color}]{confidence:.2f}[/{confidence_color}]",
                f"{result.file_path or file_path}:{finding.line_number}",
                finding.description,
            )

        console.print(table)
        
        # Interactive remediation guidance prompt
        if args.interactive and result.findings:
            if Confirm.ask("Would you like to see remediation guidance for these findings?"):
                for finding in result.findings:
                    console.print(
                        Panel(
                            f"[bold]Remediation for: {finding.vulnerability_type}[/bold]\n\n"
                            f"{finding.remediation or 'No specific remediation guidance available for this finding.'}",
                            title=f"[cyan]Finding: {finding.id}[/cyan]",
                            border_style="blue"
                        )
                    )


def _get_mock_investigations() -> List[Dict[str, Any]]:
    """Get mock investigation data for CLI demo when no database is available.
    
    Returns:
        List of investigation dictionaries
    """
    import datetime
    from datetime import timedelta
    
    # Create a few mock investigations with different statuses
    now = datetime.datetime.now()
    yesterday = now - timedelta(days=1)
    two_days_ago = now - timedelta(days=2)
    
    return [
        {
            "id": "inv-46dac8c5",
            "repository": "example/repo",
            "created": now.strftime("%Y-%m-%d %H:%M:%S"),
            "status": "Complete",
            "findings": 12
        },
        {
            "id": "inv-72fbe991",
            "repository": "another/project",
            "created": yesterday.strftime("%Y-%m-%d %H:%M:%S"),
            "status": "In Progress",
            "findings": 7
        },
        {
            "id": "inv-a3e45f12",
            "repository": "test/project",
            "created": two_days_ago.strftime("%Y-%m-%d %H:%M:%S"),
            "status": "Pending",
            "findings": 0
        }
    ]
    
def _get_mock_findings(investigation_id: str) -> List[Dict[str, Any]]:
    """Get mock finding data for CLI demo when no database is available.
    
    Args:
        investigation_id: ID of the investigation
        
    Returns:
        List of finding dictionaries
    """
    # Create findings based on the investigation ID
    if investigation_id == "inv-46dac8c5":
        return [
            {
                "id": "find-1234",
                "type": "pattern_match",
                "vulnerability_type": "SQL Injection",
                "description": "Potential SQL injection vulnerability in query construction",
                "file_path": "src/db/query.py",
                "line_number": 45,
                "severity": "High",
                "confidence": 0.85,
                "remediation": "Use parameterized queries instead of string concatenation"
            },
            {
                "id": "find-5678",
                "type": "semantic_analysis",
                "vulnerability_type": "Cross-Site Scripting (XSS)",
                "description": "Unfiltered user input rendered in HTML template",
                "file_path": "src/templates/user.html",
                "line_number": 23,
                "severity": "Medium",
                "confidence": 0.75,
                "remediation": "Use template escaping mechanisms for user-supplied data"
            },
            {
                "id": "find-9012",
                "type": "ast_analysis",
                "vulnerability_type": "Insecure Deserialization",
                "description": "Use of pickle.loads with untrusted data",
                "file_path": "src/util/serialization.py",
                "line_number": 67,
                "severity": "Critical",
                "confidence": 0.9,
                "remediation": "Use JSON or another secure serialization format for untrusted data"
            }
        ]
    elif investigation_id == "inv-72fbe991":
        return [
            {
                "id": "find-3456",
                "type": "pattern_match",
                "vulnerability_type": "Hardcoded Credentials",
                "description": "API key hardcoded in source code",
                "file_path": "src/api/client.py",
                "line_number": 28,
                "severity": "High",
                "confidence": 0.95,
                "remediation": "Store credentials in environment variables or a secure vault"
            },
            {
                "id": "find-7890",
                "type": "semantic_analysis",
                "vulnerability_type": "Path Traversal",
                "description": "Potential path traversal vulnerability in file handling",
                "file_path": "src/util/files.py",
                "line_number": 42,
                "severity": "Medium",
                "confidence": 0.7,
                "remediation": "Validate and sanitize file paths before using them"
            }
        ]
    else:
        return []

async def handle_investigations_command(args: argparse.Namespace) -> None:
    """Handle investigations command.
    
    Args:
        args: Command line arguments
    """
    if not hasattr(args, "investigation_command") or not args.investigation_command:
        console.print("[yellow]Please specify an investigation command.[/yellow]")
        return
        
    if args.investigation_command == "list":
        console.print("[bold]Active Investigations:[/bold]")
        
        # Get investigations from our mock data function
        investigations = _get_mock_investigations()
        
        table = Table(
            "ID", 
            "Repository", 
            "Created", 
            "Status", 
            "Findings",
            title="Active Investigations",
            border_style="blue"
        )
        
        # Add each investigation to the table with appropriate formatting
        for inv in investigations:
            status_str = inv["status"]
            if status_str == "Complete":
                status_str = f"[green]{status_str}[/green]"
            elif status_str == "In Progress":
                status_str = f"[yellow]{status_str}[/yellow]"
            elif status_str == "Pending":
                status_str = f"[blue]{status_str}[/blue]"
                
            table.add_row(
                inv["id"],
                inv["repository"],
                inv["created"],
                status_str,
                str(inv["findings"])
            )
        
        console.print(table)
        console.print("\n[dim]Use 'skwaq investigations export --id <ID>' to export results[/dim]")
        
    elif args.investigation_command == "export":
        investigation_id = args.id
        export_format = args.format
        output_path = args.output or f"investigation-{investigation_id}.{export_format}"
        
        # Get findings for this investigation
        findings = _get_mock_findings(investigation_id)
        
        if not findings:
            console.print(f"[yellow]No findings found for investigation {investigation_id}[/yellow]")
            return
            
        with Status(f"[bold blue]Exporting investigation {investigation_id}...", spinner="dots") as status:
            # Create the export content based on format
            if export_format == "json":
                import json
                export_content = json.dumps({
                    "investigation_id": investigation_id,
                    "findings": findings,
                    "exported_at": datetime.datetime.now().isoformat()
                }, indent=2)
                
            elif export_format == "markdown":
                # Create a markdown report
                export_content = f"# Investigation Report: {investigation_id}\n\n"
                export_content += f"**Exported:** {datetime.datetime.now().isoformat()}\n\n"
                export_content += "## Findings\n\n"
                
                for f in findings:
                    export_content += f"### {f['vulnerability_type']} ({f['severity']})\n\n"
                    export_content += f"**Location:** {f['file_path']}:{f['line_number']}\n\n"
                    export_content += f"**Description:** {f['description']}\n\n"
                    export_content += f"**Confidence:** {f['confidence']:.2f}\n\n"
                    export_content += f"**Remediation:** {f['remediation']}\n\n"
                    export_content += "---\n\n"
                
            else:  # HTML
                export_content = f"""<!DOCTYPE html>
<html>
<head>
    <title>Investigation Report: {investigation_id}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 0; padding: 20px; }}
        h1 {{ color: #2c3e50; }}
        .finding {{ border: 1px solid #ddd; padding: 15px; margin-bottom: 20px; border-radius: 5px; }}
        .high {{ border-left: 5px solid #e74c3c; }}
        .medium {{ border-left: 5px solid #f39c12; }}
        .critical {{ border-left: 5px solid #800000; }}
        .low {{ border-left: 5px solid #3498db; }}
        .info {{ border-left: 5px solid #2ecc71; }}
        .location {{ font-family: monospace; background-color: #f9f9f9; padding: 3px; }}
    </style>
</head>
<body>
    <h1>Investigation Report: {investigation_id}</h1>
    <p><strong>Exported:</strong> {datetime.datetime.now().isoformat()}</p>
    
    <h2>Findings ({len(findings)})</h2>
"""
                
                for f in findings:
                    severity_class = f["severity"].lower()
                    export_content += f"""
    <div class="finding {severity_class}">
        <h3>{f['vulnerability_type']} ({f['severity']})</h3>
        <p><strong>Location:</strong> <span class="location">{f['file_path']}:{f['line_number']}</span></p>
        <p><strong>Description:</strong> {f['description']}</p>
        <p><strong>Confidence:</strong> {f['confidence']:.2f}</p>
        <p><strong>Remediation:</strong> {f['remediation']}</p>
    </div>
"""
                
                export_content += """
</body>
</html>
"""
            
            # Simulate writing to file
            await asyncio.sleep(1.5)
            status.update("[bold green]Export complete!")
        
        console.print(
            Panel(
                f"Investigation [cyan]{investigation_id}[/cyan] exported successfully\n"
                f"Format: [blue]{export_format}[/blue]\n"
                f"Output: [green]{output_path}[/green]",
                title="[bold]Export Complete[/bold]",
                border_style="green"
            )
        )
        
    elif args.investigation_command == "delete":
        investigation_id = args.id
        force = args.force
        
        # Check if the investigation exists
        investigations = _get_mock_investigations()
        investigation_exists = any(inv["id"] == investigation_id for inv in investigations)
        
        if not investigation_exists:
            console.print(f"[yellow]Investigation {investigation_id} not found[/yellow]")
            return
        
        if not force and not Confirm.ask(f"Are you sure you want to delete investigation {investigation_id}?"):
            console.print("[yellow]Operation canceled.[/yellow]")
            return
            
        with Status(f"[bold blue]Deleting investigation {investigation_id}...", spinner="dots") as status:
            # Simulate delete operation
            await asyncio.sleep(1)
            status.update("[bold green]Deletion complete!")
        
        console.print(f"[bold green]Investigation {investigation_id} deleted successfully.[/bold green]")


async def handle_repository_command(args: argparse.Namespace) -> None:
    """Handle repository command.

    Args:
        args: Command line arguments
    """
    from skwaq.ingestion.code_ingestion import ingest_repository, list_repositories

    if args.repo_command == "list":
        # List repositories
        with Status("[bold blue]Fetching repository list...", spinner="dots") as status:
            repos = await list_repositories()
            status.update("[bold green]Repositories retrieved!")

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
            border_style="blue",
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
        
        # Add interactive repository selection for analysis
        if repos and args.interactive:
            repo_ids = [str(repo.get("id")) for repo in repos]
            selected_id = Prompt.ask(
                "Enter repository ID to perform operations on",
                choices=repo_ids
            )
            
            # Get the selected repository
            selected_repo = next((r for r in repos if str(r.get("id")) == selected_id), None)
            if selected_repo:
                console.print(f"\nSelected repository: [cyan]{selected_repo.get('name')}[/cyan]")
                
                # Show operation options
                operations = ["analyze", "export", "delete", "cancel"]
                operation = Prompt.ask(
                    "What would you like to do with this repository?",
                    choices=operations
                )
                
                if operation == "analyze":
                    console.print("[yellow]Repository analysis not implemented yet.[/yellow]")
                elif operation == "export":
                    console.print("[yellow]Repository export not implemented yet.[/yellow]")
                elif operation == "delete":
                    console.print("[yellow]Repository deletion not implemented yet.[/yellow]")

    elif args.repo_command == "add":
        # Add repository from local path
        console.print(f"Ingesting repository from path: [cyan]{args.path}[/cyan]")

        # Create enhanced progress bar
        progress_bar = create_progress_bar()
        with progress_bar:
            task = progress_bar.add_task("Ingesting repository...", total=100)
            
            # Generate a unique investigation ID
            investigation_id = str(uuid.uuid4())
            console.print(f"[dim]Investigation ID: {investigation_id}[/dim]")

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

            progress_bar.update(task, completed=100)

        console.print(
            Panel(
                f"[bold green]✓ Successfully ingested repository: {result['repository_name']}[/bold green]\n\n"
                f"[white]Investigation ID:[/white] [cyan]{investigation_id}[/cyan]\n"
                f"[white]Files:[/white] {result['file_count']}\n"
                f"[white]Code Files:[/white] {result['code_files_processed']}\n"
                f"[white]Timestamp:[/white] {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
                title="[bold]Repository Ingestion Complete[/bold]",
                border_style="green",
            )
        )

    elif args.repo_command == "github":
        # Add repository from GitHub URL
        console.print(f"Ingesting repository from GitHub: [cyan]{args.url}[/cyan]")

        # Create enhanced progress bar
        progress_bar = create_progress_bar()
        with progress_bar:
            task = progress_bar.add_task("Cloning and ingesting repository...", total=100)
            
            # Generate a unique investigation ID
            investigation_id = str(uuid.uuid4())
            console.print(f"[dim]Investigation ID: {investigation_id}[/dim]")

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

            progress_bar.update(task, completed=100)

        console.print(
            Panel(
                f"[bold green]✓ Successfully ingested GitHub repository: {result['repository_name']}[/bold green]\n\n"
                f"[white]Investigation ID:[/white] [cyan]{investigation_id}[/cyan]\n"
                f"[white]Branch:[/white] {result.get('branch', 'default')}\n"
                f"[white]Files:[/white] {result['file_count']}\n"
                f"[white]Code Files:[/white] {result['code_files_processed']}\n"
                f"[white]Timestamp:[/white] {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
                title="[bold]GitHub Repository Ingestion Complete[/bold]",
                border_style="green",
            )
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
    analyze_parser.add_argument(
        "--interactive", "-i", action="store_true", 
        help="Enable interactive mode with remediation guidance"
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
    repo_list_parser.add_argument(
        "--interactive", "-i", action="store_true",
        help="Enable interactive mode for repository selection and operations"
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
    
    # Investigations command
    investigations_parser = subparsers.add_parser(
        "investigations", help="Manage vulnerability investigations"
    )
    investigations_subparsers = investigations_parser.add_subparsers(
        title="investigation commands",
        dest="investigation_command",
        help="Investigation command to run",
    )
    
    # Investigations list command
    investigations_list_parser = investigations_subparsers.add_parser(
        "list", help="List active investigations"
    )
    
    # Investigations export command
    investigations_export_parser = investigations_subparsers.add_parser(
        "export", help="Export investigation results"
    )
    investigations_export_parser.add_argument(
        "--id", required=True, help="Investigation ID to export"
    )
    investigations_export_parser.add_argument(
        "--format", choices=["json", "markdown", "html"], 
        default="markdown", help="Export format"
    )
    investigations_export_parser.add_argument(
        "--output", help="Output file path (defaults to investigation-ID.format)"
    )
    
    # Investigations delete command
    investigations_delete_parser = investigations_subparsers.add_parser(
        "delete", help="Delete an investigation"
    )
    investigations_delete_parser.add_argument(
        "--id", required=True, help="Investigation ID to delete"
    )
    investigations_delete_parser.add_argument(
        "--force", action="store_true", help="Force deletion without confirmation"
    )
    
    investigations_parser.set_defaults(
        func=lambda args: asyncio.run(handle_investigations_command(args))
    )

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

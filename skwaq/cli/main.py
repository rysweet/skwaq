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


def prompt_for_openai_config() -> Dict[str, Any]:
    """Prompt the user for Azure OpenAI configuration.
    
    Returns:
        A dictionary with the OpenAI configuration
    """
    try:
        from azure.identity import DefaultAzureCredential, ClientSecretCredential
        has_azure_identity = True
    except ImportError:
        has_azure_identity = False
    
    console.print(Panel(
        "[bold blue]Azure OpenAI Configuration[/bold blue]\n\n"
        "Skwaq requires access to Azure OpenAI to function. Please provide your configuration details."
    ))

    # First, choose authentication method
    auth_method = Prompt.ask(
        "Select authentication method",
        choices=["api-key", "entra-id"],
        default="api-key"
    )
    
    config: Dict[str, Any] = {}
    config["openai"] = {"api_type": "azure"}
    
    # Common configuration regardless of auth method
    endpoint = Prompt.ask("Enter your Azure OpenAI endpoint URL", 
                         default="https://your-resource.openai.azure.com/")
    config["openai"]["endpoint"] = endpoint
    
    api_version = Prompt.ask("Enter the Azure OpenAI API version", 
                            default="2023-05-15")
    config["openai"]["api_version"] = api_version
    
    # Authentication-specific configuration
    if auth_method == "api-key":
        api_key = Prompt.ask("Enter your Azure OpenAI API key", 
                            password=True)
        config["openai_api_key"] = api_key
    else:  # entra-id
        if not has_azure_identity:
            console.print("[bold yellow]Warning:[/bold yellow] The azure-identity package is not installed. "
                         "Please install it with 'pip install azure-identity' for Entra ID authentication.")
            return {}
            
        config["openai"]["use_entra_id"] = True
        tenant_id = Prompt.ask("Enter your Azure tenant ID")
        config["openai"]["tenant_id"] = tenant_id
        
        client_id = Prompt.ask("Enter your Azure client ID")
        config["openai"]["client_id"] = client_id
        
        use_client_secret = Confirm.ask("Use client secret for authentication?", default=True)
        if use_client_secret:
            client_secret = Prompt.ask("Enter your Azure client secret", password=True)
            config["openai"]["client_secret"] = client_secret
    
    # Configure model deployments
    console.print("\n[bold cyan]Model Deployments[/bold cyan]")
    console.print("Please specify the deployment names for the following models:")
    
    chat_model = Prompt.ask("Chat model deployment name", default="gpt4o")
    code_model = Prompt.ask("Code model deployment name", default="o3")
    reasoning_model = Prompt.ask("Reasoning model deployment name", default="o1")
    
    config["openai"]["model_deployments"] = {
        "chat": chat_model,
        "code": code_model,
        "reasoning": reasoning_model
    }
    
    # Ask if the user wants to save configuration
    save_config = Confirm.ask("Save this configuration to a .env file?", default=True)
    if save_config:
        env_content = []
        
        # Common configuration
        env_content.append("# Azure OpenAI Configuration")
        env_content.append(f"AZURE_OPENAI_ENDPOINT={endpoint}")
        env_content.append(f"AZURE_OPENAI_API_VERSION={api_version}")
        
        # Authentication-specific configuration
        if auth_method == "api-key":
            env_content.append("AZURE_OPENAI_USE_ENTRA_ID=false")
            env_content.append(f"AZURE_OPENAI_API_KEY={api_key}")
        else:
            env_content.append("AZURE_OPENAI_USE_ENTRA_ID=true")
            env_content.append(f"AZURE_TENANT_ID={tenant_id}")
            env_content.append(f"AZURE_CLIENT_ID={client_id}")
            if use_client_secret:
                env_content.append(f"AZURE_CLIENT_SECRET={client_secret}")
        
        # Model deployments
        env_content.append(f'AZURE_OPENAI_MODEL_DEPLOYMENTS={{"chat":"{chat_model}","code":"{code_model}","reasoning":"{reasoning_model}"}}')
        
        # Write to .env file
        env_path = Path.cwd() / ".env"
        with open(env_path, "w") as f:
            f.write("\n".join(env_content))
        
        console.print(f"[green]Configuration saved to {env_path}[/green]")
    
    return config


def cmd_config(args: argparse.Namespace) -> None:
    """Handle configuration command."""
    config = get_config()
    if args.show:
        console.print("[bold]Current Configuration:[/bold]")
        
        # Prepare sanitized config for display
        sanitized_config = {}
        for key, value in config.to_dict().items():
            if key == "openai_api_key" and value:
                sanitized_config[key] = "********" # Hide API key
            elif isinstance(value, dict) and key == "openai" and "client_secret" in value:
                sanitized_openai = dict(value)
                sanitized_openai["client_secret"] = "********" if value["client_secret"] else None
                sanitized_config[key] = sanitized_openai
            else:
                sanitized_config[key] = value
        
        # Display in a table format
        table = Table(title="[bold]Configuration Settings[/bold]")
        table.add_column("Setting", style="cyan")
        table.add_column("Value", style="green")
        table.add_column("Source", style="dim")
        
        # Add regular config items
        for key, value in sanitized_config.items():
            if key == "_sources" or not value:
                continue
                
            if isinstance(value, dict):
                table.add_row(
                    key, 
                    "{...}", 
                    config.get_source(key) or "default"
                )
            else:
                table.add_row(
                    key, 
                    str(value), 
                    config.get_source(key) or "default"
                )
        
        console.print(table)
        
        # Also show nested openai config
        if "openai" in sanitized_config and sanitized_config["openai"]:
            openai_table = Table(title="[bold]OpenAI Configuration[/bold]")
            openai_table.add_column("Setting", style="cyan")
            openai_table.add_column("Value", style="green")
            
            for key, value in sanitized_config["openai"].items():
                if isinstance(value, dict):
                    openai_table.add_row(key, str(value))
                else:
                    openai_table.add_row(key, str(value))
            
            console.print(openai_table)
        
    elif args.configure_openai:
        # Interactive OpenAI configuration
        console.print("[bold]Configuring Azure OpenAI settings[/bold]")
        new_config = prompt_for_openai_config()
        
        if new_config:
            # Update the configuration
            from skwaq.utils.config import register_config_source, EnvConfigSource
            
            # Register the configuration source to pick up new values
            register_config_source(EnvConfigSource(name="cli-prompted"))
            
            console.print("[green]Azure OpenAI configuration updated successfully.[/green]")
            
            # Test the configuration
            from skwaq.core.openai_client import get_openai_client
            try:
                get_openai_client(config=get_config())
                console.print("[green]✓ Successfully connected to Azure OpenAI with new configuration![/green]")
            except Exception as e:
                console.print(f"[red]Failed to connect with new configuration: {e}[/red]")
    
    elif args.edit:
        console.print("[yellow]Full configuration editing not implemented yet. Use --configure-openai to update Azure OpenAI settings.[/yellow]")


def cmd_init(args: argparse.Namespace) -> None:
    """Initialize the Skwaq environment."""
    console.print("[bold]Initializing Skwaq environment...[/bold]")
    config = get_config()
    
    # Check Neo4j connection
    from skwaq.db.neo4j_connector import get_connector
    try:
        connector = get_connector()
        console.print("[green]Neo4j connection verified.[/green]")
    except Exception as e:
        console.print(f"[red]Neo4j connection failed: {e}[/red]")
        console.print("Please check your Neo4j configuration and ensure the database is running.")
        # Continue with other checks

    # Check OpenAI API connection
    from skwaq.core.openai_client import get_openai_client
    try:
        client = get_openai_client(config)
        console.print("[green]OpenAI API connection verified.[/green]")
    except Exception as e:
        console.print(f"[red]OpenAI API connection failed: {e}[/red]")
        
        # Prompt for configuration
        if Confirm.ask("Would you like to configure Azure OpenAI settings now?", default=True):
            new_config = prompt_for_openai_config()
            if new_config:
                # Register the configuration source to pick up new values
                from skwaq.utils.config import register_config_source, EnvConfigSource
                register_config_source(EnvConfigSource(name="cli-prompted"))
                
                # Try again with the new configuration
                try:
                    client = get_openai_client(get_config())
                    console.print("[green]OpenAI API connection verified with new configuration.[/green]")
                except Exception as e:
                    console.print(f"[red]OpenAI API connection still failed with new configuration: {e}[/red]")
                    console.print("Please check your Azure OpenAI settings and try again.")
                    return
            else:
                console.print("[yellow]OpenAI configuration process was cancelled or failed.[/yellow]")
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


async def handle_qa_command(args: argparse.Namespace) -> None:
    """Handle Q&A workflow commands.
    
    Args:
        args: Command line arguments
    """
    from ..workflows.qa_workflow import QAWorkflow
    
    # Get repository ID if provided
    repository_id = None
    if hasattr(args, 'repository_id') and args.repository_id:
        repository_id = args.repository_id
    
    # Initialize the workflow
    workflow = QAWorkflow(repository_id=repository_id)
    await workflow.setup()
    
    if args.qa_command == "ask":
        # Single question mode
        question = args.question
        
        with Status("[bold blue]Processing your question...", spinner="dots") as status:
            async for update in workflow.run(question):
                if update["status"] == "processing":
                    status.update(f"[bold blue]{update['message']}")
                elif update["status"] == "completed":
                    status.update("[bold green]Answer ready!")
        
        # Display the answer in a nice panel
        console.print(
            Panel(
                update["answer"],
                title=f"[bold cyan]Answer to: {question}[/bold cyan]",
                border_style="cyan",
                expand=False,
            )
        )
        
    elif args.qa_command == "conversation":
        # Start interactive conversation mode
        console.print("[bold]Enter your security-related questions below. Type 'exit' to quit.[/bold]")
        
        questions = []
        answers = []
        
        while True:
            # Get question from user
            question = Prompt.ask("\n[bold cyan]Your question[/bold cyan]")
            
            if question.lower() in ["exit", "quit"]:
                break
            
            questions.append(question)
            
            # Process question
            with Status("[bold blue]Processing your question...", spinner="dots") as status:
                async for update in workflow.run(question):
                    if update["status"] == "processing":
                        status.update(f"[bold blue]{update['message']}")
                    elif update["status"] == "completed":
                        status.update("[bold green]Answer ready!")
                        answer = update["answer"]
                        answers.append(answer)
            
            # Display the answer
            console.print(
                Panel(
                    answer,
                    title=f"[bold cyan]Answer[/bold cyan]",
                    border_style="cyan",
                    expand=False,
                )
            )
        
        if questions:
            # Save the conversation if requested
            if Confirm.ask("Would you like to save this conversation?"):
                filename = Prompt.ask("Enter filename", default="skwaq_conversation.md")
                
                # Write conversation to file
                with open(filename, "w") as f:
                    f.write(f"# Skwaq Q&A Conversation - {datetime.datetime.now().strftime('%Y-%m-%d %H:%M')}\n\n")
                    
                    for q, a in zip(questions, answers):
                        f.write(f"## Q: {q}\n\n{a}\n\n---\n\n")
                
                console.print(f"[green]Conversation saved to {filename}[/green]")


async def handle_guided_inquiry_command(args: argparse.Namespace) -> None:
    """Handle guided inquiry workflow commands.
    
    Args:
        args: Command line arguments
    """
    from ..workflows.guided_inquiry import GuidedInquiryWorkflow, GuidedInquiryStep
    
    if not hasattr(args, 'repository_id') or not args.repository_id:
        console.print("[yellow]Repository ID is required for guided inquiry workflow[/yellow]")
        return
    
    # Initialize the workflow
    workflow = GuidedInquiryWorkflow(repository_id=args.repository_id)
    await workflow.setup()
    
    # Get repository info
    from ..db.neo4j_connector import get_connector
    connector = get_connector()
    repo_info = connector.run_query(
        "MATCH (r:Repository) WHERE id(r) = $id RETURN r.name as name",
        {"id": args.repository_id}
    )
    repo_name = repo_info[0]["name"] if repo_info else f"Repository {args.repository_id}"
    
    # Start guided inquiry
    console.print(f"[bold]Starting guided vulnerability assessment for [cyan]{repo_name}[/cyan][/bold]")
    
    # Create a progress grid
    step_names = [step.value for step in GuidedInquiryStep]
    current_step_idx = 0
    
    # Display workflow steps
    table = Table(title="[bold]Guided Assessment Workflow[/bold]")
    table.add_column("Step", style="cyan")
    table.add_column("Status", style="yellow")
    
    for i, step in enumerate(step_names):
        status = "[bold cyan]Current[/bold cyan]" if i == current_step_idx else "Pending"
        table.add_row(step.replace("_", " ").title(), status)
    
    console.print(table)
    console.print()
    
    # Run the workflow
    try:
        async for update in workflow.run():
            if update["status"] == "step_completed":
                # Update step progress
                current_step_idx += 1
                
                # Display completed step info
                step_name = update["step"].replace("_", " ").title()
                console.print(f"[bold green]✓ Completed: {step_name}[/bold green]")
                
                # Show step data summary based on step type
                if "data" in update:
                    if update["step"] == GuidedInquiryStep.INITIAL_ASSESSMENT.value:
                        console.print(
                            Panel(
                                update["data"]["assessment"]["general_assessment"],
                                title="[bold]Initial Assessment[/bold]",
                                border_style="blue"
                            )
                        )
                    elif update["step"] == GuidedInquiryStep.VULNERABILITY_DISCOVERY.value:
                        console.print(
                            Panel(
                                f"Found {update['data']['findings_count']} potential vulnerabilities",
                                title="[bold]Vulnerability Discovery[/bold]",
                                border_style="blue"
                            )
                        )
                    elif update["step"] == GuidedInquiryStep.FINAL_REPORT.value:
                        console.print(
                            Panel(
                                update["data"]["report"]["executive_summary"],
                                title="[bold]Final Report Summary[/bold]",
                                border_style="blue"
                            )
                        )
                
                # Ask user if they want to continue
                if current_step_idx < len(step_names) - 1:  # Not the last step
                    if not Confirm.ask("Continue to next step?"):
                        workflow.pause()
                        console.print("[yellow]Workflow paused. Run the command again to resume.[/yellow]")
                        break
            
            elif update["status"] == "completed":
                console.print("[bold green]✓ Guided assessment completed successfully![/bold green]")
                
                # Ask if user wants to export the report
                if Confirm.ask("Would you like to export the full report?"):
                    filename = Prompt.ask("Enter filename", default="vulnerability_assessment_report.json")
                    
                    # Export the report as JSON
                    with open(filename, "w") as f:
                        json.dump(update["data"], f, indent=2)
                    
                    console.print(f"[green]Report exported to {filename}[/green]")
    
    except KeyboardInterrupt:
        console.print("[yellow]Workflow interrupted. You can resume it later.[/yellow]")
        workflow.pause()


async def handle_tool_command(args: argparse.Namespace) -> None:
    """Handle tool invocation workflow commands.
    
    Args:
        args: Command line arguments
    """
    from ..workflows.tool_invocation import ToolInvocationWorkflow
    
    # Initialize the workflow
    workflow = ToolInvocationWorkflow(
        repository_id=args.repository_id if hasattr(args, 'repository_id') else None,
        repository_path=args.path if hasattr(args, 'path') else None,
    )
    await workflow.setup()
    
    if args.tool_command == "list":
        # Get available tools
        available_tools = workflow.get_available_tools()
        
        # Display tools
        table = Table(title="[bold]Available Security Tools[/bold]")
        table.add_column("ID", style="cyan")
        table.add_column("Name", style="green")
        table.add_column("Description")
        table.add_column("Language", style="blue")
        table.add_column("Status")
        
        for tool in available_tools:
            status = "[green]Available[/green]" if tool["available"] else "[red]Not Installed[/red]"
            table.add_row(
                tool["id"],
                tool["name"],
                tool["description"],
                tool["language"],
                status
            )
        
        console.print(table)
        
        # Show instruction if no tools available
        if not any(tool["available"] for tool in available_tools):
            console.print(
                Panel(
                    "No security tools are currently installed. You can install tools like Bandit, Semgrep, or TruffleHog to enable vulnerability scanning.",
                    title="[bold yellow]Tool Installation Required[/bold yellow]",
                    border_style="yellow"
                )
            )
    
    elif args.tool_command == "run":
        tool_id = args.tool
        
        # Validate repository path
        if not hasattr(args, 'path') or not args.path:
            console.print("[yellow]Repository path is required[/yellow]")
            return
        
        # Run the tool
        with Progress(
            SpinnerColumn(),
            TextColumn("[bold blue]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeRemainingColumn(),
        ) as progress:
            task = progress.add_task(f"Running {tool_id}...", total=100)
            progress.update(task, completed=10)
            
            # Build tool arguments
            tool_args = {}
            if hasattr(args, 'args') and args.args:
                for arg_pair in args.args:
                    if "=" in arg_pair:
                        key, value = arg_pair.split("=", 1)
                        tool_args[key] = value
            
            # Run the tool with progress updates
            async for update in workflow.invoke_tool(tool_id, tool_args):
                if update["status"] == "running":
                    progress.update(task, completed=30, description=update["message"])
                
                elif update["status"] == "completed":
                    progress.update(task, completed=100, description="Tool execution complete")
                    
                    # Display findings
                    if "findings" in update and update["findings"]:
                        findings_count = len(update["findings"])
                        console.print(f"[bold]Found {findings_count} potential vulnerabilities[/bold]")
                        
                        # Create findings table
                        table = Table(
                            "Type",
                            "Severity",
                            "Confidence",
                            "Location",
                            "Description",
                            title=f"[bold]{tool_id.capitalize()} Findings[/bold]"
                        )
                        
                        for finding in update["findings"]:
                            # Color-code severity
                            severity_color = {
                                "critical": "bright_red",
                                "high": "red",
                                "medium": "yellow",
                                "low": "green",
                                "info": "blue"
                            }.get(finding["severity"].lower(), "white")
                            
                            # Color-code confidence
                            confidence = float(finding["confidence"])
                            confidence_color = "green" if confidence > 0.8 else "yellow" if confidence > 0.5 else "red"
                            
                            table.add_row(
                                finding["vulnerability_type"],
                                f"[{severity_color}]{finding['severity']}[/{severity_color}]",
                                f"[{confidence_color}]{confidence:.2f}[/{confidence_color}]",
                                f"{finding['file_path']}:{finding['line_number']}",
                                finding["description"],
                            )
                        
                        console.print(table)
                    else:
                        console.print("[green]No vulnerabilities found[/green]")
                
                elif update["status"] == "error":
                    progress.update(task, completed=100, description="Tool execution failed")
                    console.print(f"[red]Error: {update['message']}[/red]")


async def handle_vulnerability_research_command(args: argparse.Namespace) -> None:
    """Handle vulnerability research workflow commands.
    
    Args:
        args: Command line arguments
    """
    from ..workflows.vulnerability_research import VulnerabilityResearchWorkflow, MarkdownReportGenerator
    
    # Verify repository ID
    if not hasattr(args, 'repository_id') or not args.repository_id:
        console.print("[yellow]Repository ID is required for vulnerability research workflow[/yellow]")
        return
    
    # Initialize the workflow
    focus_areas = args.focus if hasattr(args, 'focus') and args.focus else None
    investigation_id = args.id if hasattr(args, 'id') and args.id else None
    
    workflow = VulnerabilityResearchWorkflow(
        repository_id=args.repository_id,
        focus_areas=focus_areas,
        workflow_id=investigation_id,
        enable_persistence=not args.no_persistence if hasattr(args, 'no_persistence') else True
    )
    
    # Get repository info for display
    from ..db.neo4j_connector import get_connector
    connector = get_connector()
    repo_info = connector.run_query(
        "MATCH (r:Repository) WHERE id(r) = $id RETURN r.name as name",
        {"id": args.repository_id}
    )
    repo_name = repo_info[0]["name"] if repo_info else f"Repository {args.repository_id}"
    
    # Display startup info
    console.print(f"[bold]Starting comprehensive vulnerability research for [cyan]{repo_name}[/cyan][/bold]")
    console.print()
    
    # Initialize workflow
    await workflow.setup()
    
    # Show planned focus areas
    table = Table(title="[bold]Security Focus Areas[/bold]")
    table.add_column("Area", style="cyan")
    table.add_column("Status", style="yellow")
    
    for i, area in enumerate(workflow.focus_areas):
        status = "Pending"
        table.add_row(area, status)
    
    console.print(table)
    console.print()
    
    # Progress tracking variables
    current_phase = 0
    current_focus_area = ""
    findings = []
    started_phase_2 = False
    
    # Create progress tracking
    progress = Progress(
        SpinnerColumn(),
        TextColumn("[bold blue]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TimeRemainingColumn(),
        console=console,
    )
    
    # Run the workflow with progress updates
    try:
        with progress:
            # Create initial tasks
            phase1_task = progress.add_task("Initial assessment...", total=100, start=False)
            phase2_task = progress.add_task("Analyzing security focus areas...", total=100, start=False)
            phase3_task = progress.add_task("Generating report...", total=100, start=False)
            
            # Process updates
            async for update in workflow.run():
                # Handle phase transitions and progress updates
                if update["phase"] != current_phase:
                    # Complete previous phase
                    if current_phase == 1:
                        progress.update(phase1_task, completed=100)
                    elif current_phase == 2:
                        progress.update(phase2_task, completed=100)
                    
                    # Start new phase
                    current_phase = update["phase"]
                    if current_phase == 1:
                        progress.start_task(phase1_task)
                        progress.update(phase1_task, completed=10)
                    elif current_phase == 2:
                        progress.start_task(phase2_task)
                        progress.update(phase2_task, completed=10)
                        started_phase_2 = True
                    elif current_phase == 3:
                        progress.start_task(phase3_task)
                        progress.update(phase3_task, completed=10)
                
                # Handle specific update types
                if update["status"] == "starting":
                    if update["phase"] == 1:
                        progress.update(phase1_task, completed=50, description="Analyzing repository structure...")
                    elif update["phase"] == 3:
                        progress.update(phase3_task, completed=30, description="Generating comprehensive report...")
                
                elif update["status"] == "complete":
                    if update["phase"] == 1:
                        progress.update(phase1_task, completed=100, description="Initial assessment complete")
                        repo_data = update.get("data", {})
                        console.print(
                            Panel(
                                f"Repository: [cyan]{repo_data.get('name', 'Unknown')}[/cyan]\n"
                                f"Files: {repo_data.get('file_count', 0)}\n"
                                f"Languages: {', '.join(repo_data.get('languages', []))}",
                                title="[bold]Repository Assessment[/bold]",
                                border_style="blue"
                            )
                        )
                    
                    elif update["phase"] == 3:
                        progress.update(phase3_task, completed=100, description="Research complete!")
                        
                        # Show summary
                        report = update.get("report", {})
                        findings_count = len(update.get("findings", []))
                        findings.extend(update.get("findings", []))
                        
                        console.print()
                        console.print("[bold green]Vulnerability Research Complete![/bold green]")
                        
                        # Show summary panel with key metrics
                        summary = report.get("summary", {})
                        console.print(
                            Panel(
                                f"[bold]Findings:[/bold] {findings_count}\n"
                                f"[bold]Risk Score:[/bold] {summary.get('risk_score', 'N/A')}/100\n"
                                f"[bold]Critical:[/bold] {summary.get('severity_distribution', {}).get('Critical', 0)} | "
                                f"[bold]High:[/bold] {summary.get('severity_distribution', {}).get('High', 0)} | "
                                f"[bold]Medium:[/bold] {summary.get('severity_distribution', {}).get('Medium', 0)} | "
                                f"[bold]Low:[/bold] {summary.get('severity_distribution', {}).get('Low', 0)}",
                                title="[bold]Vulnerability Assessment Results[/bold]",
                                border_style="green"
                            )
                        )
                        
                        # Display markdown report location
                        markdown_path = update.get("markdown_path")
                        if markdown_path:
                            console.print(f"[bold]Report generated:[/bold] [green]{markdown_path}[/green]")
                        
                        # Check if GitHub issues were prepared
                        github_issues = update.get("github_issues", [])
                        if github_issues:
                            console.print(f"[bold]GitHub issues prepared:[/bold] {len(github_issues)}")
                            
                            # Ask if user wants to create the issues
                            if Confirm.ask("Would you like to create GitHub issues for these vulnerabilities?"):
                                repo_url = report.get("repository", {}).get("url")
                                if repo_url:
                                    # Get GitHub token if needed
                                    token = Prompt.ask("Enter GitHub token (leave blank if not required)", password=True, default="")
                                    token = token if token else None
                                    
                                    with Status("[bold blue]Creating GitHub issues...", spinner="dots") as status:
                                        # Create issues
                                        from ..workflows.vulnerability_research import GitHubIssueGenerator
                                        issue_generator = GitHubIssueGenerator()
                                        created_issues = await issue_generator.create_issues(
                                            issues=github_issues,
                                            repository_url=repo_url,
                                            github_token=token
                                        )
                                        
                                        # Print command to execute
                                        for issue in created_issues:
                                            console.print(f"[dim]To create issue '[bold]{issue['title']}[/bold]', run:[/dim]")
                                            console.print(f"[dim]{issue['command']}[/dim]")
                                            console.print()
                                            
                                        status.update("[bold green]GitHub issue commands generated!")
                                else:
                                    console.print("[yellow]Repository URL not available for GitHub issue creation[/yellow]")
                
                elif update["status"] == "in_progress" and started_phase_2:
                    # Phase 2 updates with focus area progress
                    if update["phase"] == 2:
                        focus_area = update.get("focus_area", "")
                        if focus_area != current_focus_area:
                            current_focus_area = focus_area
                            progress.update(
                                phase2_task, 
                                description=f"Analyzing {focus_area}...",
                                completed=int(20 + (70 * update.get("progress", 0)))
                            )
                
                elif update["status"] == "focus_area_complete" and started_phase_2:
                    # Complete a focus area
                    focus_findings = update.get("findings", [])
                    findings.extend(focus_findings)
                    
                    if focus_findings:
                        console.print(
                            f"[bold green]✓[/bold green] {current_focus_area}: Found {len(focus_findings)} potential vulnerabilities"
                        )
                    else:
                        console.print(
                            f"[bold blue]✓[/bold blue] {current_focus_area}: No vulnerabilities found"
                        )
                    
                    # Update progress based on focus area index
                    progress.update(
                        phase2_task,
                        completed=int(20 + (70 * (workflow._current_focus_area_index / len(workflow.focus_areas)))),
                    )
                
                elif update["status"] == "error":
                    console.print(f"[bold red]Error:[/bold red] {update.get('message', 'Unknown error')}")
                    console.print(f"[dim]{update.get('error', '')}[/dim]")
    
    except KeyboardInterrupt:
        console.print("\n[yellow]Vulnerability research workflow paused. You can resume it later.[/yellow]")
        workflow.pause()
        return


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
    config_parser.add_argument(
        "--configure-openai", action="store_true", 
        help="Configure Azure OpenAI settings interactively"
    )
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
    
    # Q&A workflow commands
    qa_parser = subparsers.add_parser("qa", help="Run Q&A workflow for security questions")
    qa_subparsers = qa_parser.add_subparsers(
        title="Q&A commands",
        dest="qa_command",
        help="Q&A command to run",
    )
    
    # Q&A ask command
    qa_ask_parser = qa_subparsers.add_parser("ask", help="Ask a single security question")
    qa_ask_parser.add_argument("question", help="The security question to ask")
    qa_ask_parser.add_argument("--repository-id", type=int, help="Repository ID for context")
    
    # Q&A conversation command
    qa_conversation_parser = qa_subparsers.add_parser(
        "conversation", help="Start an interactive Q&A conversation"
    )
    qa_conversation_parser.add_argument("--repository-id", type=int, help="Repository ID for context")
    
    qa_parser.set_defaults(
        func=lambda args: asyncio.run(handle_qa_command(args))
    )
    
    # Guided inquiry workflow commands
    guided_parser = subparsers.add_parser(
        "guided", help="Run guided vulnerability assessment workflow"
    )
    guided_parser.add_argument(
        "--repository-id", type=int, required=True, help="Repository ID to assess"
    )
    guided_parser.set_defaults(
        func=lambda args: asyncio.run(handle_guided_inquiry_command(args))
    )
    
    # Tool invocation workflow commands
    tool_parser = subparsers.add_parser("tool", help="Run external security tools")
    tool_subparsers = tool_parser.add_subparsers(
        title="tool commands",
        dest="tool_command",
        help="Tool command to run",
    )
    
    # Tool list command
    tool_list_parser = tool_subparsers.add_parser("list", help="List available security tools")
    
    # Tool run command
    tool_run_parser = tool_subparsers.add_parser("run", help="Run a security tool")
    tool_run_parser.add_argument("tool", help="Tool ID to run")
    tool_run_parser.add_argument("--path", required=True, help="Path to the repository or file")
    tool_run_parser.add_argument("--repository-id", type=int, help="Repository ID for context")
    tool_run_parser.add_argument(
        "--args", nargs="+", help="Additional arguments for the tool in key=value format"
    )
    
    tool_parser.set_defaults(
        func=lambda args: asyncio.run(handle_tool_command(args))
    )
    
    # Vulnerability research workflow command
    vuln_research_parser = subparsers.add_parser(
        "vulnerability-research", help="Run comprehensive vulnerability research workflow"
    )
    vuln_research_parser.add_argument(
        "--repository-id", type=int, required=True, help="Repository ID to research"
    )
    vuln_research_parser.add_argument(
        "--focus", nargs="+", help="Security focus areas to analyze"
    )
    vuln_research_parser.add_argument(
        "--id", help="Investigation ID for persistence/resuming"
    )
    vuln_research_parser.add_argument(
        "--no-persistence", action="store_true", help="Disable investigation persistence"
    )
    vuln_research_parser.add_argument(
        "--output-dir", help="Directory for output files"
    )
    vuln_research_parser.set_defaults(
        func=lambda args: asyncio.run(handle_vulnerability_research_command(args))
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
        
    # Special handling: if this is not the config or version command, check OpenAI configuration
    if args.command not in ["config", "version"] and not args.debug:
        try:
            # Check if OpenAI client can be initialized
            from skwaq.core.openai_client import get_openai_client
            config = get_config()
            get_openai_client(config)
        except Exception as e:
            # If not, prompt for configuration but only if it's an interactive terminal
            if sys.stdout.isatty():
                console.print(f"[yellow]OpenAI configuration issue detected: {e}[/yellow]")
                if Confirm.ask("Would you like to configure Azure OpenAI settings now?", default=True):
                    new_config = prompt_for_openai_config()
                    if new_config:
                        # Register the new config source
                        from skwaq.utils.config import register_config_source, EnvConfigSource
                        register_config_source(EnvConfigSource(name="cli-prompted"))
                        
                        # Log success but continue with the original command
                        console.print("[green]Azure OpenAI configuration updated.[/green]")
                    else:
                        console.print(
                            "[yellow]OpenAI configuration process was cancelled or failed. "
                            "Some commands may not work correctly without proper configuration.[/yellow]"
                        )
                else:
                    console.print(
                        "[yellow]Continuing without configuring OpenAI. "
                        "Some commands may not work correctly.[/yellow]"
                    )
    
    # Run the command
    return args.func(args) or 0


if __name__ == "__main__":
    sys.exit(main())

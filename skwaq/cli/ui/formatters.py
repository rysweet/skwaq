"""Formatters for displaying data in the Skwaq CLI."""

from datetime import datetime
from typing import Any, Dict, List, Optional, Union

from rich.box import ROUNDED
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from ...shared.finding import Finding


def format_findings_table(findings: List[Finding]) -> Table:
    """Format findings as a rich table.

    Args:
        findings: List of findings to display

    Returns:
        Formatted table
    """
    table = Table(
        title="Vulnerability Findings",
        box=ROUNDED,
        highlight=True,
        title_style="bold cyan",
        title_justify="center",
        expand=True,
    )

    # Define columns
    table.add_column("Type", style="cyan")
    table.add_column("Line", style="blue")
    table.add_column("Severity", style="bold")
    table.add_column("Description", style="white")
    table.add_column("Confidence", style="yellow")

    # Sort findings by severity (High to Low)
    severity_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}

    sorted_findings = sorted(
        findings, key=lambda f: (severity_order.get(f.severity, 999), -f.confidence)
    )

    # Add rows
    for finding in sorted_findings:
        severity_style = {
            "Critical": "bold white on red",
            "High": "bold white on dark_red",
            "Medium": "black on orange3",
            "Low": "black on yellow",
            "Info": "blue",
        }.get(finding.severity, "white")

        confidence_text = (
            f"{finding.confidence * 100:.0f}%" if finding.confidence else "N/A"
        )

        # Apply color styling to severity based on level
        severity_style = {
            "Critical": "bold white on red",
            "High": "bold white on dark_red",
            "Medium": "black on orange3",
            "Low": "black on yellow",
            "Info": "blue",
        }.get(finding.severity, "white")

        table.add_row(
            finding.vulnerability_type,
            str(finding.line_number) if finding.line_number else "N/A",
            Text(finding.severity, style=severity_style),  # Apply style to severity
            finding.description,
            confidence_text,
            style=None,
        )

    return table


def format_repository_table(repositories: List[Dict[str, Any]]) -> Table:
    """Format repositories as a rich table.

    Args:
        repositories: List of repository data to display

    Returns:
        Formatted table
    """
    table = Table(
        title="Repositories",
        box=ROUNDED,
        highlight=True,
        title_style="bold cyan",
        title_justify="center",
        expand=True,
    )

    # Define columns
    table.add_column("ID", style="dim")
    table.add_column("Name", style="cyan")
    table.add_column("Files", style="blue")
    table.add_column("Source", style="green")
    table.add_column("Ingested At", style="yellow")

    # Add rows
    for repo in repositories:
        repo_id = str(repo.get("id", "N/A"))
        name = repo.get("name", "Unknown")
        file_count = str(repo.get("files", 0))
        source = "GitHub" if "GitHubRepository" in repo.get("labels", []) else "Local"

        ingested_at = repo.get("ingested_at", "")
        if ingested_at:
            try:
                # Convert ISO timestamp to readable format
                dt = datetime.fromisoformat(ingested_at.replace("Z", "+00:00"))
                ingested_at = dt.strftime("%Y-%m-%d %H:%M")
            except ValueError:
                # Failed to parse timestamp, keep original
                pass

        table.add_row(repo_id, name, file_count, source, ingested_at)

    return table


def format_panel(
    content: Union[str, Text],
    title: Optional[str] = None,
    style: str = "cyan",
    expand: bool = False,
) -> Panel:
    """Format content in a rich panel.

    Args:
        content: Content to display in the panel
        title: Optional title for the panel
        style: Style for the panel
        expand: Whether to expand the panel to the full width

    Returns:
        Formatted panel
    """
    return Panel(
        content, title=title, style=style, expand=expand, border_style="bright_blue"
    )


def format_investigation_table(investigations: List[Dict[str, Any]]) -> Table:
    """Format investigations as a rich table.

    Args:
        investigations: List of investigation data to display

    Returns:
        Formatted table
    """
    table = Table(
        title="Investigations",
        box=ROUNDED,
        highlight=True,
        title_style="bold cyan",
        title_justify="center",
        expand=True,
    )

    # Define columns
    table.add_column("ID", style="dim")
    table.add_column("Title", style="cyan")
    table.add_column("Status", style="bold")
    table.add_column("Findings", style="yellow")
    table.add_column("Created At", style="blue")

    # Add rows
    for inv in investigations:
        inv_id = inv.get("id", "N/A")
        title = inv.get("title", "Untitled")

        status = inv.get("status", "Unknown")
        status_style = {
            "In Progress": "bold yellow",
            "Completed": "bold green",
            "Failed": "bold red",
            "Pending": "blue",
        }.get(status, "white")

        finding_count = str(inv.get("finding_count", 0))

        created_at = inv.get("created_at", "")
        if created_at:
            try:
                # Convert ISO timestamp to readable format
                dt = datetime.fromisoformat(created_at.replace("Z", "+00:00"))
                created_at = dt.strftime("%Y-%m-%d %H:%M")
            except ValueError:
                # Failed to parse timestamp, keep original
                pass

        table.add_row(
            inv_id, title, Text(status, style=status_style), finding_count, created_at
        )

    return table

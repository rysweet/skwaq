"""Command parsers for the Skwaq CLI."""

import argparse
from typing import Optional

from .base import SkwaqArgumentParser

# Analyze command removed


def register_repository_parser(parser: SkwaqArgumentParser) -> None:
    """Register the repository command parser.

    Args:
        parser: Main argument parser
    """
    repo_parser = parser.create_command_parser("repo", "Manage code repositories")

    repo_subparsers = repo_parser.add_subparsers(
        dest="repo_command", help="Repository command"
    )

    # List repositories
    list_parser = repo_subparsers.add_parser("list", help="List all repositories")

    list_parser.add_argument(
        "--format",
        "-f",
        choices=["table", "json"],
        default="table",
        help="Output format",
    )

    # Add local repository
    add_parser = repo_subparsers.add_parser("add", help="Add a local repository")

    add_parser.add_argument("path", help="Path to the local repository")

    add_parser.add_argument(
        "--include",
        action="append",
        help="File pattern to include (glob format, can specify multiple)",
    )

    add_parser.add_argument(
        "--exclude",
        action="append",
        help="File pattern to exclude (glob format, can specify multiple)",
    )

    # Add GitHub repository
    github_parser = repo_subparsers.add_parser("github", help="Add a GitHub repository")

    github_parser.add_argument("url", help="GitHub repository URL")

    github_parser.add_argument("--token", "-t", help="GitHub personal access token")

    github_parser.add_argument(
        "--branch", "-b", help="Branch to clone (defaults to default branch)"
    )

    github_parser.add_argument(
        "--include",
        action="append",
        help="File pattern to include (glob format, can specify multiple)",
    )

    github_parser.add_argument(
        "--exclude",
        action="append",
        help="File pattern to exclude (glob format, can specify multiple)",
    )

    # Delete repository
    delete_parser = repo_subparsers.add_parser("delete", help="Delete a repository")

    delete_parser.add_argument("id", help="Repository ID to delete")

    delete_parser.add_argument(
        "--force", "-f", action="store_true", help="Force deletion without confirmation"
    )


# Investigation command moved to workflow commands


def register_ingest_parser(parser: SkwaqArgumentParser) -> None:
    """Register the ingest command parser.

    Args:
        parser: Main argument parser
    """
    ingest_parser = parser.create_command_parser(
        "ingest", "Ingest data into the system"
    )

    ingest_parser.add_argument(
        "type", choices=["repo", "kb", "cve"], help="Type of data to ingest"
    )

    ingest_parser.add_argument("source", help="Path to the source to ingest")

    ingest_parser.add_argument(
        "--parse-only",
        action="store_true",
        help="Only parse the codebase without LLM summarization",
    )

    ingest_parser.add_argument(
        "--threads",
        type=int,
        default=3,
        help="Maximum number of parallel threads for processing",
    )

    ingest_parser.add_argument(
        "--branch", help="Git branch to clone (for repository URLs)"
    )


def register_config_parser(parser: SkwaqArgumentParser) -> None:
    """Register the config command parser.

    Args:
        parser: Main argument parser
    """
    config_parser = parser.create_command_parser("config", "Manage configuration")

    config_subparsers = config_parser.add_subparsers(
        dest="config_command", help="Configuration command"
    )

    # Show configuration
    show_parser = config_subparsers.add_parser(
        "show", help="Show current configuration"
    )

    show_parser.add_argument(
        "--path",
        "-p",
        help="Show configuration at specific path (e.g., openai.api_key)",
    )

    show_parser.add_argument(
        "--format", "-f", choices=["text", "json"], default="text", help="Output format"
    )

    # Set configuration value
    set_parser = config_subparsers.add_parser("set", help="Set configuration value")

    set_parser.add_argument("path", help="Configuration path (e.g., openai.api_key)")

    set_parser.add_argument("value", help="Configuration value")

    # Reset configuration
    reset_parser = config_subparsers.add_parser(
        "reset", help="Reset configuration to defaults"
    )

    reset_parser.add_argument(
        "--force", "-f", action="store_true", help="Force reset without confirmation"
    )

    # Check configuration
    check_parser = config_subparsers.add_parser(
        "check", help="Check configuration for required values and connectivity"
    )

    check_parser.add_argument(
        "--fix",
        "-f",
        action="store_true",
        help="Attempt to fix configuration issues interactively",
    )


def register_gui_parser(parser: SkwaqArgumentParser) -> None:
    """Register the GUI command parser.

    Args:
        parser: Main argument parser
    """
    gui_parser = parser.create_command_parser(
        "gui", "Launch the graphical user interface"
    )

    gui_parser.add_argument(
        "--no-browser", action="store_true", help="Don't open browser automatically"
    )


def register_workflow_parsers(parser: SkwaqArgumentParser) -> None:
    """Register workflow-related command parsers.

    Args:
        parser: Main argument parser
    """
    # QA workflow
    qa_parser = parser.create_command_parser("qa", "Run interactive QA workflow")

    qa_parser.add_argument("--repo", "-r", help="Repository ID to analyze")

    qa_parser.add_argument(
        "--investigation", "-i", help="Investigation ID to associate with the workflow"
    )

    # Guided inquiry workflow
    inquiry_parser = parser.create_command_parser(
        "inquiry", "Run guided inquiry workflow"
    )

    inquiry_parser.add_argument("--repo", "-r", help="Repository ID to analyze")

    inquiry_parser.add_argument(
        "--investigation", "-i", help="Investigation ID to associate with the workflow"
    )

    inquiry_parser.add_argument(
        "--prompt", "-p", help="Initial prompt to start the inquiry"
    )

    # Tool workflow
    tool_parser = parser.create_command_parser("tool", "Run external tool workflow")

    tool_parser.add_argument("tool_name", help="Name of the tool to run")

    tool_parser.add_argument("--repo", "-r", help="Repository ID to analyze")

    tool_parser.add_argument(
        "--args", "-a", help="Tool-specific arguments (JSON format)"
    )

    # Vulnerability research workflow
    research_parser = parser.create_command_parser(
        "research", "Run vulnerability research workflow"
    )

    research_parser.add_argument("--repo", "-r", help="Repository ID to analyze")

    research_parser.add_argument("--cve", "-c", help="CVE ID to research")

    research_parser.add_argument(
        "--investigation", "-i", help="Investigation ID to associate with the workflow"
    )

    # Sources and Sinks workflow
    sources_and_sinks_parser = parser.create_command_parser(
        "sources-and-sinks", "Run sources and sinks analysis workflow"
    )

    sources_and_sinks_parser.add_argument(
        "--investigation",
        "-i",
        required=True,
        help="Investigation ID to analyze (required)",
    )

    sources_and_sinks_parser.add_argument(
        "--format",
        "-f",
        choices=["markdown", "json"],
        default="markdown",
        help="Output format for the report",
    )

    sources_and_sinks_parser.add_argument(
        "--output",
        "-o",
        help="Output file path (default: reports/sources_and_sinks_{investigation_id}.{format})",
    )

    # Investigations workflow (moved from top-level command)
    investigation_parser = parser.create_command_parser(
        "investigations", "Manage vulnerability investigations"
    )

    investigation_subparsers = investigation_parser.add_subparsers(
        dest="investigation_command", help="Investigation command"
    )

    # List investigations
    list_parser = investigation_subparsers.add_parser(
        "list", help="List all investigations"
    )

    list_parser.add_argument(
        "--format",
        "-f",
        choices=["table", "json"],
        default="table",
        help="Output format",
    )

    # Create investigation
    create_parser = investigation_subparsers.add_parser(
        "create", help="Create a new investigation"
    )

    create_parser.add_argument("title", help="Investigation title")

    create_parser.add_argument(
        "--repo", "-r", help="Repository ID to associate with the investigation"
    )

    create_parser.add_argument("--description", "-d", help="Investigation description")

    # Show investigation details
    show_parser = investigation_subparsers.add_parser(
        "show", help="Show investigation details"
    )

    show_parser.add_argument("id", help="Investigation ID")

    show_parser.add_argument(
        "--format", "-f", choices=["text", "json"], default="text", help="Output format"
    )

    # Delete investigation
    delete_parser = investigation_subparsers.add_parser(
        "delete", help="Delete an investigation"
    )

    delete_parser.add_argument("id", help="Investigation ID to delete")

    delete_parser.add_argument(
        "--force", "-f", action="store_true", help="Force deletion without confirmation"
    )

    # Visualize investigation
    visualize_parser = investigation_subparsers.add_parser(
        "visualize", help="Generate visualization of an investigation"
    )

    visualize_parser.add_argument("id", help="Investigation ID to visualize")

    visualize_parser.add_argument(
        "--format",
        "-f",
        choices=["html", "json", "svg"],
        default="html",
        help="Visualization format",
    )

    visualize_parser.add_argument(
        "--output", "-o", help="Output file path (default: investigation-{id}.{format})"
    )

    visualize_parser.add_argument(
        "--include-findings",
        action="store_true",
        help="Include finding nodes in visualization",
    )

    visualize_parser.add_argument(
        "--include-vulnerabilities",
        action="store_true",
        help="Include vulnerability nodes in visualization",
    )

    visualize_parser.add_argument(
        "--include-files",
        action="store_true",
        help="Include file nodes in visualization",
    )

    visualize_parser.add_argument(
        "--max-nodes",
        type=int,
        default=100,
        help="Maximum number of nodes to include in visualization",
    )


def register_all_parsers(parser: SkwaqArgumentParser) -> None:
    """Register all command parsers.

    Args:
        parser: Main argument parser
    """
    register_repository_parser(parser)
    register_ingest_parser(parser)
    register_config_parser(parser)
    register_gui_parser(parser)
    register_workflow_parsers(parser)

"""Command handlers for workflow-related commands."""

import asyncio
import json
import os
import time
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional

from ...db.neo4j_connector import Neo4jConnector, get_connector
from ...db.schema import RelationshipTypes
from ...workflows.guided_inquiry import GuidedInquiryWorkflow
from ...workflows.qa_workflow import QAWorkflow
from ...workflows.sources_and_sinks import SourcesAndSinksWorkflow
from ...workflows.tool_invocation import ToolInvocationWorkflow
from ...workflows.vulnerability_research import VulnerabilityResearchWorkflow
from ..ui.console import console, error, info, success
from ..ui.formatters import (
    format_findings_table,
    format_investigation_table,
    format_panel,
)
from ..ui.progress import create_status_indicator
from ..ui.prompts import prompt_for_confirmation, prompt_for_input
from .base import CommandHandler, handle_command_error


class QACommandHandler(CommandHandler):
    """Handler for the Q&A workflow command."""

    @handle_command_error
    async def handle(self) -> int:
        """Handle the Q&A command.

        Returns:
            Exit code (0 for success, non-zero for errors)
        """
        repo_id = getattr(self.args, "repo", None)
        investigation_id = getattr(self.args, "investigation", None)

        # Create QA workflow
        workflow = QAWorkflow()

        console.print(
            format_panel(
                "Starting interactive Q&A session. Ask questions about security vulnerabilities, "
                "coding practices, or specific code patterns. Type 'exit' to quit.",
                title="Q&A Workflow",
                style="cyan",
            )
        )

        # Initialize the workflow
        await workflow.initialize(repo_id, investigation_id)

        # Start interactive session
        try:
            while True:
                question = prompt_for_input("\nQuestion:")

                if question.lower() in ["exit", "quit", "q"]:
                    break

                with create_status_indicator(
                    "[bold blue]Thinking...", spinner="dots"
                ) as status:
                    answer = await workflow.process_question(question)
                    status.update("[bold green]Answer ready!")

                console.print(format_panel(answer, title="Answer", style="green"))
        finally:
            # Clean up
            await workflow.cleanup()

        success("Q&A session completed")
        return 0


class GuidedInquiryCommandHandler(CommandHandler):
    """Handler for the guided inquiry workflow command."""

    @handle_command_error
    async def handle(self) -> int:
        """Handle the guided inquiry command.

        Returns:
            Exit code (0 for success, non-zero for errors)
        """
        repo_id = getattr(self.args, "repo", None)
        investigation_id = getattr(self.args, "investigation", None)
        prompt = getattr(self.args, "prompt", None)

        # Create guided inquiry workflow
        workflow = GuidedInquiryWorkflow()

        console.print(
            format_panel(
                "Starting guided vulnerability assessment. You will be guided through "
                "a structured process to discover and analyze potential vulnerabilities.",
                title="Guided Inquiry Workflow",
                style="cyan",
            )
        )

        # Initialize the workflow
        with create_status_indicator(
            "[bold blue]Initializing workflow...", spinner="dots"
        ) as status:
            inquiry_id = await workflow.initialize(repo_id, investigation_id)
            status.update("[bold green]Workflow initialized!")

        # Start guided process
        try:
            # Start with initial prompt if provided
            if prompt:
                with create_status_indicator(
                    "[bold blue]Processing initial prompt...", spinner="dots"
                ) as status:
                    result = await workflow.start_inquiry(prompt)
                    status.update("[bold green]Initial processing complete!")

                console.print(
                    format_panel(result, title="Initial Assessment", style="green")
                )

            # Continue with interactive process
            while True:
                next_step = await workflow.get_next_step()

                if next_step is None:
                    # Workflow is complete
                    break

                console.print(
                    format_panel(
                        next_step["prompt"], title=next_step["title"], style="cyan"
                    )
                )

                # Get user input if needed
                if next_step["requires_input"]:
                    user_input = prompt_for_input("\nYour response:")
                else:
                    user_input = None

                with create_status_indicator(
                    "[bold blue]Processing...", spinner="dots"
                ) as status:
                    result = await workflow.process_step(next_step["id"], user_input)
                    status.update("[bold green]Step completed!")

                console.print(format_panel(result, title="Results", style="green"))

                # Check if user wants to continue
                if not await workflow.should_continue():
                    break
        finally:
            # Generate final report
            with create_status_indicator(
                "[bold blue]Generating final report...", spinner="dots"
            ) as status:
                report = await workflow.generate_report()
                status.update("[bold green]Report generated!")

            console.print(
                format_panel(report, title="Final Assessment Report", style="green")
            )

            # Clean up
            await workflow.cleanup()

        success(f"Guided inquiry completed. Investigation ID: {inquiry_id}")
        return 0


class ToolCommandHandler(CommandHandler):
    """Handler for the tool workflow command."""

    @handle_command_error
    async def handle(self) -> int:
        """Handle the tool command.

        Returns:
            Exit code (0 for success, non-zero for errors)
        """
        tool_name = self.args.tool_name
        repo_id = getattr(self.args, "repo", None)
        tool_args = getattr(self.args, "args", None)

        # Parse tool arguments if provided
        tool_arguments = {}
        if tool_args:
            try:
                tool_arguments = json.loads(tool_args)
            except json.JSONDecodeError:
                error(f"Invalid tool arguments: {tool_args}")
                info("Tool arguments must be a valid JSON string")
                return 1

        # Create tool invocation workflow
        workflow = ToolInvocationWorkflow()

        console.print(
            format_panel(
                f"Executing tool: {tool_name}",
                title="Tool Invocation Workflow",
                style="cyan",
            )
        )

        # Initialize the workflow
        with create_status_indicator(
            "[bold blue]Initializing tool...", spinner="dots"
        ) as status:
            initialized = await workflow.initialize(tool_name, repo_id)
            if not initialized:
                status.update("[bold red]Tool initialization failed!")
                error(f"Failed to initialize tool: {tool_name}")
                return 1
            status.update("[bold green]Tool initialized!")

        # Execute the tool
        try:
            with create_status_indicator(
                f"[bold blue]Running {tool_name}...", spinner="dots"
            ) as status:
                result = await workflow.execute_tool(tool_arguments)
                status.update("[bold green]Tool execution complete!")

            if isinstance(result, str):
                console.print(format_panel(result, title="Tool Output", style="green"))
            else:
                console.print_json(json.dumps(result, indent=2))

            return 0
        except Exception as e:
            error(f"Tool execution failed: {str(e)}")
            return 1
        finally:
            # Clean up
            await workflow.cleanup()


class VulnerabilityResearchCommandHandler(CommandHandler):
    """Handler for the vulnerability research workflow command."""

    @handle_command_error
    async def handle(self) -> int:
        """Handle the vulnerability research command.

        Returns:
            Exit code (0 for success, non-zero for errors)
        """
        repo_id = getattr(self.args, "repo", None)
        cve_id = getattr(self.args, "cve", None)
        investigation_id = getattr(self.args, "investigation", None)

        if not repo_id:
            error("Repository ID is required for vulnerability research")
            return 1

        # Create vulnerability research workflow
        workflow = VulnerabilityResearchWorkflow()

        console.print(
            format_panel(
                f"Starting vulnerability research on repository ID: {repo_id}",
                title="Vulnerability Research Workflow",
                style="cyan",
            )
        )

        # Initialize the workflow
        with create_status_indicator(
            "[bold blue]Initializing research...", spinner="dots"
        ) as status:
            research_id = await workflow.initialize(repo_id, investigation_id)
            status.update("[bold green]Research initialized!")

        # Start the research process
        try:
            # Focus on specific CVE if provided
            if cve_id:
                with create_status_indicator(
                    f"[bold blue]Researching CVE {cve_id}...", spinner="dots"
                ) as status:
                    cve_result = await workflow.research_cve(cve_id)
                    status.update("[bold green]CVE research complete!")

                console.print(
                    format_panel(
                        cve_result, title=f"CVE {cve_id} Research", style="green"
                    )
                )

            # Perform comprehensive analysis
            with create_status_indicator(
                "[bold blue]Analyzing repository for vulnerabilities...", spinner="dots"
            ) as status:
                analysis_result = await workflow.analyze_repository()
                status.update("[bold green]Analysis complete!")

            console.print(
                format_panel(
                    f"Found {len(analysis_result.get('findings', []))} potential vulnerabilities",
                    title="Analysis Summary",
                    style="cyan",
                )
            )

            # Display findings
            for i, finding in enumerate(analysis_result.get("findings", []), 1):
                console.print(
                    format_panel(
                        f"Type: {finding.get('type')}\n"
                        f"Severity: {finding.get('severity')}\n"
                        f"Description: {finding.get('description')}\n"
                        f"Location: {finding.get('file_path')}:{finding.get('line_number', 'N/A')}\n\n"
                        f"Remediation: {finding.get('remediation')}",
                        title=f"Finding {i}: {finding.get('vulnerability_type')}",
                        style=(
                            "yellow"
                            if finding.get("severity") in ["High", "Critical"]
                            else "green"
                        ),
                    )
                )

            # Generate final report
            with create_status_indicator(
                "[bold blue]Generating report...", spinner="dots"
            ) as status:
                report = await workflow.generate_report()
                status.update("[bold green]Report generated!")

            # Save report to file
            report_path = f"vulnerability_report_{research_id}.md"
            with open(report_path, "w") as f:
                f.write(report)

            success(f"Vulnerability research completed. Report saved to: {report_path}")

            # Suggest GitHub issue creation if findings were detected
            if analysis_result.get("findings", []):
                info("To create GitHub issues for these findings, use the 'gh' command")

            return 0
        except Exception as e:
            error(f"Vulnerability research failed: {str(e)}")
            return 1
        finally:
            # Clean up
            await workflow.cleanup()


"""Command handlers for investigation management."""


class SourcesAndSinksCommandHandler(CommandHandler):
    """Handler for the sources and sinks workflow command."""

    @handle_command_error
    async def handle(self) -> int:
        """Handle the sources and sinks command.

        Returns:
            Exit code (0 for success, non-zero for errors)
        """
        investigation_id = getattr(self.args, "investigation", None)
        output_format = getattr(self.args, "format", "markdown")
        output_file = getattr(self.args, "output", None)

        if not investigation_id:
            error("Investigation ID is required for sources and sinks analysis")
            return 1

        # Create the sources and sinks workflow
        from ...core.openai_client import get_openai_client

        # Initialize OpenAI client
        try:
            openai_client = get_openai_client(async_mode=True)
        except Exception as e:
            error(f"Failed to initialize OpenAI client: {str(e)}")
            return 1

        workflow = SourcesAndSinksWorkflow(
            llm_client=openai_client, investigation_id=investigation_id
        )

        console.print(
            format_panel(
                f"Starting sources and sinks analysis on investigation ID: {investigation_id}",
                title="Sources and Sinks Analysis Workflow",
                style="cyan",
            )
        )

        try:
            # Run the workflow
            with create_status_indicator(
                "[bold blue]Running sources and sinks analysis...", spinner="dots"
            ) as status:
                result = await workflow.run()
                status.update("[bold green]Analysis complete!")

            # Print summary
            console.print(
                format_panel(
                    f"Found {len(result.sources)} sources, {len(result.sinks)} sinks, and "
                    f"{len(result.data_flow_paths)} data flow paths",
                    title="Analysis Summary",
                    style="green",
                )
            )

            # Save the results to a file if output is specified
            if output_file:
                output_path = output_file
            else:
                output_dir = "reports"
                os.makedirs(output_dir, exist_ok=True)
                output_path = os.path.join(
                    output_dir, f"sources_and_sinks_{investigation_id}.{output_format}"
                )

            with create_status_indicator(
                f"[bold blue]Saving results to {output_path}...", spinner="dots"
            ) as status:
                if output_format == "json":
                    with open(output_path, "w") as f:
                        f.write(result.to_json())
                else:  # markdown
                    with open(output_path, "w") as f:
                        f.write(result.to_markdown())
                status.update(f"[bold green]Results saved to {output_path}!")

            # Display sources
            if result.sources:
                console.print("\n[bold cyan]Sources Identified:[/bold cyan]")
                for i, source in enumerate(
                    result.sources[:5], 1
                ):  # Show only first 5 for brevity
                    console.print(
                        f"{i}. [yellow]{source.name}[/yellow] ({source.source_type.value}) - {source.description[:50]}..."
                    )

                if len(result.sources) > 5:
                    console.print(f"... and {len(result.sources) - 5} more sources")

            # Display sinks
            if result.sinks:
                console.print("\n[bold cyan]Sinks Identified:[/bold cyan]")
                for i, sink in enumerate(
                    result.sinks[:5], 1
                ):  # Show only first 5 for brevity
                    console.print(
                        f"{i}. [yellow]{sink.name}[/yellow] ({sink.sink_type.value}) - {sink.description[:50]}..."
                    )

                if len(result.sinks) > 5:
                    console.print(f"... and {len(result.sinks) - 5} more sinks")

            # Display data flow paths (potential vulnerabilities)
            if result.data_flow_paths:
                console.print(
                    "\n[bold red]Potential Data Flow Vulnerabilities:[/bold red]"
                )
                for i, path in enumerate(
                    result.data_flow_paths[:3], 1
                ):  # Show only first 3 for brevity
                    console.print(
                        format_panel(
                            f"Source: {path.source_node.name} ({path.source_node.source_type.value})\n"
                            f"Sink: {path.sink_node.name} ({path.sink_node.sink_type.value})\n"
                            f"Impact: {path.impact.value}\n"
                            f"Description: {path.description}\n"
                            f"Recommendations: {', '.join(path.recommendations[:2])}...",
                            title=f"Vulnerability {i}: {path.vulnerability_type}",
                            style="red" if path.impact.value == "high" else "yellow",
                        )
                    )

                if len(result.data_flow_paths) > 3:
                    console.print(
                        f"... and {len(result.data_flow_paths) - 3} more potential vulnerabilities"
                    )

            success(
                f"Sources and sinks analysis completed. Results saved to: {output_path}"
            )
            return 0

        except Exception as e:
            error(f"Sources and sinks analysis failed: {str(e)}")
            return 1


class InvestigationCommandHandler(CommandHandler):
    """Handler for investigation commands."""

    @handle_command_error
    async def handle(self) -> int:
        """Handle the investigation command.

        Returns:
            Exit code (0 for success, non-zero for errors)
        """
        if (
            not hasattr(self.args, "investigation_command")
            or not self.args.investigation_command
        ):
            error("No investigation command specified")
            return 1

        # Dispatch to appropriate subcommand handler
        if self.args.investigation_command == "list":
            return await self._handle_list()
        elif self.args.investigation_command == "create":
            return await self._handle_create()
        elif self.args.investigation_command == "show":
            return await self._handle_show()
        elif self.args.investigation_command == "delete":
            return await self._handle_delete()
        elif self.args.investigation_command == "visualize":
            return await self._handle_visualize()
        elif self.args.investigation_command == "check-ast":
            return await self._handle_check_ast()
        elif self.args.investigation_command == "summarize-ast":
            return await self._handle_summarize_ast()
        else:
            error(f"Unknown investigation command: {self.args.investigation_command}")
            return 1
            
    async def _handle_check_ast(self) -> int:
        """Handle the check-ast command.

        Returns:
            Exit code (0 for success, non-zero for errors)
        """
        investigation_id = self.args.id
        
        # Verify investigation exists
        investigation = await self._get_investigation(investigation_id)
        
        if not investigation:
            error(f"Investigation not found: {investigation_id}")
            return 1
        
        with create_status_indicator(
            f"[bold blue]Checking AST nodes and summaries for investigation {investigation_id}...",
            spinner="dots",
        ) as status:
            try:
                # Import the AST visualizer
                from ...visualization.ast_visualizer import ASTVisualizer
                
                # Create the visualizer and check AST summaries
                visualizer = ASTVisualizer()
                counts = visualizer.check_ast_summaries(investigation_id)
                
                status.update(f"[bold green]Check completed for investigation {investigation_id}")
                
                # Display the results
                console.print(
                    format_panel(
                        f"AST Nodes: {counts['ast_count']}\n"
                        f"AST Nodes with code: {counts['ast_with_code_count']}\n"
                        f"Summary count: {counts['summary_count']}\n"
                        f"AST nodes with summary: {counts['ast_with_summary_count']}",
                        title=f"AST Summary for Investigation: {investigation['title']}",
                        style="cyan",
                    )
                )
                
                # Show recommendations if there are AST nodes without summaries
                if counts['ast_count'] > counts['ast_with_summary_count']:
                    diff = counts['ast_count'] - counts['ast_with_summary_count']
                    info(f"Found {diff} AST nodes without summaries.")
                    info("To generate summaries, run: skwaq investigations summarize-ast " + investigation_id)
                
                return 0
                
            except Exception as e:
                status.update("[bold red]Error checking AST nodes and summaries!")
                error(f"Error: {str(e)}")
                import traceback
                traceback.print_exc()
                return 1
                
    async def _handle_summarize_ast(self) -> int:
        """Handle the summarize-ast command.

        Returns:
            Exit code (0 for success, non-zero for errors)
        """
        investigation_id = self.args.id
        limit = getattr(self.args, "limit", 100)
        batch_size = getattr(self.args, "batch_size", 10)
        max_concurrent = getattr(self.args, "max_concurrent", 3)
        
        # Verify investigation exists
        investigation = await self._get_investigation(investigation_id)
        
        if not investigation:
            error(f"Investigation not found: {investigation_id}")
            return 1
        
        with create_status_indicator(
            f"[bold blue]Generating AST summaries for investigation {investigation_id}...",
            spinner="dots",
        ) as status:
            try:
                # First check the current state
                from ...visualization.ast_visualizer import ASTVisualizer
                visualizer = ASTVisualizer()
                
                counts_before = visualizer.check_ast_summaries(investigation_id)
                status.update(f"[bold blue]Found {counts_before['ast_count']} AST nodes, {counts_before['ast_with_summary_count']} with summaries")
                
                # If all nodes already have summaries, we're done
                if counts_before['ast_count'] <= counts_before['ast_with_summary_count']:
                    status.update("[bold green]All AST nodes already have summaries!")
                    success("All AST nodes already have summaries!")
                    return 0
                
                # Initialize OpenAI client
                from ...core.openai_client import get_openai_client
                openai_client = await get_openai_client(async_mode=True)
                
                # Use the generate_ast_summaries function
                results = await self._generate_ast_summaries(
                    investigation_id=investigation_id,
                    limit=limit,
                    openai_client=openai_client
                )
                
                # Get final counts
                counts_after = visualizer.check_ast_summaries(investigation_id)
                status.update(f"[bold green]Generation completed: {results['created']} summaries created")
                
                # Display summary
                console.print(
                    format_panel(
                        f"AST Nodes processed: {results['processed']}\n"
                        f"Summaries created: {results['created']}\n\n"
                        f"Before: {counts_before['ast_with_summary_count']} of {counts_before['ast_count']} nodes had summaries\n"
                        f"After: {counts_after['ast_with_summary_count']} of {counts_after['ast_count']} nodes have summaries",
                        title=f"AST Summary Generation: {investigation['title']}",
                        style="green",
                    )
                )
                
                success(f"Generated {results['created']} new AST summaries.")
                if counts_after['ast_count'] > counts_after['ast_with_summary_count']:
                    diff = counts_after['ast_count'] - counts_after['ast_with_summary_count']
                    info(f"There are still {diff} AST nodes without summaries.")
                    info(f"Use --limit {diff} to generate the remaining summaries.")
                
                return 0
                
            except Exception as e:
                status.update("[bold red]Error generating AST summaries!")
                error(f"Error: {str(e)}")
                import traceback
                traceback.print_exc()
                return 1

    async def _handle_list(self) -> int:
        """Handle the list command.

        Returns:
            Exit code (0 for success, non-zero for errors)
        """
        output_format = getattr(self.args, "format", "table")

        with create_status_indicator(
            "[bold blue]Fetching investigation list...", spinner="dots"
        ) as status:
            investigations = await self._get_investigations()
            status.update("[bold green]Investigations retrieved!")

        if not investigations:
            info("No investigations found.")
            return 0

        if output_format == "json":
            console.print_json(json.dumps(investigations, indent=2))
        else:
            console.print(format_investigation_table(investigations))

        return 0

    async def _handle_create(self) -> int:
        """Handle the create command.

        Returns:
            Exit code (0 for success, non-zero for errors)
        """
        title = self.args.title
        repo_id = self.args.repo
        description = self.args.description or ""

        # Verify repository exists if specified
        if repo_id:
            connector = get_connector()
            repo = connector.run_query(
                "MATCH (r:Repository) WHERE id(r) = $id RETURN r.name as name",
                {"id": int(repo_id)},
            )

            if not repo:
                error(f"Repository not found: {repo_id}")
                return 1

        # Generate investigation ID
        investigation_id = f"inv-{uuid.uuid4().hex[:8]}"

        # Create investigation
        with create_status_indicator(
            f"[bold blue]Creating investigation '{title}'...", spinner="dots"
        ) as status:
            connector = get_connector()

            # Create investigation node
            investigation_props = {
                "id": investigation_id,
                "title": title,
                "description": description,
                "status": "In Progress",
                "created_at": datetime.now().isoformat(),
                "updated_at": datetime.now().isoformat(),
                "finding_count": 0,
            }

            investigation_node_id = connector.create_node(
                labels=["Investigation"], properties=investigation_props
            )

            # Link to repository if specified
            if repo_id:
                connector.create_relationship(
                    int(repo_id), investigation_node_id, "HAS_INVESTIGATION"
                )

            status.update(f"[bold green]Investigation '{title}' created!")

        success(f"Investigation created successfully: {title}")
        info(f"Investigation ID: {investigation_id}")

        return 0

    async def _handle_show(self) -> int:
        """Handle the show command.

        Returns:
            Exit code (0 for success, non-zero for errors)
        """
        investigation_id = self.args.id
        output_format = self.args.format

        # Get investigation details
        with create_status_indicator(
            f"[bold blue]Fetching investigation {investigation_id}...", spinner="dots"
        ) as status:
            investigation = await self._get_investigation(investigation_id)

            if not investigation:
                status.update(f"[bold red]Investigation {investigation_id} not found!")
                error(f"Investigation not found: {investigation_id}")
                return 1

            # Get findings
            findings = await self._get_investigation_findings(investigation_id)
            status.update(f"[bold green]Investigation {investigation_id} retrieved!")

        # Display investigation details
        if output_format == "json":
            result = {"investigation": investigation, "findings": findings}
            console.print_json(json.dumps(result, indent=2))
        else:
            # Display investigation details
            console.print(
                format_panel(
                    f"Title: {investigation['title']}\n"
                    f"Status: {investigation['status']}\n"
                    f"Created: {investigation['created_at']}\n"
                    f"Description: {investigation['description'] or 'No description'}\n"
                    f"Findings: {len(findings)}",
                    title=f"Investigation: {investigation_id}",
                    style="cyan",
                )
            )

            # Display findings if any
            if findings:
                console.print(format_findings_table(findings))
            else:
                info("No findings associated with this investigation.")

        return 0

    async def _handle_delete(self) -> int:
        """Handle the delete command.

        Returns:
            Exit code (0 for success, non-zero for errors)
        """
        investigation_id = self.args.id
        force = self.args.force

        # Verify investigation exists
        investigation = await self._get_investigation(investigation_id)

        if not investigation:
            error(f"Investigation not found: {investigation_id}")
            return 1

        # Confirm deletion
        if not force:
            confirmed = prompt_for_confirmation(
                f"Are you sure you want to delete investigation '{investigation['title']}' (ID: {investigation_id})?"
            )

            if not confirmed:
                info("Deletion cancelled.")
                return 0

        # Delete investigation
        with create_status_indicator(
            f"[bold blue]Deleting investigation '{investigation['title']}'...",
            spinner="dots",
        ) as status:
            connector = get_connector()

            # Delete all connected nodes recursively
            connector.run_query(
                """
                MATCH (i:Investigation {id: $id})
                OPTIONAL MATCH (i)-[*1..2]-(connected)
                DETACH DELETE connected, i
                """,
                {"id": investigation_id},
            )

            status.update(
                f"[bold green]Investigation '{investigation['title']}' deleted!"
            )

        success(f"Investigation '{investigation['title']}' deleted successfully.")
        return 0

    async def _handle_visualize(self) -> int:
        """Handle the visualize command.

        Returns:
            Exit code (0 for success, non-zero for errors)
        """
        investigation_id = self.args.id
        visualization_format = self.args.format
        output_path = self.args.output
        include_findings = self.args.include_findings
        include_vulnerabilities = self.args.include_vulnerabilities
        include_files = self.args.include_files
        max_nodes = self.args.max_nodes
        
        # New AST visualization options
        visualization_type = getattr(self.args, "visualization_type", "standard")
        with_summaries = getattr(self.args, "with_summaries", False)
        generate_summaries = getattr(self.args, "generate_summaries", False)
        open_in_browser = getattr(self.args, "open", False)

        # Verify investigation exists
        investigation = await self._get_investigation(investigation_id)

        if not investigation:
            error(f"Investigation not found: {investigation_id}")
            return 1

        # Determine output path
        if not output_path:
            if visualization_type == "ast":
                output_path = f"investigation-{investigation_id}-ast.{visualization_format}"
            else:
                output_path = f"investigation-{investigation_id}.{visualization_format}"

        # If generating summaries is requested, do that first
        if visualization_type == "ast" and generate_summaries:
            with create_status_indicator(
                f"[bold blue]Generating missing AST summaries for investigation {investigation_id}...",
                spinner="dots",
            ) as status:
                try:
                    from ...visualization.ast_visualizer import ASTVisualizer
                    from ...core.openai_client import get_openai_client
                    
                    # Check current summary status
                    visualizer = ASTVisualizer()
                    counts_before = visualizer.check_ast_summaries(investigation_id)
                    
                    if counts_before['ast_count'] <= counts_before['ast_with_summary_count']:
                        status.update("[bold green]All AST nodes already have summaries!")
                    else:
                        status.update(f"[bold blue]Found {counts_before['ast_count'] - counts_before['ast_with_summary_count']} AST nodes without summaries")
                        
                        # Initialize OpenAI client
                        openai_client = await get_openai_client(async_mode=True)
                        
                        # Use the generate_ast_summaries function (will be implemented below)
                        results = await self._generate_ast_summaries(
                            investigation_id=investigation_id,
                            limit=100,  # Reasonable default
                            openai_client=openai_client
                        )
                        
                        counts_after = visualizer.check_ast_summaries(investigation_id)
                        status.update(f"[bold green]Generated {results['created']} summaries")
                        
                        # Show summary generation stats
                        info(f"Generated {results['created']} new AST summaries.")
                        if counts_after['ast_with_summary_count'] < counts_after['ast_count']:
                            info(f"{counts_after['ast_count'] - counts_after['ast_with_summary_count']} AST nodes still need summaries.")
                            info("Use 'investigations summarize-ast' command for more control.")
                
                except Exception as e:
                    status.update("[bold red]Error generating AST summaries!")
                    error(f"Error generating summaries: {str(e)}")
                    # Continue with visualization regardless of summary generation success

        # Generate visualization
        with create_status_indicator(
            f"[bold blue]Generating graph visualization for investigation {investigation_id}...",
            spinner="dots",
        ) as status:
            try:
                # Choose visualization approach based on type
                if visualization_type == "ast":
                    # Use AST visualizer for AST-focused visualization
                    from ...visualization.ast_visualizer import ASTVisualizer
                    
                    # Initialize the AST visualizer
                    visualizer = ASTVisualizer()
                    
                    # Generate the visualization
                    status.update(f"[bold blue]Creating AST visualization for investigation {investigation_id}...")
                    
                    # Use the specialized AST visualization method
                    result_path = visualizer.visualize_ast(
                        investigation_id=investigation_id,
                        include_files=include_files,
                        include_summaries=with_summaries,
                        max_nodes=max_nodes,
                        output_path=output_path,
                        title=f"AST Visualization: {investigation_id}",
                    )
                    
                    status.update(f"[bold green]AST visualization saved to {result_path}!")
                    success(f"AST visualization saved to: {result_path}")
                    
                    # Show summary counts to inform the user
                    ast_counts = visualizer.check_ast_summaries(investigation_id)
                    info(f"AST Nodes: {ast_counts['ast_count']}, AST Nodes with summaries: {ast_counts['ast_with_summary_count']}")
                    
                else:
                    # Use standard graph visualizer for regular visualization
                    from ...visualization.graph_visualizer import GraphVisualizer

                    # Initialize the graph visualizer
                    visualizer = GraphVisualizer()

                    # Get the graph data
                    status.update(
                        "[bold blue]Querying database for investigation graph data..."
                    )
                    graph_data = visualizer.get_investigation_graph(
                        investigation_id=investigation_id,
                        include_findings=include_findings,
                        include_vulnerabilities=include_vulnerabilities,
                        include_files=include_files,
                        include_sources_sinks=True,  # Always include sources and sinks for better visualization
                        max_nodes=max_nodes,
                    )

                    # Also include AST nodes for connected files if include_files is True
                    if include_files and graph_data['nodes']:
                        # Extract file nodes
                        file_nodes = [node for node in graph_data['nodes'] if node['type'] == 'File']
                        
                        if file_nodes:
                            file_ids = [node['id'] for node in file_nodes]
                            
                            # Query for AST nodes with PART_OF relationships to these files
                            connector = get_connector()
                            ast_query = """
                            MATCH (ast)-[:PART_OF]->(file)
                            WHERE elementId(file) IN $file_ids AND (ast:Function OR ast:Class OR ast:Method)
                            RETURN file.name as file_name, elementId(file) as file_id, 
                                   ast.name as ast_name, elementId(ast) as ast_id, labels(ast) as ast_labels
                            LIMIT 1000
                            """
                            
                            ast_results = connector.run_query(ast_query, {"file_ids": file_ids})
                            status.update(f"[bold blue]Found {len(ast_results)} AST nodes to include...")
                            
                            # Add AST nodes and relationships
                            node_ids = set([node['id'] for node in graph_data['nodes']])
                            
                            for ast in ast_results:
                                file_id = ast["file_id"]
                                ast_id = str(ast["ast_id"])
                                
                                # Add AST node if not already added
                                if ast_id not in node_ids:
                                    node_ids.add(ast_id)
                                    node_type = ast["ast_labels"][0] if ast["ast_labels"] else "Unknown"
                                    
                                    graph_data['nodes'].append({
                                        "id": ast_id,
                                        "label": ast["ast_name"],
                                        "type": node_type,
                                        "properties": {"file": ast["file_name"]},
                                        "color": "#8da0cb" if node_type == "Function" else 
                                                 "#e78ac3" if node_type == "Class" else
                                                 "#a6d854" if node_type == "Method" else "#999999"
                                    })
                                
                                # Add relationship in both directions
                                graph_data['links'].append({
                                    "source": str(file_id),
                                    "target": ast_id,
                                    "type": "DEFINES"
                                })
                                
                                graph_data['links'].append({
                                    "source": ast_id,
                                    "target": str(file_id),
                                    "type": "PART_OF"
                                })
                            
                            # Get AI summaries for AST nodes if with_summaries is True
                            if ast_results and with_summaries:
                                ast_ids = [ast["ast_id"] for ast in ast_results]
                                summary_query = """
                                MATCH (summary:CodeSummary)-[r]->(ast)
                                WHERE elementId(ast) IN $ast_ids
                                RETURN summary.summary as summary_text, elementId(summary) as summary_id, 
                                       elementId(ast) as ast_id, type(r) as relationship_type
                                """
                                
                                summary_results = connector.run_query(summary_query, {"ast_ids": ast_ids})
                                status.update(f"[bold blue]Found {len(summary_results)} AI summaries...")
                                
                                # Add AI summary nodes and relationships
                                for summary in summary_results:
                                    summary_id = str(summary["summary_id"])
                                    ast_id = str(summary["ast_id"])
                                    
                                    # Add summary node if not already added
                                    if summary_id not in node_ids:
                                        node_ids.add(summary_id)
                                        # Truncate summary text for label display
                                        summary_text = summary["summary_text"]
                                        short_summary = summary_text[:30] + "..." if summary_text and len(summary_text) > 30 else summary_text
                                        
                                        graph_data['nodes'].append({
                                            "id": summary_id,
                                            "label": f"Summary: {short_summary}",
                                            "type": "CodeSummary",
                                            "properties": {"summary": summary_text},
                                            "color": "#ffd92f"
                                        })
                                    
                                    # Add relationship
                                    graph_data['links'].append({
                                        "source": summary_id,
                                        "target": ast_id,
                                        "type": summary["relationship_type"]
                                    })

                    # Export in the requested format
                    status.update(
                        f"[bold blue]Generating {visualization_format} visualization..."
                    )

                    if visualization_format == "json":
                        result_path = visualizer.export_graph_as_json(
                            graph_data, output_path
                        )
                    elif visualization_format == "html":
                        result_path = visualizer.export_graph_as_html(
                            graph_data,
                            output_path,
                            title=f"Investigation Graph: {investigation_id}",
                        )
                    else:  # SVG
                        result_path = visualizer.export_graph_as_svg(
                            graph_data, output_path
                        )

                    status.update(f"[bold green]Visualization saved to {result_path}!")
                    success(f"Investigation visualization saved to: {result_path}")

                    # Show node statistics
                    node_types = {}
                    for node in graph_data['nodes']:
                        node_type = node.get('type', 'Unknown')
                        node_types[node_type] = node_types.get(node_type, 0) + 1
                    
                    node_stats = ", ".join([f"{count} {node_type}" for node_type, count in node_types.items()])
                    info(f"Graph statistics: {len(graph_data['nodes'])} nodes ({node_stats}), {len(graph_data['links'])} relationships")

                # Open in browser if requested
                if open_in_browser:
                    try:
                        import webbrowser
                        status.update("[bold blue]Opening visualization in browser...")
                        webbrowser.open(f"file://{os.path.abspath(result_path)}")
                    except Exception as e:
                        status.update("[bold yellow]Could not open browser")
                        info(f"Could not open browser: {str(e)}")

                return 0

            except ImportError:
                status.update("[bold red]Graph visualization not available!")
                error("Graph visualization functionality is not available.")
                info(
                    "This is likely because the required dependencies are not installed."
                )
                info("Install with: pip install networkx matplotlib d3-graph-viz")
                return 1

            except Exception as e:
                status.update("[bold red]Error generating visualization!")
                error(f"Error generating visualization: {str(e)}")
                return 1
                
    async def _generate_ast_summaries(
        self, investigation_id: str, limit: int = 100, openai_client: Any = None
    ) -> Dict[str, int]:
        """Generate summaries for AST nodes without summaries.
        
        Args:
            investigation_id: ID of the investigation to process
            limit: Maximum number of AST nodes to process
            openai_client: Initialized OpenAI client
            
        Returns:
            Dictionary with counts of processed and created summaries
        """
        # Set up semaphore to limit concurrent tasks
        semaphore = asyncio.Semaphore(3)  # Default concurrency
        
        # Get database connector
        connector = get_connector()
        
        # Build query to get AST nodes without summaries
        query = """
        MATCH (i:Investigation {id: $id})-[:HAS_FINDING]->(f:Finding)-[:FOUND_IN]->(file:File)
        MATCH (ast)-[:PART_OF]->(file)
        WHERE (ast:Function OR ast:Class OR ast:Method) 
        AND ast.code IS NOT NULL
        AND NOT (ast)<-[:DESCRIBES]-(:CodeSummary)
        RETURN 
            elementId(ast) as ast_id, 
            ast.name as name, 
            ast.code as code,
            labels(ast) as labels,
            elementId(file) as file_id,
            file.name as file_name,
            file.path as file_path
        LIMIT $limit
        """
        
        # Execute the query
        ast_nodes = connector.run_query(query, {"id": investigation_id, "limit": limit})
        
        if not ast_nodes:
            return {"processed": 0, "created": 0}
        
        # Create tasks for each AST node
        tasks = []
        for ast_node in ast_nodes:
            task = self._generate_single_ast_summary(ast_node, connector, openai_client, semaphore)
            tasks.append(task)
        
        # Run all tasks concurrently with semaphore limiting
        results = await asyncio.gather(*tasks)
        
        # Count successes
        processed = 0
        created = 0
        for result in results:
            if result:
                processed += 1
                if result.get("created"):
                    created += 1
        
        return {"processed": processed, "created": created}
    
    async def _generate_single_ast_summary(
        self, ast_node: Dict, connector: Any, model_client: Any, semaphore: asyncio.Semaphore
    ) -> Optional[Dict]:
        """Generate a summary for a single AST node."""
        async with semaphore:
            try:
                ast_id = ast_node["ast_id"]
                ast_name = ast_node["name"]
                ast_code = ast_node["code"]
                ast_type = ast_node["labels"][0] if ast_node["labels"] else "Unknown"
                file_name = ast_node["file_name"] or "Unknown"
                
                if not ast_code or len(ast_code.strip()) < 10:
                    return {"processed": True, "created": False, "reason": "insufficient_code"}
                
                # Create prompt
                ast_prompt = f"""
                You are analyzing a specific {ast_type} from a larger file.
                
                File name: {file_name}
                {ast_type} name: {ast_name}
                
                Your task is to create a detailed, accurate summary of this {ast_type.lower()}'s:
                1. Purpose and functionality 
                2. Parameters, return values, and important logic
                3. Role within the larger file
                4. Any potential security implications
                5. How it interacts with other components
                
                {ast_type} code:
                ```
                {ast_code}
                ```
                
                Summary:
                """
                
                # Generate summary
                summary_start_time = time.time()
                ast_summary = await model_client.get_completion(
                    ast_prompt, temperature=0.3
                )
                summary_time = time.time() - summary_start_time
                
                # Create summary node
                summary_node_id = connector.create_node(
                    "CodeSummary",
                    {
                        "summary": ast_summary,
                        "file_name": file_name,
                        "ast_node_id": ast_id,  # Store reference to AST node
                        "ast_name": ast_name,
                        "ast_type": ast_type,
                        "created_at": time.time(),
                        "generation_time": summary_time,
                        "summary_type": "ast",  # Mark this as an AST-level summary
                    },
                )
                
                # Create relationship to AST node
                connector.create_relationship(
                    summary_node_id, ast_id, RelationshipTypes.DESCRIBES
                )
                
                return {"processed": True, "created": True}
                
            except Exception as e:
                return {"processed": True, "created": False, "error": str(e)}

    async def _get_investigations(self) -> List[Dict[str, Any]]:
        """Get all investigations.

        Returns:
            List of investigation data
        """
        try:
            connector = get_connector()

            results = connector.run_query(
                """
                MATCH (i:Investigation)
                OPTIONAL MATCH (i)-[:HAS_FINDING]->(f:Finding)
                WITH i, count(f) as finding_count
                RETURN id(i) as node_id, i.id as id, i.title as title, 
                       i.status as status, i.created_at as created_at,
                       i.description as description, finding_count
                ORDER BY i.created_at DESC
                """,
                {},
            )

            return results

        except Exception as e:
            console.log(f"Error fetching investigations: {str(e)}")

            # Provide mock data for development when database isn't available
            return self._get_mock_investigations()

    async def _get_investigation(
        self, investigation_id: str
    ) -> Optional[Dict[str, Any]]:
        """Get a specific investigation.

        Args:
            investigation_id: ID of the investigation

        Returns:
            Investigation data or None if not found
        """
        try:
            connector = get_connector()

            results = connector.run_query(
                """
                MATCH (i:Investigation {id: $id})
                OPTIONAL MATCH (i)-[:HAS_FINDING]->(f:Finding)
                WITH i, count(f) as finding_count
                RETURN id(i) as node_id, i.id as id, i.title as title, 
                       i.status as status, i.created_at as created_at,
                       i.description as description, finding_count
                """,
                {"id": investigation_id},
            )

            return results[0] if results else None

        except Exception as e:
            console.log(f"Error fetching investigation: {str(e)}")

            # Provide mock data for development when database isn't available
            mock_investigations = self._get_mock_investigations()
            for inv in mock_investigations:
                if inv["id"] == investigation_id:
                    return inv

            return None

    async def _get_investigation_findings(
        self, investigation_id: str
    ) -> List[Dict[str, Any]]:
        """Get findings for a specific investigation.

        Args:
            investigation_id: ID of the investigation

        Returns:
            List of finding data
        """
        try:
            connector = get_connector()

            results = connector.run_query(
                """
                MATCH (i:Investigation {id: $id})-[:HAS_FINDING]->(f:Finding)
                RETURN id(f) as id, f.type as type, f.vulnerability_type as vulnerability_type,
                       f.description as description, f.severity as severity,
                       f.confidence as confidence, f.line_number as line_number,
                       f.matched_text as matched_text, f.remediation as remediation
                """,
                {"id": investigation_id},
            )

            # Convert database results to Finding objects
            from ...shared.finding import Finding

            findings = []
            for result in results:
                finding = Finding(
                    type=result["type"],
                    vulnerability_type=result["vulnerability_type"],
                    description=result["description"],
                    file_id=None,  # Not needed for display
                    line_number=result["line_number"],
                    matched_text=result["matched_text"],
                    severity=result["severity"],
                    confidence=result["confidence"],
                    remediation=result["remediation"],
                )
                findings.append(finding)

            return findings

        except Exception as e:
            console.log(f"Error fetching findings: {str(e)}")

            # Provide mock data for development when database isn't available
            return self._get_mock_findings()

    def _get_mock_investigations(self) -> List[Dict[str, Any]]:
        """Get mock investigation data for development.

        Returns:
            List of mock investigation data
        """
        return [
            {
                "node_id": 1,
                "id": "inv-12345678",
                "title": "Example Investigation",
                "status": "In Progress",
                "created_at": datetime.now().isoformat(),
                "description": "This is a sample investigation for development purposes.",
                "finding_count": 3,
            },
            {
                "node_id": 2,
                "id": "inv-87654321",
                "title": "Completed Analysis",
                "status": "Completed",
                "created_at": datetime.now().isoformat(),
                "description": "A completed investigation example.",
                "finding_count": 5,
            },
        ]

    def _get_mock_findings(self) -> List[Any]:
        """Get mock finding data for development.

        Returns:
            List of mock finding data
        """
        from ...shared.finding import Finding

        return [
            Finding(
                type="pattern_match",
                vulnerability_type="SQL Injection",
                description="Potential SQL injection vulnerability in database query",
                file_id=0,
                line_number=42,
                matched_text="execute(query_with_params)",
                severity="High",
                confidence=0.85,
                remediation="Use parameterized queries with placeholders instead of string concatenation.",
            ),
            Finding(
                type="semantic_analysis",
                vulnerability_type="Insecure Authentication",
                description="Weak password validation",
                file_id=0,
                line_number=123,
                matched_text="if password == stored_password:",
                severity="Medium",
                confidence=0.75,
                remediation="Use secure password hashing with a strong algorithm like bcrypt.",
            ),
            Finding(
                type="ast_analysis",
                vulnerability_type="Information Disclosure",
                description="Sensitive data exposure in error message",
                file_id=0,
                line_number=245,
                matched_text='raise Exception(f"Error connecting to {username}:{password}@{host}")',
                severity="High",
                confidence=0.9,
                remediation="Avoid including sensitive information in error messages.",
            ),
        ]
        
        
class ASTVisualizationCommandHandler(CommandHandler):
    """Handler for the AST visualization command."""

    @handle_command_error
    async def handle(self) -> int:
        """Handle the AST visualization command.

        Returns:
            Exit code (0 for success, non-zero for errors)
        """
        repo_id = self.args.repo_id
        investigation_id = self.args.investigation_id
        output_path = self.args.output
        
        with create_status_indicator(
            "[bold blue]Creating enhanced AST visualization...", spinner="dots"
        ) as status:
            try:
                # Import required modules
                from ...db.neo4j_connector import get_connector
                
                connector = get_connector()
                
                # Create graph data structure
                graph_data = {
                    "nodes": [],
                    "links": []
                }
                
                status.update("[bold blue]Querying database for visualization data...")
                
                # Get repository information if repo_id is provided
                repo_info = None
                if repo_id:
                    repo_query = """
                    MATCH (r:Repository)
                    WHERE r.ingestion_id = $repo_id OR elementId(r) = $repo_id
                    RETURN r.name as name, elementId(r) as id, r.path as path
                    """
                    repo_results = connector.run_query(repo_query, {"repo_id": repo_id})
                    if repo_results:
                        repo_info = repo_results[0]
                
                # Get investigation information if investigation_id is provided
                investigation_info = None
                if investigation_id:
                    inv_query = """
                    MATCH (i:Investigation {id: $id})
                    RETURN i.title as title, elementId(i) as id
                    """
                    inv_results = connector.run_query(inv_query, {"id": investigation_id})
                    if inv_results:
                        investigation_info = inv_results[0]
                
                # Set for tracking added node IDs
                node_ids = set()
                
                # Add root node (repository or investigation)
                root_id = "root"
                root_label = "Code Graph"
                root_type = "Root"
                
                if repo_info:
                    root_id = str(repo_info["id"])
                    root_label = f"Repository: {repo_info['name']}"
                    root_type = "Repository"
                elif investigation_info:
                    root_id = str(investigation_info["id"])
                    root_label = f"Investigation: {investigation_info['title']}"
                    root_type = "Investigation"
                
                graph_data["nodes"].append({
                    "id": root_id,
                    "label": root_label,
                    "type": root_type,
                    "color": "#ff7f0e"
                })
                node_ids.add(root_id)
                
                # Query for files
                file_query = """
                MATCH (file:File)
                """
                
                if repo_info:
                    file_query += """
                    MATCH (r:Repository)-[:CONTAINS]->(file)
                    WHERE elementId(r) = $root_id
                    """
                elif investigation_id:
                    file_query += """
                    MATCH (i:Investigation {id: $investigation_id})-[:HAS_FILE]->(file)
                    """
                else:
                    file_query += """
                    WHERE true
                    """
                
                file_query += """
                RETURN 
                    elementId(file) as file_id,
                    file.name as file_name,
                    file.path as file_path,
                    file.summary as file_summary
                LIMIT 100
                """
                
                params = {}
                if repo_info:
                    params["root_id"] = repo_info["id"]
                if investigation_id:
                    params["investigation_id"] = investigation_id
                
                file_results = connector.run_query(file_query, params)
                status.update(f"[bold blue]Found {len(file_results)} files...")
                
                # Add file nodes and connect to root
                for file in file_results:
                    file_id = str(file["file_id"])
                    
                    if file_id not in node_ids:
                        node_ids.add(file_id)
                        graph_data["nodes"].append({
                            "id": file_id,
                            "label": file["file_name"] or os.path.basename(file["file_path"] or "Unknown"),
                            "type": "File",
                            "properties": {
                                "path": file["file_path"],
                                "summary": file["file_summary"]
                            },
                            "color": "#66c2a5"
                        })
                        
                        # Connect to root
                        graph_data["links"].append({
                            "source": root_id,
                            "target": file_id,
                            "type": "CONTAINS"
                        })
                
                # Query for AST nodes connected to these files
                if file_results:
                    file_ids = [file["file_id"] for file in file_results]
                    
                    ast_query = """
                    MATCH (ast)-[:PART_OF]->(file)
                    WHERE elementId(file) IN $file_ids 
                          AND (ast:Function OR ast:Class OR ast:Method)
                    RETURN 
                        elementId(ast) as ast_id,
                        ast.name as ast_name,
                        labels(ast) as ast_labels,
                        ast.start_line as start_line,
                        ast.end_line as end_line,
                        elementId(file) as file_id
                    LIMIT 300
                    """
                    
                    ast_results = connector.run_query(ast_query, {"file_ids": file_ids})
                    status.update(f"[bold blue]Found {len(ast_results)} AST nodes...")
                    
                    # Add AST nodes and connect to files
                    for ast in ast_results:
                        ast_id = str(ast["ast_id"])
                        file_id = str(ast["file_id"])
                        
                        if ast_id not in node_ids:
                            node_ids.add(ast_id)
                            node_type = ast["ast_labels"][0] if ast["ast_labels"] else "Unknown"
                            
                            graph_data["nodes"].append({
                                "id": ast_id,
                                "label": ast["ast_name"] or "Unnamed AST Node",
                                "type": node_type,
                                "properties": {
                                    "start_line": ast["start_line"],
                                    "end_line": ast["end_line"]
                                },
                                "color": "#8da0cb" if node_type == "Function" else 
                                        "#e78ac3" if node_type == "Class" else
                                        "#a6d854" if node_type == "Method" else "#999999"
                            })
                            
                            # Connect to file
                            graph_data["links"].append({
                                "source": ast_id,
                                "target": file_id,
                                "type": "PART_OF"
                            })
                            
                            graph_data["links"].append({
                                "source": file_id,
                                "target": ast_id,
                                "type": "DEFINES"
                            })
                
                # Query for summary nodes
                summary_query = """
                MATCH (summary:CodeSummary)-[:DESCRIBES]->(target)
                WHERE elementId(target) IN $node_ids
                RETURN 
                    elementId(summary) as summary_id,
                    summary.summary as summary_text,
                    summary.summary_type as summary_type,
                    elementId(target) as target_id
                """
                
                all_ids = [node_id for node_id in node_ids]
                summary_results = connector.run_query(summary_query, {"node_ids": all_ids})
                status.update(f"[bold blue]Found {len(summary_results)} code summaries...")
                
                # Add summary nodes
                for summary in summary_results:
                    summary_id = str(summary["summary_id"])
                    target_id = str(summary["target_id"])
                    
                    if summary_id not in node_ids:
                        node_ids.add(summary_id)
                        summary_text = summary["summary_text"] or "No summary available"
                        short_summary = summary_text[:30] + "..." if len(summary_text) > 30 else summary_text
                        
                        # Determine summary type and color
                        summary_type = summary["summary_type"] or "unknown"
                        summary_color = "#ffd92f"  # Default
                        if summary_type == "file":
                            summary_color = "#fc8d62"  # Orange-red for file summaries
                        
                        graph_data["nodes"].append({
                            "id": summary_id,
                            "label": f"Summary: {short_summary}",
                            "type": "CodeSummary",
                            "properties": {
                                "summary": summary_text,
                                "summary_type": summary_type
                            },
                            "color": summary_color
                        })
                        
                        # Connect to target
                        graph_data["links"].append({
                            "source": summary_id,
                            "target": target_id,
                            "type": "DESCRIBES"
                        })
                
                # Generate HTML with the advanced interactive visualization
                if not output_path:
                    # Default output name based on source
                    if investigation_id:
                        output_path = f"investigation-{investigation_id}-visualization.html"
                    elif repo_id:
                        output_path = f"repository-{repo_id}-visualization.html"
                    else:
                        output_path = "ast-visualization.html"
                
                status.update(f"[bold blue]Creating D3.js visualization ({len(graph_data['nodes'])} nodes, {len(graph_data['links'])} links)...")
                
                # Create visualization HTML
                from ...visualization.graph_visualizer import create_interactive_html_visualization
                
                html_content = create_interactive_html_visualization(
                    graph_data,
                    title="AST Visualization with Code Summaries",
                    enable_filtering=True,
                    enable_search=True
                )
                
                # Write to file
                with open(output_path, "w") as f:
                    f.write(html_content)
                
                status.update(f"[bold green]Visualization saved to {output_path}")
                
                # Show node statistics
                node_types = {}
                for node in graph_data['nodes']:
                    node_type = node.get('type', 'Unknown')
                    node_types[node_type] = node_types.get(node_type, 0) + 1
                
                node_stats = ", ".join([f"{count} {node_type}" for node_type, count in node_types.items()])
                info(f"Graph statistics: {len(graph_data['nodes'])} nodes ({node_stats}), {len(graph_data['links'])} relationships")
                
                # Try to open in browser if GUI is available
                try:
                    import webbrowser
                    webbrowser.open(f"file://{os.path.abspath(output_path)}")
                except Exception:
                    pass  # Silently fail if browser can't be opened
                
                return 0
                
            except Exception as e:
                status.update("[bold red]Error creating visualization!")
                error(f"Error creating AST visualization: {str(e)}")
                import traceback
                traceback.print_exc()
                return 1

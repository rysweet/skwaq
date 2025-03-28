"""Command handlers for workflow-related commands."""

import argparse
import json
import os
import uuid
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any, Union

from ...workflows.guided_inquiry import GuidedInquiryWorkflow
from ...workflows.qa_workflow import QAWorkflow
from ...workflows.vulnerability_research import VulnerabilityResearchWorkflow
from ...workflows.tool_invocation import ToolInvocationWorkflow
from ...workflows.sources_and_sinks import SourcesAndSinksWorkflow
from ...db.neo4j_connector import get_connector
from ..ui.console import console, success, error, info
from ..ui.progress import create_status_indicator
from ..ui.formatters import (
    format_panel,
    format_investigation_table,
    format_findings_table,
)
from ..ui.prompts import prompt_for_input, prompt_for_confirmation
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
        else:
            error(f"Unknown investigation command: {self.args.investigation_command}")
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

        # Verify investigation exists
        investigation = await self._get_investigation(investigation_id)

        if not investigation:
            error(f"Investigation not found: {investigation_id}")
            return 1

        # Determine output path
        if not output_path:
            output_path = f"investigation-{investigation_id}.{visualization_format}"

        # Generate visualization
        with create_status_indicator(
            f"[bold blue]Generating graph visualization for investigation {investigation_id}...",
            spinner="dots",
        ) as status:
            try:
                # Import here to avoid circular imports
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
                    max_nodes=max_nodes,
                )

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
                info(
                    f"Graph statistics: {len(graph_data['nodes'])} nodes, {len(graph_data['links'])} relationships"
                )

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

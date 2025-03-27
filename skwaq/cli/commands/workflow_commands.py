"""Command handlers for workflow-related commands."""

import argparse
import json
import os
from pathlib import Path
from typing import Dict, List, Optional, Any, Union

from ...workflows.guided_inquiry import GuidedInquiryWorkflow
from ...workflows.qa_workflow import QAWorkflow
from ...workflows.vulnerability_research import VulnerabilityResearchWorkflow
from ...workflows.tool_invocation import ToolInvocationWorkflow
from ..ui.console import console, success, error, info
from ..ui.progress import create_status_indicator
from ..ui.formatters import format_panel
from ..ui.prompts import prompt_for_input
from .base import CommandHandler, handle_command_error


class QACommandHandler(CommandHandler):
    """Handler for the Q&A workflow command."""
    
    @handle_command_error
    async def handle(self) -> int:
        """Handle the Q&A command.
        
        Returns:
            Exit code (0 for success, non-zero for errors)
        """
        repo_id = getattr(self.args, 'repo', None)
        investigation_id = getattr(self.args, 'investigation', None)
        
        # Create QA workflow
        workflow = QAWorkflow()
        
        console.print(format_panel(
            "Starting interactive Q&A session. Ask questions about security vulnerabilities, "
            "coding practices, or specific code patterns. Type 'exit' to quit.",
            title="Q&A Workflow",
            style="cyan"
        ))
        
        # Initialize the workflow
        await workflow.initialize(repo_id, investigation_id)
        
        # Start interactive session
        try:
            while True:
                question = prompt_for_input("\nQuestion:")
                
                if question.lower() in ['exit', 'quit', 'q']:
                    break
                
                with create_status_indicator("[bold blue]Thinking...", spinner="dots") as status:
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
        repo_id = getattr(self.args, 'repo', None)
        investigation_id = getattr(self.args, 'investigation', None)
        prompt = getattr(self.args, 'prompt', None)
        
        # Create guided inquiry workflow
        workflow = GuidedInquiryWorkflow()
        
        console.print(format_panel(
            "Starting guided vulnerability assessment. You will be guided through "
            "a structured process to discover and analyze potential vulnerabilities.",
            title="Guided Inquiry Workflow",
            style="cyan"
        ))
        
        # Initialize the workflow
        with create_status_indicator("[bold blue]Initializing workflow...", spinner="dots") as status:
            inquiry_id = await workflow.initialize(repo_id, investigation_id)
            status.update("[bold green]Workflow initialized!")
        
        # Start guided process
        try:
            # Start with initial prompt if provided
            if prompt:
                with create_status_indicator("[bold blue]Processing initial prompt...", spinner="dots") as status:
                    result = await workflow.start_inquiry(prompt)
                    status.update("[bold green]Initial processing complete!")
                
                console.print(format_panel(result, title="Initial Assessment", style="green"))
            
            # Continue with interactive process
            while True:
                next_step = await workflow.get_next_step()
                
                if next_step is None:
                    # Workflow is complete
                    break
                
                console.print(format_panel(next_step["prompt"], title=next_step["title"], style="cyan"))
                
                # Get user input if needed
                if next_step["requires_input"]:
                    user_input = prompt_for_input("\nYour response:")
                else:
                    user_input = None
                
                with create_status_indicator("[bold blue]Processing...", spinner="dots") as status:
                    result = await workflow.process_step(next_step["id"], user_input)
                    status.update("[bold green]Step completed!")
                
                console.print(format_panel(result, title="Results", style="green"))
                
                # Check if user wants to continue
                if not await workflow.should_continue():
                    break
        finally:
            # Generate final report
            with create_status_indicator("[bold blue]Generating final report...", spinner="dots") as status:
                report = await workflow.generate_report()
                status.update("[bold green]Report generated!")
            
            console.print(format_panel(report, title="Final Assessment Report", style="green"))
            
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
        repo_id = getattr(self.args, 'repo', None)
        tool_args = getattr(self.args, 'args', None)
        
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
        
        console.print(format_panel(
            f"Executing tool: {tool_name}",
            title="Tool Invocation Workflow",
            style="cyan"
        ))
        
        # Initialize the workflow
        with create_status_indicator("[bold blue]Initializing tool...", spinner="dots") as status:
            initialized = await workflow.initialize(tool_name, repo_id)
            if not initialized:
                status.update("[bold red]Tool initialization failed!")
                error(f"Failed to initialize tool: {tool_name}")
                return 1
            status.update("[bold green]Tool initialized!")
        
        # Execute the tool
        try:
            with create_status_indicator(f"[bold blue]Running {tool_name}...", spinner="dots") as status:
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
        repo_id = getattr(self.args, 'repo', None)
        cve_id = getattr(self.args, 'cve', None)
        investigation_id = getattr(self.args, 'investigation', None)
        
        if not repo_id:
            error("Repository ID is required for vulnerability research")
            return 1
        
        # Create vulnerability research workflow
        workflow = VulnerabilityResearchWorkflow()
        
        console.print(format_panel(
            f"Starting vulnerability research on repository ID: {repo_id}",
            title="Vulnerability Research Workflow",
            style="cyan"
        ))
        
        # Initialize the workflow
        with create_status_indicator("[bold blue]Initializing research...", spinner="dots") as status:
            research_id = await workflow.initialize(repo_id, investigation_id)
            status.update("[bold green]Research initialized!")
        
        # Start the research process
        try:
            # Focus on specific CVE if provided
            if cve_id:
                with create_status_indicator(f"[bold blue]Researching CVE {cve_id}...", spinner="dots") as status:
                    cve_result = await workflow.research_cve(cve_id)
                    status.update("[bold green]CVE research complete!")
                
                console.print(format_panel(cve_result, title=f"CVE {cve_id} Research", style="green"))
            
            # Perform comprehensive analysis
            with create_status_indicator("[bold blue]Analyzing repository for vulnerabilities...", spinner="dots") as status:
                analysis_result = await workflow.analyze_repository()
                status.update("[bold green]Analysis complete!")
            
            console.print(format_panel(
                f"Found {len(analysis_result.get('findings', []))} potential vulnerabilities",
                title="Analysis Summary",
                style="cyan"
            ))
            
            # Display findings
            for i, finding in enumerate(analysis_result.get("findings", []), 1):
                console.print(format_panel(
                    f"Type: {finding.get('type')}\n"
                    f"Severity: {finding.get('severity')}\n"
                    f"Description: {finding.get('description')}\n"
                    f"Location: {finding.get('file_path')}:{finding.get('line_number', 'N/A')}\n\n"
                    f"Remediation: {finding.get('remediation')}",
                    title=f"Finding {i}: {finding.get('vulnerability_type')}",
                    style="yellow" if finding.get("severity") in ["High", "Critical"] else "green"
                ))
            
            # Generate final report
            with create_status_indicator("[bold blue]Generating report...", spinner="dots") as status:
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
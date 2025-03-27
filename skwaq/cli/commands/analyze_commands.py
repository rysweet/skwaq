"""Command handlers for analysis commands."""

import sys
import argparse
import json
from pathlib import Path
from typing import Dict, List, Optional, Any

from ...code_analysis.analyzer import CodeAnalyzer
from ...shared.finding import Finding
from ..ui.console import console, success, error, info
from ..ui.progress import create_status_indicator
from ..ui.formatters import format_findings_table, format_panel
from .base import CommandHandler, handle_command_error

class AnalyzeCommandHandler(CommandHandler):
    """Handler for the analyze command."""
    
    @handle_command_error
    async def handle(self) -> int:
        """Handle the analyze command.
        
        Returns:
            Exit code (0 for success, non-zero for errors)
        """
        file_path = self.args.file
        strategy_names = self.args.strategy or ["pattern_matching"]
        output_format = self.args.output or "text"
        save_results = self.args.save
        investigation_id = self.args.investigation
        
        info(f"Analyzing file: {file_path}")
        info(f"Using strategies: {', '.join(strategy_names)}")
        
        # Ensure file exists
        file_path_obj = Path(file_path)
        if not file_path_obj.exists():
            error(f"File not found: {file_path}")
            return 1
        
        # Create analyzer
        analyzer = CodeAnalyzer()
        
        # Use status indicator for analysis
        with create_status_indicator("[bold blue]Analyzing file for vulnerabilities...", spinner="dots") as status:
            # Analyze file using the file path wrapper method
            result = await analyzer.analyze_file_from_path(
                file_path=file_path,
                repository_id=None,  # No repository context for standalone files
                strategy_names=strategy_names,
            )
            status.update("[bold green]Analysis complete!")
        
        # Display results based on output format
        if output_format == "json":
            json_data = {
                "file": file_path,
                "findings": [finding.to_dict() for finding in result.findings],
                "count": len(result.findings),
                "analysis_info": {
                    "strategies": strategy_names,
                    "file_path": file_path,
                }
            }
            console.print_json(json.dumps(json_data, indent=2))
            
        elif output_format == "html":
            # Create HTML output
            html_output = self._create_html_report(file_path, result.findings, strategy_names)
            
            # Determine output filename
            output_file = f"{file_path_obj.stem}_analysis.html"
            
            # Write HTML to file
            with open(output_file, "w") as f:
                f.write(html_output)
                
            success(f"Analysis results saved to: {output_file}")
            
        else:  # Default to text output
            if result.findings:
                console.print(format_findings_table(result.findings))
                
                # Show summary
                console.print()
                summary = f"Found {len(result.findings)} potential vulnerabilities."
                console.print(format_panel(summary, title="Analysis Summary"))
            else:
                console.print(format_panel(
                    "No vulnerabilities found.",
                    title="Analysis Summary",
                    style="green"
                ))
        
        # Save results to database if requested
        if save_results:
            if investigation_id:
                # Save findings to the specified investigation
                with create_status_indicator("[bold blue]Saving findings to database...", spinner="dots") as status:
                    await self._save_findings_to_investigation(result.findings, investigation_id)
                    status.update("[bold green]Findings saved to investigation!")
            else:
                error("Cannot save findings without an investigation ID. Use --investigation to specify.")
                return 1
                
        return 0
    
    async def _save_findings_to_investigation(
        self,
        findings: List[Finding],
        investigation_id: str
    ) -> None:
        """Save findings to an investigation.
        
        Args:
            findings: List of findings to save
            investigation_id: Investigation ID to save to
        """
        # Normally this would use direct DB access, but we'll go through
        # a proper service interface instead to maintain separation
        from ...db.neo4j_connector import get_connector
        
        connector = get_connector()
        
        # Verify investigation exists
        investigation = connector.run_query(
            "MATCH (i:Investigation) WHERE i.id = $id RETURN i",
            {"id": investigation_id}
        )
        
        if not investigation:
            raise ValueError(f"Investigation not found: {investigation_id}")
        
        # Add findings to the investigation
        for finding in findings:
            finding_id = connector.create_node(
                labels=["Finding"],
                properties=finding.to_dict()
            )
            
            # Link finding to investigation
            connector.create_relationship(
                investigation[0]["id"],
                finding_id,
                "HAS_FINDING"
            )
    
    def _create_html_report(
        self,
        file_path: str,
        findings: List[Finding],
        strategies: List[str]
    ) -> str:
        """Create an HTML report of findings.
        
        Args:
            file_path: Path to the analyzed file
            findings: List of findings
            strategies: List of strategies used
            
        Returns:
            HTML report
        """
        # Create an HTML report as a string
        html = f"""<!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Skwaq Analysis Report - {file_path}</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                h1 {{ color: #2c3e50; }}
                .summary {{ background-color: #f8f9fa; padding: 15px; border-radius: 5px; margin-bottom: 20px; }}
                table {{ width: 100%; border-collapse: collapse; margin-top: 20px; }}
                th {{ background-color: #2c3e50; color: white; text-align: left; padding: 10px; }}
                td {{ padding: 10px; border-bottom: 1px solid #ddd; }}
                tr:nth-child(even) {{ background-color: #f2f2f2; }}
                .critical {{ background-color: #ff5252; color: white; padding: 3px 8px; border-radius: 3px; }}
                .high {{ background-color: #ff7b7b; color: white; padding: 3px 8px; border-radius: 3px; }}
                .medium {{ background-color: #ffb74d; color: black; padding: 3px 8px; border-radius: 3px; }}
                .low {{ background-color: #ffee58; color: black; padding: 3px 8px; border-radius: 3px; }}
                .info {{ background-color: #4fc3f7; color: black; padding: 3px 8px; border-radius: 3px; }}
                .footer {{ margin-top: 30px; font-size: 0.8em; color: #7f8c8d; text-align: center; }}
            </style>
        </head>
        <body>
            <h1>Skwaq Vulnerability Analysis Report</h1>
            
            <div class="summary">
                <h2>Analysis Summary</h2>
                <p><strong>File analyzed:</strong> {file_path}</p>
                <p><strong>Strategies used:</strong> {', '.join(strategies)}</p>
                <p><strong>Findings:</strong> {len(findings)}</p>
            </div>
            
            <h2>Vulnerability Findings</h2>
        """
        
        if findings:
            html += """
            <table>
                <tr>
                    <th>Type</th>
                    <th>Line</th>
                    <th>Severity</th>
                    <th>Description</th>
                    <th>Confidence</th>
                </tr>
            """
            
            # Sort findings by severity
            severity_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
            sorted_findings = sorted(
                findings,
                key=lambda f: (
                    severity_order.get(f.severity, 999),
                    -f.confidence
                )
            )
            
            for finding in sorted_findings:
                severity_class = finding.severity.lower() if finding.severity else "info"
                confidence = f"{finding.confidence * 100:.0f}%" if finding.confidence else "N/A"
                line = finding.line_number if finding.line_number else "N/A"
                
                html += f"""
                <tr>
                    <td>{finding.vulnerability_type}</td>
                    <td>{line}</td>
                    <td><span class="{severity_class}">{finding.severity}</span></td>
                    <td>{finding.description}</td>
                    <td>{confidence}</td>
                </tr>
                """
            
            html += "</table>"
        else:
            html += "<p>No vulnerabilities found.</p>"
        
        html += """
            <div class="footer">
                <p>Generated by Skwaq Vulnerability Assessment Tool</p>
            </div>
        </body>
        </html>
        """
        
        return html
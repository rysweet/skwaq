"""Guided inquiry workflow for vulnerability assessment.

This module implements a step-by-step guided inquiry workflow for assessing vulnerabilities
in a codebase.
"""

from typing import Dict, List, Any, Optional, AsyncGenerator, Tuple
import asyncio
import json
from enum import Enum

import autogen_core
from autogen_core import Agent
from autogen_core import event

# Use the BaseEvent class from our vulnerability_events implementation
from ..agents.vulnerability_events import BaseEvent

from .base import Workflow
from ..agents.skwaq_agent import SkwaqAgent
from ..agents.vulnerability_events import KnowledgeRetrievalEvent
from ..db.neo4j_connector import get_connector
from ..utils.logging import get_logger
from ..shared.finding import Finding, AnalysisResult

logger = get_logger(__name__)


class GuidedInquiryStep(Enum):
    """Steps in the guided inquiry workflow."""

    INITIAL_ASSESSMENT = "initial_assessment"
    SCOPE_DEFINITION = "scope_definition"
    THREAT_MODELING = "threat_modeling"
    VULNERABILITY_DISCOVERY = "vulnerability_discovery"
    IMPACT_ASSESSMENT = "impact_assessment"
    REMEDIATION_PLANNING = "remediation_planning"
    FINAL_REPORT = "final_report"


class GuidedInquiryEvent(BaseEvent):
    """Event for guided inquiry interactions."""

    def __init__(
        self,
        sender: str,
        step: GuidedInquiryStep,
        data: Dict[str, Any],
        target: Optional[str] = None,
    ):
        super().__init__(
            sender=sender,
            target=target,
            step=step.value if isinstance(step, GuidedInquiryStep) else step,
            data=data,
        )


class GuidedInquiryWorkflow(Workflow):
    """Guided inquiry workflow for vulnerability assessment.

    This workflow provides a structured, step-by-step approach to vulnerability
    assessment, guiding users through the process of identifying, analyzing,
    and remediating security issues in their codebase.
    """

    def __init__(
        self,
        repository_id: Optional[int] = None,
    ):
        """Initialize the guided inquiry workflow.

        Args:
            repository_id: Optional ID of the repository to analyze
        """
        super().__init__()
        self.repository_id = repository_id
        self.investigation_id = None
        self.connector = get_connector()
        self.current_step = GuidedInquiryStep.INITIAL_ASSESSMENT
        self.assessment_data: Dict[str, Any] = {}
        self.findings: List[Finding] = []

        # State management
        self._should_continue = True
        self._pause_event = asyncio.Event()
        self._pause_event.set()  # Not paused by default

    async def setup(self) -> None:
        """Set up the guided inquiry workflow."""
        # Create a new investigation if needed
        if self.repository_id and not self.investigation_id:
            try:
                result = self.connector.run_query(
                    "MATCH (r:Repository) WHERE id(r) = $repo_id "
                    "CREATE (i:Investigation {created: datetime(), status: 'In Progress', type: 'GuidedInquiry'}) "
                    "CREATE (r)-[:HAS_INVESTIGATION]->(i) "
                    "RETURN id(i) as id",
                    {"repo_id": self.repository_id},
                )
                if result:
                    self.investigation_id = result[0]["id"]
                    logger.info(
                        f"Created new investigation with ID: {self.investigation_id}"
                    )
            except Exception as e:
                logger.warning(f"Failed to create investigation: {e}")
                # Still continue even if we can't create an investigation

        # Initialize agents
        self.agents = {}
        self.agents["guided"] = GuidedInquiryAgent(
            repository_id=self.repository_id,
            investigation_id=self.investigation_id,
        )

        logger.info("Guided inquiry workflow initialized")

    async def run(self) -> AsyncGenerator[Dict[str, Any], None]:
        """Run the guided inquiry workflow.

        Yields:
            Progress updates and results for each step
        """
        # Start with initial assessment
        yield {
            "status": "starting",
            "step": self.current_step.value,
            "message": "Starting guided vulnerability assessment",
        }

        # Process each step in sequence
        while self.should_continue():
            # Check if we need to pause
            await self._pause_event.wait()

            # Process current step
            step_result = await self._process_step(self.current_step)

            # Record step results
            self.assessment_data[self.current_step.value] = step_result

            # Emit event for the step - adapted for new autogen_core version
            inquiry_event = GuidedInquiryEvent(
                sender=self.__class__.__name__,
                step=self.current_step,
                data=step_result,
            )

            # Log the event
            logger.info(
                f"Emitting event: {inquiry_event.__class__.__name__} for step {self.current_step.value}"
            )

            yield {
                "status": "step_completed",
                "step": self.current_step.value,
                "data": step_result,
            }

            # Move to next step
            if self.current_step == GuidedInquiryStep.FINAL_REPORT:
                # Workflow is complete
                self._should_continue = False
                yield {
                    "status": "completed",
                    "message": "Guided assessment complete",
                    "data": self.assessment_data,
                }
                break
            else:
                # Advance to the next step
                self._advance_step()
                yield {
                    "status": "advancing",
                    "step": self.current_step.value,
                    "message": f"Moving to {self.current_step.value}",
                }

        # Update investigation status if we have one
        if self.investigation_id:
            self.connector.run_query(
                "MATCH (i:Investigation) WHERE id(i) = $id "
                "SET i.status = 'Complete', i.completed = datetime()",
                {"id": self.investigation_id},
            )

    def should_continue(self) -> bool:
        """Check if the workflow should continue.

        Returns:
            True if the workflow should continue, False otherwise
        """
        return self._should_continue

    def pause(self) -> None:
        """Pause the workflow."""
        self._pause_event.clear()
        logger.info(
            f"Guided inquiry workflow paused at step: {self.current_step.value}"
        )

    def resume(self) -> None:
        """Resume the workflow."""
        self._pause_event.set()
        logger.info(
            f"Guided inquiry workflow resumed at step: {self.current_step.value}"
        )

    def _advance_step(self) -> None:
        """Advance to the next step in the workflow."""
        steps = list(GuidedInquiryStep)
        current_idx = steps.index(self.current_step)
        if current_idx < len(steps) - 1:
            self.current_step = steps[current_idx + 1]
        logger.info(f"Advanced to step: {self.current_step.value}")

    async def _process_step(self, step: GuidedInquiryStep) -> Dict[str, Any]:
        """Process a single step in the guided inquiry workflow.

        Args:
            step: The step to process

        Returns:
            Results of processing the step
        """
        logger.info(f"Processing step: {step.value}")

        # Different processing based on step
        if step == GuidedInquiryStep.INITIAL_ASSESSMENT:
            return await self._process_initial_assessment()
        elif step == GuidedInquiryStep.SCOPE_DEFINITION:
            return await self._process_scope_definition()
        elif step == GuidedInquiryStep.THREAT_MODELING:
            return await self._process_threat_modeling()
        elif step == GuidedInquiryStep.VULNERABILITY_DISCOVERY:
            return await self._process_vulnerability_discovery()
        elif step == GuidedInquiryStep.IMPACT_ASSESSMENT:
            return await self._process_impact_assessment()
        elif step == GuidedInquiryStep.REMEDIATION_PLANNING:
            return await self._process_remediation_planning()
        elif step == GuidedInquiryStep.FINAL_REPORT:
            return await self._process_final_report()
        else:
            return {"error": f"Unknown step: {step.value}"}

    async def _process_initial_assessment(self) -> Dict[str, Any]:
        """Process the initial assessment step.

        Returns:
            Assessment results
        """
        # Get repository information
        repo_info = {}
        if self.repository_id:
            result = self.connector.run_query(
                "MATCH (r:Repository) WHERE id(r) = $repo_id "
                "OPTIONAL MATCH (r)-[:HAS_FILE]->(f) "
                "RETURN r.name as name, r.path as path, r.url as url, "
                "count(f) as file_count",
                {"repo_id": self.repository_id},
            )
            if result:
                repo_info = result[0]

        # Use the guided inquiry agent to do initial assessment
        assessment = await self.agents["guided"].initial_assessment(repo_info)

        return {
            "repository": repo_info,
            "assessment": assessment,
            "timestamp": self._get_timestamp(),
        }

    async def _process_scope_definition(self) -> Dict[str, Any]:
        """Process the scope definition step.

        Returns:
            Scope definition results
        """
        # Get file types and distribution from repository
        file_types = {}
        if self.repository_id:
            result = self.connector.run_query(
                "MATCH (r:Repository)-[:HAS_FILE]->(f) "
                "WHERE id(r) = $repo_id "
                "RETURN f.language as language, count(f) as count "
                "ORDER BY count DESC",
                {"repo_id": self.repository_id},
            )
            if result:
                file_types = {
                    r["language"]: r["count"] for r in result if r["language"]
                }

        # Use the guided inquiry agent to define scope
        previous_assessment = self.assessment_data.get(
            GuidedInquiryStep.INITIAL_ASSESSMENT.value, {}
        )
        scope = await self.agents["guided"].define_scope(
            previous_assessment, file_types
        )

        return {
            "file_types": file_types,
            "scope": scope,
            "timestamp": self._get_timestamp(),
        }

    async def _process_threat_modeling(self) -> Dict[str, Any]:
        """Process the threat modeling step.

        Returns:
            Threat modeling results
        """
        # Use the guided inquiry agent to do threat modeling
        scope = self.assessment_data.get(GuidedInquiryStep.SCOPE_DEFINITION.value, {})

        threats = await self.agents["guided"].identify_threats(scope)

        return {
            "threats": threats,
            "timestamp": self._get_timestamp(),
        }

    async def _process_vulnerability_discovery(self) -> Dict[str, Any]:
        """Process the vulnerability discovery step.

        Returns:
            Vulnerability discovery results
        """
        from ..code_analysis.analyzer import CodeAnalyzer

        # Get threat model and scope
        threats = self.assessment_data.get(GuidedInquiryStep.THREAT_MODELING.value, {})
        scope = self.assessment_data.get(GuidedInquiryStep.SCOPE_DEFINITION.value, {})

        # Run analysis based on the threats and scope
        analyzer = CodeAnalyzer()

        # Determine analysis strategies based on threat model
        strategies = await self.agents["guided"].determine_analysis_strategies(threats)

        # Run code analysis if we have a repository
        findings = []
        if self.repository_id:
            # Run analysis and collect findings
            with_semantic = "semantic_analysis" in strategies
            with_ast = "ast_analysis" in strategies

            analysis_result = await analyzer.analyze_repository(
                repository_id=self.repository_id,
                with_semantic=with_semantic,
                with_ast=with_ast,
            )

            if analysis_result and analysis_result.findings:
                findings = analysis_result.findings
                self.findings.extend(findings)

        # Use the guided inquiry agent to summarize findings
        findings_summary = await self.agents["guided"].summarize_findings(findings)

        return {
            "strategies_used": strategies,
            "findings_count": len(findings),
            "findings_summary": findings_summary,
            "timestamp": self._get_timestamp(),
        }

    async def _process_impact_assessment(self) -> Dict[str, Any]:
        """Process the impact assessment step.

        Returns:
            Impact assessment results
        """
        # Get findings from the previous step
        findings = self.findings

        # Let the agent assess the impact
        impact = await self.agents["guided"].assess_impact(findings)

        return {
            "impact": impact,
            "timestamp": self._get_timestamp(),
        }

    async def _process_remediation_planning(self) -> Dict[str, Any]:
        """Process the remediation planning step.

        Returns:
            Remediation planning results
        """
        # Get findings and impact assessment
        findings = self.findings
        impact = self.assessment_data.get(GuidedInquiryStep.IMPACT_ASSESSMENT.value, {})

        # Let the agent create remediation plans
        remediation = await self.agents["guided"].plan_remediation(findings, impact)

        return {
            "remediation_plan": remediation,
            "timestamp": self._get_timestamp(),
        }

    async def _process_final_report(self) -> Dict[str, Any]:
        """Process the final report step.

        Returns:
            Final report data
        """
        # Use all the data from previous steps to generate a report
        report = await self.agents["guided"].generate_report(self.assessment_data)

        # Store the report in the database if we have an investigation
        if self.investigation_id:
            self.connector.run_query(
                "MATCH (i:Investigation) WHERE id(i) = $id "
                "CREATE (r:Report {content: $content, generated: datetime()}) "
                "CREATE (i)-[:HAS_REPORT]->(r)",
                {
                    "id": self.investigation_id,
                    "content": json.dumps(report),
                },
            )

        return {
            "report": report,
            "timestamp": self._get_timestamp(),
        }

    def _get_timestamp(self) -> str:
        """Get the current timestamp.

        Returns:
            Timestamp string in ISO format
        """
        import datetime

        return datetime.datetime.utcnow().isoformat()


class GuidedInquiryAgent(SkwaqAgent):
    """Agent for guiding vulnerability assessment inquiries.

    This agent helps users through a structured vulnerability assessment process,
    providing guidance, interpreting results, and generating recommendations.
    """

    def __init__(
        self,
        repository_id: Optional[int] = None,
        investigation_id: Optional[int] = None,
        name: str = "GuidedInquiryAgent",
        system_message: Optional[str] = None,
        **kwargs,
    ):
        if system_message is None:
            system_message = """You are the Guided Inquiry agent for a vulnerability assessment system.
Your role is to guide users through a structured process of identifying, analyzing, and 
remediating security vulnerabilities in their code. You should provide clear explanations,
focused assessments, and actionable recommendations at each step of the process."""

        super().__init__(
            name=name,
            system_message=system_message,
            description="Guides users through structured vulnerability assessments",
            **kwargs,
        )

        self.repository_id = repository_id
        self.investigation_id = investigation_id
        self.connector = get_connector()

    async def initial_assessment(
        self, repository_info: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Perform an initial assessment of the repository.

        Args:
            repository_info: Information about the repository

        Returns:
            Initial assessment data
        """
        from ..core.openai_client import get_openai_client

        # Prepare prompt for initial assessment
        prompt = f"""Perform an initial security assessment based on the following repository information:

Repository name: {repository_info.get('name', 'Unknown')}
File count: {repository_info.get('file_count', 'Unknown')}
Repository path/URL: {repository_info.get('path') or repository_info.get('url', 'Unknown')}

Provide a structured initial security assessment with the following components:
1. General security posture estimation
2. Key areas that should be prioritized for security review
3. Potential security challenges based on repository information
4. Recommended assessment approach

Format your response as a JSON object with keys: general_assessment, priority_areas, potential_challenges, and recommended_approach.
"""

        # Get completion
        openai_client = get_openai_client(async_mode=True)
        response = await openai_client.get_completion(prompt, temperature=0.3)

        # Parse response as JSON
        try:
            assessment = json.loads(response)
        except json.JSONDecodeError:
            logger.error("Failed to parse initial assessment response as JSON")
            # Create a structured response manually
            assessment = {
                "general_assessment": "Unable to parse assessment response",
                "priority_areas": [],
                "potential_challenges": [],
                "recommended_approach": "Perform standard security assessment",
            }

        return assessment

    async def define_scope(
        self, previous_assessment: Dict[str, Any], file_types: Dict[str, int]
    ) -> Dict[str, Any]:
        """Define the scope of the security assessment.

        Args:
            previous_assessment: Results from the initial assessment
            file_types: Distribution of file types in the repository

        Returns:
            Scope definition data
        """
        from ..core.openai_client import get_openai_client

        # Extract the assessment part from previous results
        assessment = previous_assessment.get("assessment", {})

        # Prepare prompt for scope definition
        prompt = f"""Define the scope for a security assessment based on the following information:

Initial assessment:
General assessment: {assessment.get('general_assessment', 'Not available')}
Priority areas: {assessment.get('priority_areas', [])}
Potential challenges: {assessment.get('potential_challenges', [])}

File type distribution:
{json.dumps(file_types, indent=2)}

Define a focused scope for the security assessment with the following components:
1. Included file types and components (be specific about what should be assessed)
2. Excluded file types and components (what can be safely excluded)
3. Priority ranking of components to assess (from highest to lowest)
4. Specific vulnerability types to focus on for this codebase
5. Assessment depth for different components (surface-level vs in-depth)

Format your response as a JSON object with keys: included, excluded, priority_ranking, vulnerability_focus, and assessment_depth.
"""

        # Get completion
        openai_client = get_openai_client(async_mode=True)
        response = await openai_client.get_completion(prompt, temperature=0.3)

        # Parse response as JSON
        try:
            scope = json.loads(response)
        except json.JSONDecodeError:
            logger.error("Failed to parse scope definition response as JSON")
            # Create a structured response manually
            scope = {
                "included": ["All code files"],
                "excluded": ["Non-code files"],
                "priority_ranking": ["High-risk components"],
                "vulnerability_focus": ["Common vulnerabilities"],
                "assessment_depth": {"default": "standard"},
            }

        return scope

    async def identify_threats(self, scope: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Identify potential threats based on the defined scope.

        Args:
            scope: The defined assessment scope

        Returns:
            List of identified threats
        """
        from ..core.openai_client import get_openai_client

        # Extract scope data
        scope_info = scope.get("scope", {})

        # Prepare prompt for threat modeling
        prompt = f"""Perform threat modeling based on the following assessment scope:

Included components: {scope_info.get('included', [])}
Vulnerability focus: {scope_info.get('vulnerability_focus', [])}
Priority ranking: {scope_info.get('priority_ranking', [])}

Identify potential threats to this system using the STRIDE threat model:
- Spoofing
- Tampering
- Repudiation
- Information Disclosure
- Denial of Service
- Elevation of Privilege

For each applicable threat category, identify specific threats that should be assessed.

Format your response as a JSON array where each item has:
- "category": The STRIDE category
- "threats": Array of specific threats in this category
- "likelihood": Estimated likelihood (high, medium, low)
- "impact": Estimated impact if exploited (high, medium, low)
- "detection_methods": How to detect this type of threat in code
"""

        # Get completion
        openai_client = get_openai_client(async_mode=True)
        response = await openai_client.get_completion(prompt, temperature=0.3)

        # Parse response as JSON
        try:
            threats = json.loads(response)
            if not isinstance(threats, list):
                threats = [threats]  # Convert to list if not already
        except json.JSONDecodeError:
            logger.error("Failed to parse threat identification response as JSON")
            # Create a basic threat model manually
            threats = [
                {
                    "category": "Information Disclosure",
                    "threats": ["Sensitive data exposure"],
                    "likelihood": "medium",
                    "impact": "high",
                    "detection_methods": ["Code review for hardcoded secrets"],
                }
            ]

        return threats

    async def determine_analysis_strategies(
        self, threat_data: Dict[str, Any]
    ) -> List[str]:
        """Determine which analysis strategies to use based on the threats.

        Args:
            threat_data: The threat modeling data

        Returns:
            List of analysis strategies to use
        """
        # Extract threats
        threats = threat_data.get("threats", [])

        # Always include pattern matching
        strategies = ["pattern_matching"]

        # Add semantic analysis for complex threats
        complex_categories = [
            "Repudiation",
            "Information Disclosure",
            "Elevation of Privilege",
        ]
        if any(t.get("category") in complex_categories for t in threats):
            strategies.append("semantic_analysis")

        # Add AST analysis for code structure threats
        structure_categories = ["Tampering", "Elevation of Privilege"]
        if any(t.get("category") in structure_categories for t in threats):
            strategies.append("ast_analysis")

        logger.info(f"Selected analysis strategies: {strategies}")
        return strategies

    async def summarize_findings(self, findings: List[Finding]) -> Dict[str, Any]:
        """Summarize the vulnerability findings.

        Args:
            findings: List of findings from the analysis

        Returns:
            Summary of findings
        """
        from ..core.openai_client import get_openai_client

        # Convert findings to a simplified format for the prompt
        findings_text = []
        for i, finding in enumerate(findings):
            findings_text.append(
                f"{i+1}. {finding.vulnerability_type} ({finding.severity}, confidence: {finding.confidence:.2f})\n"
                f"   Location: {finding.file_path}:{finding.line_number}\n"
                f"   Description: {finding.description}\n"
            )

        findings_str = "\n".join(findings_text) if findings_text else "No findings."

        # Prepare prompt for findings summary
        prompt = f"""Summarize the following vulnerability findings:

{findings_str}

Provide a comprehensive summary with the following components:
1. Overall assessment of the findings
2. Distribution of finding types and severity levels
3. Key vulnerability patterns identified
4. Most critical issues requiring immediate attention
5. False positive estimation (which findings might be false positives)

Format your response as a JSON object with keys: overall_assessment, distribution, key_patterns, critical_issues, and false_positive_estimate.
"""

        # Get completion
        openai_client = get_openai_client(async_mode=True)
        response = await openai_client.get_completion(prompt, temperature=0.3)

        # Parse response as JSON
        try:
            summary = json.loads(response)
        except json.JSONDecodeError:
            logger.error("Failed to parse findings summary response as JSON")
            # Create a basic summary manually
            summary = {
                "overall_assessment": f"Found {len(findings)} potential vulnerabilities.",
                "distribution": {},
                "key_patterns": [],
                "critical_issues": [],
                "false_positive_estimate": "Unknown",
            }

        return summary

    async def assess_impact(self, findings: List[Finding]) -> Dict[str, Any]:
        """Assess the impact of the identified vulnerabilities.

        Args:
            findings: List of findings from the analysis

        Returns:
            Impact assessment data
        """
        from ..core.openai_client import get_openai_client

        # Convert findings to a simplified format for the prompt
        findings_text = []
        for i, finding in enumerate(findings):
            findings_text.append(
                f"{i+1}. {finding.vulnerability_type} ({finding.severity}, confidence: {finding.confidence:.2f})\n"
                f"   Location: {finding.file_path}:{finding.line_number}\n"
                f"   Description: {finding.description}\n"
            )

        findings_str = "\n".join(findings_text) if findings_text else "No findings."

        # Prepare prompt for impact assessment
        prompt = f"""Assess the impact of the following vulnerability findings:

{findings_str}

Provide a comprehensive impact assessment with the following components:
1. Business impact (financial, reputational, operational)
2. Security impact (confidentiality, integrity, availability)
3. Exploitation difficulty assessment
4. Combined risk score and justification
5. Contextual factors affecting impact

Format your response as a JSON object with keys: business_impact, security_impact, exploitation_difficulty, risk_score, and contextual_factors.
"""

        # Get completion
        openai_client = get_openai_client(async_mode=True)
        response = await openai_client.get_completion(prompt, temperature=0.3)

        # Parse response as JSON
        try:
            impact = json.loads(response)
        except json.JSONDecodeError:
            logger.error("Failed to parse impact assessment response as JSON")
            # Create a basic impact assessment manually
            impact = {
                "business_impact": "Needs assessment",
                "security_impact": {},
                "exploitation_difficulty": "Unknown",
                "risk_score": 5,  # Medium risk as default
                "contextual_factors": [],
            }

        return impact

    async def plan_remediation(
        self, findings: List[Finding], impact: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Plan remediation for the identified vulnerabilities.

        Args:
            findings: List of findings from the analysis
            impact: Impact assessment data

        Returns:
            Remediation plan data
        """
        from ..core.openai_client import get_openai_client

        # Convert findings to a simplified format for the prompt
        findings_text = []
        for i, finding in enumerate(findings):
            findings_text.append(
                f"{i+1}. {finding.vulnerability_type} ({finding.severity}, confidence: {finding.confidence:.2f})\n"
                f"   Location: {finding.file_path}:{finding.line_number}\n"
                f"   Description: {finding.description}\n"
            )

        findings_str = "\n".join(findings_text) if findings_text else "No findings."

        # Extract impact assessment
        impact_data = impact.get("impact", {})

        # Prepare prompt for remediation planning
        prompt = f"""Create a remediation plan for the following vulnerability findings:

{findings_str}

Impact assessment:
Business impact: {impact_data.get('business_impact', 'Not available')}
Security impact: {impact_data.get('security_impact', {})}
Risk score: {impact_data.get('risk_score', 'Unknown')}

Provide a comprehensive remediation plan with the following components:
1. Prioritized list of vulnerabilities to address
2. Specific remediation steps for each vulnerability type
3. Implementation difficulty (easy, medium, hard)
4. Estimated remediation time
5. Required resources and skills
6. Testing approach to verify remediation

Format your response as a JSON object with keys: prioritized_vulnerabilities, remediation_steps, difficulty, timeline, resources, and testing.
"""

        # Get completion
        openai_client = get_openai_client(async_mode=True)
        response = await openai_client.get_completion(prompt, temperature=0.3)

        # Parse response as JSON
        try:
            plan = json.loads(response)
        except json.JSONDecodeError:
            logger.error("Failed to parse remediation plan response as JSON")
            # Create a basic remediation plan manually
            plan = {
                "prioritized_vulnerabilities": [
                    f.vulnerability_type for f in findings[:5]
                ],
                "remediation_steps": {},
                "difficulty": "medium",
                "timeline": "Varies by vulnerability",
                "resources": ["Security engineer"],
                "testing": "Manual verification",
            }

        return plan

    async def generate_report(self, assessment_data: Dict[str, Any]) -> Dict[str, Any]:
        """Generate a final report based on all assessment data.

        Args:
            assessment_data: All data collected during the assessment

        Returns:
            Final report data
        """
        from ..core.openai_client import get_openai_client

        # Extract key information from each step
        initial = assessment_data.get(GuidedInquiryStep.INITIAL_ASSESSMENT.value, {})
        scope = assessment_data.get(GuidedInquiryStep.SCOPE_DEFINITION.value, {})
        threats = assessment_data.get(GuidedInquiryStep.THREAT_MODELING.value, {})
        findings = assessment_data.get(
            GuidedInquiryStep.VULNERABILITY_DISCOVERY.value, {}
        )
        impact = assessment_data.get(GuidedInquiryStep.IMPACT_ASSESSMENT.value, {})
        remediation = assessment_data.get(
            GuidedInquiryStep.REMEDIATION_PLANNING.value, {}
        )

        # Prepare a concise summary of the assessment for the prompt
        assessment_summary = {
            "initial_assessment": initial.get("assessment", {}),
            "scope": scope.get("scope", {}),
            "threats": threats.get("threats", [])[:3],  # First 3 threats for brevity
            "findings_summary": findings.get("findings_summary", {}),
            "impact": impact.get("impact", {}),
            "remediation_plan": remediation.get("remediation_plan", {}),
        }

        # Prepare prompt for final report
        prompt = f"""Generate a final security assessment report based on the following data:

{json.dumps(assessment_summary, indent=2)}

Create a comprehensive security assessment report with the following sections:
1. Executive Summary
2. Assessment Methodology
3. Key Findings
4. Risk Assessment
5. Detailed Remediation Plan
6. Conclusion and Next Steps

Format your response as a JSON object with these sections as keys. For each section, provide detailed,
professional content suitable for a formal security assessment report.
"""

        # Get completion
        openai_client = get_openai_client(async_mode=True)
        response = await openai_client.get_completion(prompt, temperature=0.4)

        # Parse response as JSON
        try:
            report = json.loads(response)
        except json.JSONDecodeError:
            logger.error("Failed to parse final report response as JSON")
            # Create a basic report manually
            report = {
                "executive_summary": "Security assessment completed",
                "assessment_methodology": "Guided inquiry methodology",
                "key_findings": "See detailed findings",
                "risk_assessment": "See impact assessment",
                "detailed_remediation_plan": "See remediation planning",
                "conclusion_and_next_steps": "Follow remediation plan",
            }

        return report

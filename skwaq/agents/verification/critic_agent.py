"""Advanced Critic Agent for the Skwaq vulnerability assessment system.

This module defines an advanced critic agent that provides detailed
evaluation and feedback on the work of other agents, helping to
improve overall system quality and reliability.
"""

import enum
import json
import time
import uuid
from typing import Any, Dict, List, Optional, Union

from ...utils.logging import get_logger
from ..critic_agent import CriticAgent
from ..events import AgentCommunicationEvent, Task

logger = get_logger(__name__)


class CritiqueCategory(enum.Enum):
    """Categories of critique that the critic agent can provide."""

    TECHNICAL_ACCURACY = "technical_accuracy"
    COMPLETENESS = "completeness"
    CONSISTENCY = "consistency"
    READABILITY = "readability"
    SECURITY_IMPLICATIONS = "security_implications"
    METHODOLOGY = "methodology"
    EVIDENCE_QUALITY = "evidence_quality"


class CritiqueEvent(AgentCommunicationEvent):
    """Event for providing detailed critique feedback."""

    def __init__(
        self,
        sender_id: str,
        receiver_id: str,
        critique: Dict[str, Any],
        content_reference: str,
        categories: List[CritiqueCategory],
        severity: float = 0.5,  # 0.0 to 1.0
        metadata: Optional[Dict[str, Any]] = None,
    ):
        """Initialize a critique event.

        Args:
            sender_id: ID of the sending agent
            receiver_id: ID of the receiving agent
            critique: Detailed critique information
            content_reference: Reference to the content being critiqued
            categories: Categories of critique being provided
            severity: Severity level of the critique (0.0 to 1.0)
            metadata: Additional metadata
        """
        critique_summary = critique.get("summary", "Detailed critique of work")
        critique_metadata = metadata or {}
        critique_metadata.update(
            {
                "content_reference": content_reference,
                "categories": [cat.value for cat in categories],
                "severity": severity,
                "critique_id": str(uuid.uuid4()),
                "event_type": "critique",
            }
        )

        super().__init__(
            sender_id=sender_id,
            receiver_id=receiver_id,
            message=critique_summary,
            message_type="critique",
            metadata=critique_metadata,
        )
        self.critique = critique
        self.content_reference = content_reference
        self.categories = categories
        self.severity = severity


class AdvancedCriticAgent(CriticAgent):
    """Advanced critic agent for evaluating and improving agent outputs.

    This agent extends the base CriticAgent with more sophisticated
    critique capabilities, including multi-category evaluation and
    improvement suggestions.
    """

    def __init__(
        self,
        name: str = "AdvancedCriticAgent",
        description: str = "Advanced agent that critiques and improves the work of other agents",
        config_key: str = "agents.advanced_critic",
        system_message: Optional[str] = None,
        agent_id: Optional[str] = None,
        model: Optional[str] = None,
        critique_categories: Optional[List[CritiqueCategory]] = None,
    ):
        """Initialize the advanced critic agent.

        Args:
            name: Name of the agent
            description: Description of the agent's purpose
            config_key: Configuration key for this agent
            system_message: Custom system message for the agent
            agent_id: Optional unique identifier for the agent
            model: Optional model override
            critique_categories: Optional list of categories to critique
        """
        if system_message is None:
            system_message = """You are an advanced critic agent for a vulnerability assessment system.
Your purpose is to provide detailed, constructive critique on findings, analyses,
and reports produced by other agents in the system.

Your responsibilities include:
1. Evaluating technical accuracy of vulnerability findings
2. Checking for completeness of analyses
3. Ensuring consistency across findings and reports
4. Assessing readability and clarity of reports
5. Evaluating security implications of findings
6. Analyzing methodology and evidence quality
7. Providing detailed, actionable feedback

Your critiques should be structured by category, with clear justification,
severity assessment, and specific improvement suggestions. Your goal is not
just to identify problems but to help improve the quality of the vulnerability
assessment process.

Remember that your critiques should always be constructive, specific, and focused
on improving the final output rather than simply pointing out flaws.
"""

        super().__init__(
            name=name,
            description=description,
            config_key=config_key,
            system_message=system_message,
            agent_id=agent_id,
            model=model,
        )

        # Set up critique categories
        self.critique_categories = critique_categories or [
            CritiqueCategory.TECHNICAL_ACCURACY,
            CritiqueCategory.COMPLETENESS,
            CritiqueCategory.CONSISTENCY,
            CritiqueCategory.SECURITY_IMPLICATIONS,
        ]

        # Track critiqued content and associated tasks
        self.critiqued_content: Dict[str, Dict[str, Any]] = {}
        self.critique_tasks: Dict[str, Task] = {}

    async def _start(self):
        """Initialize the agent on startup."""
        await super()._start()

        # Register additional event handlers
        self.register_event_handler(CritiqueEvent, self._handle_critique_event)

    async def critique_content(
        self,
        content: Union[str, Dict[str, Any]],
        content_id: str,
        task_id: Optional[str] = None,
        sender_id: Optional[str] = None,
        categories: Optional[List[CritiqueCategory]] = None,
    ) -> Dict[str, Any]:
        """Provide detailed critique on the provided content.

        Args:
            content: Content to critique (text or structured data)
            content_id: Identifier for the content
            task_id: Optional task ID associated with this critique
            sender_id: Optional ID of the agent that created the content
            categories: Optional specific categories to critique

        Returns:
            Dictionary with critique results
        """
        critique_task_id = task_id or f"critique_{int(time.time())}_{content_id}"

        # Determine which categories to critique
        critique_categories = categories or self.critique_categories

        logger.info(
            f"Starting critique of content {content_id} in categories: {[c.value for c in critique_categories]}"
        )

        # Create task for tracking
        critique_task = Task(
            task_id=critique_task_id,
            task_type="content_critique",
            description=f"Critique content: {content_id}",
            parameters={
                "content_id": content_id,
                "categories": [c.value for c in critique_categories],
                "sender_id": sender_id,
            },
            status="in_progress",
        )

        self.critique_tasks[critique_task_id] = critique_task

        try:
            # Structure for the critique
            critique_result = {
                "content_id": content_id,
                "task_id": critique_task_id,
                "timestamp": time.time(),
                "categories": {},
                "overall": {
                    "rating": 0.0,  # 0.0 to 1.0
                    "summary": "",
                    "key_issues": [],
                    "improvement_suggestions": [],
                },
            }

            # Evaluate each category
            for category in critique_categories:
                category_result = await self._evaluate_category(
                    content, category, content_id
                )
                critique_result["categories"][category.value] = category_result

            # Calculate overall rating and summary
            if critique_result["categories"]:
                # Calculate average rating
                ratings = [
                    cat_data["rating"]
                    for cat_data in critique_result["categories"].values()
                ]
                overall_rating = sum(ratings) / len(ratings)
                critique_result["overall"]["rating"] = overall_rating

                # Compile key issues and suggestions
                for cat_data in critique_result["categories"].values():
                    critique_result["overall"]["key_issues"].extend(
                        cat_data.get("issues", [])
                    )
                    critique_result["overall"]["improvement_suggestions"].extend(
                        cat_data.get("suggestions", [])
                    )

                # Generate overall summary
                if isinstance(content, str) and len(content) > 100:
                    content_preview = content[:100] + "..."
                else:
                    content_preview = str(content)

                critique_result["overall"]["summary"] = (
                    f"Critique of '{content_preview}' with overall rating {overall_rating:.2f}/1.0. "
                    f"Found {len(critique_result['overall']['key_issues'])} issues "
                    f"with {len(critique_result['overall']['improvement_suggestions'])} improvement suggestions."
                )

            # Store critique in the agent's memory
            self.critiqued_content[content_id] = critique_result

            # Update task status
            critique_task.status = "completed"
            critique_task.result = critique_result

            # Log completion
            logger.info(
                f"Completed critique of content {content_id} with rating {critique_result['overall']['rating']:.2f}/1.0"
            )

            return critique_result
        except Exception as e:
            logger.error(f"Error critiquing content {content_id}: {e}")
            critique_task.status = "failed"
            critique_task.error = str(e)
            raise

    async def _evaluate_category(
        self,
        content: Union[str, Dict[str, Any]],
        category: CritiqueCategory,
        content_id: str,
    ) -> Dict[str, Any]:
        """Evaluate content in a specific critique category.

        Args:
            content: Content to evaluate
            category: Category to evaluate
            content_id: Content identifier

        Returns:
            Dictionary with category evaluation results
        """
        # Prepare evaluation messages based on category
        if category == CritiqueCategory.TECHNICAL_ACCURACY:
            evaluation_prompt = (
                f"Evaluate the technical accuracy of the following content:\n\n{content}\n\n"
                f"Specifically check for factual errors, misunderstandings, or incorrect technical details. "
                f"Return a rating from 0.0 to 1.0 where 1.0 is completely accurate, along with a list of issues "
                f"and improvement suggestions."
            )
        elif category == CritiqueCategory.COMPLETENESS:
            evaluation_prompt = (
                f"Evaluate the completeness of the following content:\n\n{content}\n\n"
                f"Check for missing information, unexplored areas, or incomplete analysis. "
                f"Return a rating from 0.0 to 1.0 where 1.0 is completely thorough, along with a list of issues "
                f"and improvement suggestions."
            )
        elif category == CritiqueCategory.CONSISTENCY:
            evaluation_prompt = (
                f"Evaluate the consistency of the following content:\n\n{content}\n\n"
                f"Check for internal contradictions, logical inconsistencies, or conflicting statements. "
                f"Return a rating from 0.0 to 1.0 where 1.0 is completely consistent, along with a list of issues "
                f"and improvement suggestions."
            )
        elif category == CritiqueCategory.SECURITY_IMPLICATIONS:
            evaluation_prompt = (
                f"Evaluate the security implications in the following content:\n\n{content}\n\n"
                f"Check for missed security concerns, underestimated risks, or incomplete threat models. "
                f"Return a rating from 0.0 to 1.0 where 1.0 addresses all security implications perfectly, "
                f"along with a list of issues and improvement suggestions."
            )
        else:
            evaluation_prompt = (
                f"Evaluate the {category.value} of the following content:\n\n{content}\n\n"
                f"Return a rating from 0.0 to 1.0 where 1.0 is excellent, along with a list of issues "
                f"and improvement suggestions."
            )

        # Use the chat model to evaluate
        response = await self.openai_client.create_completion(
            prompt=evaluation_prompt,
            model=self.model,
            temperature=0.2,
            max_tokens=1500,
            response_format={"type": "json"},
        )

        response_text = response.get("choices", [{}])[0].get("text", "").strip()

        try:
            # Parse the response
            evaluation = json.loads(response_text)

            # Ensure required fields
            if "rating" not in evaluation:
                evaluation["rating"] = 0.5
            if "issues" not in evaluation:
                evaluation["issues"] = []
            if "suggestions" not in evaluation:
                evaluation["suggestions"] = []

            # Normalize rating to 0.0-1.0
            if isinstance(evaluation["rating"], (int, float)):
                if evaluation["rating"] > 1.0:
                    evaluation["rating"] /= 10.0  # Convert 1-10 scale to 0.0-1.0
                evaluation["rating"] = max(0.0, min(1.0, evaluation["rating"]))
            else:
                evaluation["rating"] = 0.5

            return evaluation
        except (json.JSONDecodeError, KeyError) as e:
            logger.error(f"Error parsing evaluation for {category.value}: {e}")
            # Return a basic evaluation on parsing error
            return {
                "rating": 0.5,
                "issues": ["Could not properly evaluate this category"],
                "suggestions": ["Review this category manually"],
            }

    async def _handle_critique_event(self, event: CritiqueEvent) -> None:
        """Handle incoming critique events.

        Args:
            event: Incoming critique event
        """
        if not isinstance(event, CritiqueEvent):
            return

        # Log the received critique
        logger.info(
            f"Received critique event for content {event.content_reference} with severity {event.severity}"
        )

        # Store the critique for future reference
        content_id = event.content_reference

        if content_id not in self.critiqued_content:
            self.critiqued_content[content_id] = {}

        # Add this critique
        critique_id = event.metadata.get("critique_id", str(uuid.uuid4()))
        self.critiqued_content[content_id][critique_id] = event.critique

    async def get_critiques_for_content(self, content_id: str) -> List[Dict[str, Any]]:
        """Get all critiques for a specific content.

        Args:
            content_id: Content identifier

        Returns:
            List of critiques for the content
        """
        if content_id in self.critiqued_content:
            return list(self.critiqued_content[content_id].values())
        return []

"""Q&A workflow for vulnerability assessment.

This module implements the question-answering workflow for interacting with
the vulnerability assessment system.
"""

from typing import Dict, List, Any, Optional, AsyncGenerator
import asyncio
import json

from autogen_core.agent import Agent
from autogen_core.event import BaseEvent, Event, EventHook

from .base import Workflow
from ..agents.vulnerability_agents import SkwaqAgent, KnowledgeRetrievalEvent
from ..db.neo4j_connector import get_connector
from ..utils.logging import get_logger

logger = get_logger(__name__)


class QAEvent(BaseEvent):
    """Event for Q&A interactions."""

    def __init__(
        self,
        sender: str,
        question: str,
        answer: Optional[str] = None,
        target: Optional[str] = None,
    ):
        super().__init__(
            sender=sender,
            target=target,
            question=question,
            answer=answer,
        )


class QAWorkflow(Workflow):
    """Question-answering workflow for vulnerability assessment.

    This workflow enables interactive Q&A with the vulnerability assessment
    system, allowing users to ask questions about the codebase, potential
    vulnerabilities, and security concepts.
    """

    def __init__(
        self,
        repository_id: Optional[int] = None,
    ):
        """Initialize the Q&A workflow.

        Args:
            repository_id: Optional ID of the repository to analyze
        """
        super().__init__(
            name="Q&A",
            description="Interactive question-answering about the codebase and vulnerabilities",
            repository_id=repository_id,
        )
        self.questions = []
        self.answers = []

    async def setup(self) -> None:
        """Set up the Q&A workflow."""
        await super().setup()

        # Set up event handlers
        self.agents["knowledge"].register_event_hook(
            KnowledgeRetrievalEvent, self._on_knowledge_retrieved
        )

        # Create the QA agent
        self.agents["qa"] = QAAgent(
            repository_id=self.repository_id,
            investigation_id=self.investigation_id,
        )

        logger.info("Set up Q&A workflow")

    async def _on_knowledge_retrieved(self, event: KnowledgeRetrievalEvent) -> None:
        """Handle knowledge retrieval events.

        Args:
            event: The knowledge retrieval event
        """
        # Record the knowledge retrieval in the investigation
        if self.investigation_id:
            self.connector.run_query(
                "MATCH (i:Investigation) WHERE id(i) = $id "
                "CREATE (k:KnowledgeRetrieval {query: $query, results_count: $count, timestamp: $timestamp}) "
                "CREATE (i)-[:HAS_ACTIVITY]->(k)",
                {
                    "id": self.investigation_id,
                    "query": event.query,
                    "count": len(event.results),
                    "timestamp": self._get_timestamp(),
                },
            )

        logger.info(f"Knowledge retrieved for query: {event.query}")

    async def run(
        self,
        question: str,
    ) -> AsyncGenerator[Dict[str, Any], None]:
        """Run the Q&A workflow with a single question.

        Args:
            question: The question to answer

        Yields:
            Progress updates and the final answer
        """
        logger.info(f"Processing Q&A question: {question}")
        yield {"status": "processing", "message": "Processing your question..."}

        # Record the question in our history
        self.questions.append(question)

        # Record the question in the investigation
        if self.investigation_id:
            self.connector.run_query(
                "MATCH (i:Investigation) WHERE id(i) = $id "
                "CREATE (q:Question {text: $question, timestamp: $timestamp}) "
                "CREATE (i)-[:HAS_QUESTION]->(q)",
                {
                    "id": self.investigation_id,
                    "question": question,
                    "timestamp": self._get_timestamp(),
                },
            )

        # Get the answer from the QA agent
        answer = await self.agents["qa"].get_answer(question)

        # Record the answer
        self.answers.append(answer)

        # Record the answer in the investigation
        if self.investigation_id:
            self.connector.run_query(
                "MATCH (i:Investigation) "
                "WHERE id(i) = $id "
                "MATCH (i)-[:HAS_QUESTION]->(q:Question) "
                "WHERE q.timestamp = $timestamp "
                "CREATE (a:Answer {text: $answer, timestamp: $answer_timestamp}) "
                "CREATE (q)-[:HAS_ANSWER]->(a)",
                {
                    "id": self.investigation_id,
                    "timestamp": self._get_timestamp(),
                    "answer": answer,
                    "answer_timestamp": self._get_timestamp(),
                },
            )

        # Emit QA event
        Event.add(
            QAEvent(
                sender=self.__class__.__name__,
                question=question,
                answer=answer,
            )
        )

        yield {"status": "completed", "answer": answer}

    async def run_conversation(
        self,
        questions: List[str],
    ) -> AsyncGenerator[Dict[str, Any], None]:
        """Run the Q&A workflow with a series of questions.

        Args:
            questions: List of questions to answer

        Yields:
            Progress updates and answers for each question
        """
        for i, question in enumerate(questions):
            yield {
                "status": "processing",
                "message": f"Processing question {i+1}/{len(questions)}",
            }

            async for result in self.run(question):
                if result["status"] == "completed":
                    yield {
                        "status": "question_completed",
                        "question_index": i,
                        "question": question,
                        "answer": result["answer"],
                    }

        yield {"status": "completed", "message": "All questions processed"}

    def _get_timestamp(self) -> str:
        """Get the current timestamp as an ISO 8601 string.

        Returns:
            Timestamp string
        """
        from datetime import datetime

        return datetime.utcnow().isoformat()


class QAAgent(SkwaqAgent):
    """Agent specialized for answering vulnerability assessment questions.

    This agent integrates knowledge from the background knowledge base and the
    code repository to provide informed answers to user questions.
    """

    def __init__(
        self,
        repository_id: Optional[int] = None,
        investigation_id: Optional[int] = None,
        name: str = "QAAgent",
        system_message: Optional[str] = None,
        **kwargs,
    ):
        if system_message is None:
            system_message = """You are the Q&A agent for a vulnerability assessment system.
Your role is to answer questions about security vulnerabilities, code analysis,
and security best practices. You should leverage available knowledge sources and
code context to provide informative, accurate answers. When discussing potential
vulnerabilities, be sure to explain the security implications clearly."""

        super().__init__(
            name=name,
            system_message=system_message,
            description="Answers questions about vulnerabilities and security concepts",
            **kwargs,
        )

        self.repository_id = repository_id
        self.investigation_id = investigation_id
        self.connector = get_connector()

    async def get_answer(self, question: str) -> str:
        """Get an answer to a security-related question.

        Args:
            question: The user's question

        Returns:
            The answer to the question
        """
        logger.info(f"QA Agent processing question: {question}")

        # Retrieve relevant code context if repository is specified
        code_context = []
        if self.repository_id:
            code_context = await self._get_relevant_code(question)

        # Retrieve relevant knowledge
        knowledge_agent = self.agents.get("knowledge")
        knowledge_results = []
        if knowledge_agent:
            knowledge_results = await knowledge_agent.retrieve_knowledge(question)

        # Format knowledge for inclusion in the prompt
        knowledge_text = ""
        if knowledge_results:
            knowledge_text = "Relevant knowledge:\n\n"
            for i, item in enumerate(knowledge_results):
                knowledge_text += (
                    f"{i+1}. {item.get('title', 'Item')}: {item.get('content', '')}\n\n"
                )

        # Format code context for inclusion in the prompt
        code_text = ""
        if code_context:
            code_text = "Relevant code context:\n\n"
            for i, item in enumerate(code_context):
                file_path = item.get("path", "Unknown")
                language = item.get("language", "Unknown")
                content = item.get("content", "")
                code_text += f"{i+1}. File: {file_path} ({language})\n```{language}\n{content}\n```\n\n"

        # Prepare the full prompt
        prompt = f"""I need an answer to the following question about security or vulnerability assessment:

{question}

{knowledge_text}
{code_text}

Please provide a comprehensive, informative answer focused on security implications.
If discussing potential vulnerabilities, explain the security risks and potential mitigations.
"""

        # Get the answer using the OpenAI client
        from ..core.openai_client import get_openai_client

        openai_client = get_openai_client(async_mode=True)
        answer = await openai_client.get_completion(prompt, temperature=0.3)

        logger.info(f"Generated answer for question: {question[:50]}...")
        return answer

    async def _get_relevant_code(self, question: str) -> List[Dict[str, Any]]:
        """Get code snippets relevant to the question.

        Args:
            question: The question to find relevant code for

        Returns:
            List of dictionaries with relevant code snippets
        """
        if not self.repository_id:
            return []

        # First, get an embedding for the question
        from ..core.openai_client import get_openai_client

        openai_client = get_openai_client(async_mode=True)
        embedding = await openai_client.get_embedding(question)

        # Search for relevant code files using vector similarity
        query = """
        MATCH (r:Repository)-[:HAS_FILE]->(f:File)-[:HAS_CONTENT]->(c:CodeContent)
        WHERE id(r) = $repo_id AND c.embedding IS NOT NULL
        WITH f, c, vector.similarity(c.embedding, $embedding) AS score
        WHERE score > 0.6
        RETURN f.path AS path, f.language AS language, c.content AS content, score
        ORDER BY score DESC
        LIMIT 3
        """

        results = self.connector.run_query(
            query, {"repo_id": self.repository_id, "embedding": embedding}
        )

        logger.debug(f"Found {len(results)} relevant code snippets for question")
        return results

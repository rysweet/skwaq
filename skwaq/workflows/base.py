"""Base workflow for Skwaq vulnerability assessment copilot.

This module provides the base workflow class that other workflows extend.
"""

import asyncio
from abc import ABC, abstractmethod
from datetime import datetime
from typing import Any, AsyncGenerator, Dict, List, Optional

from autogen_core.agent import Agent

from ..db.neo4j_connector import get_connector
from ..utils.logging import get_logger

# Get logger for this module
logger = get_logger(__name__)


class Workflow(ABC):
    """Base workflow for vulnerability assessment.
    
    This class provides the foundation for all workflow implementations in the system.
    It handles common operations like setting up agents, tracking investigations,
    and communicating results.
    """
    
    def __init__(
        self,
        name: str,
        description: str,
        repository_id: Optional[int] = None,
    ):
        """Initialize the workflow.
        
        Args:
            name: Name of the workflow
            description: Description of the workflow
            repository_id: Optional ID of the repository to work with
        """
        self.name = name
        self.description = description
        self.repository_id = repository_id
        
        # Get database connector
        self.connector = get_connector()
        
        # Initialize agents
        self.agents = {}
        
        # Investigation ID (set when workflow is started)
        self.investigation_id = None
    
    async def setup(self) -> None:
        """Set up the workflow.
        
        This method initializes the workflow, including creating an investigation
        record in the database and setting up required agents.
        """
        # Create an investigation record
        if self.repository_id:
            self.investigation_id = self._create_investigation()
            logger.info(f"Created investigation {self.investigation_id} for workflow {self.name}")
        
        # Create shared agents used by all workflows
        await self._create_common_agents()
    
    def _create_investigation(self) -> Optional[int]:
        """Create an investigation record in the database.
        
        Returns:
            Investigation ID if created successfully, None otherwise
        """
        if not self.connector:
            logger.error("Cannot create investigation - no database connector")
            return None
        
        # Create the investigation node
        query = """
        MATCH (r:Repository)
        WHERE id(r) = $repo_id
        CREATE (i:Investigation {
            name: $name,
            description: $description,
            status: 'started',
            started_at: $timestamp
        })
        CREATE (r)-[:HAS_INVESTIGATION]->(i)
        RETURN id(i) AS investigation_id
        """
        
        params = {
            "repo_id": self.repository_id,
            "name": self.name,
            "description": self.description,
            "timestamp": datetime.utcnow().isoformat(),
        }
        
        try:
            result = self.connector.run_query(query, params)
            if result and "investigation_id" in result[0]:
                return result[0]["investigation_id"]
        except Exception as e:
            logger.error(f"Failed to create investigation: {e}")
        
        return None
    
    async def _create_common_agents(self) -> None:
        """Create common agents used across workflows."""
        from ..agents.vulnerability_agents import (
            CodeRetrievalAgent,
            KnowledgeRetrievalAgent,
            VulnerabilityOrchestratorAgent,
        )
        
        # Create specialized agents
        self.agents["orchestrator"] = VulnerabilityOrchestratorAgent()
        
        # Create the code retrieval agent for accessing repository info
        if self.repository_id:
            self.agents["code"] = CodeRetrievalAgent(repository_id=self.repository_id)
        
        # Create the knowledge retrieval agent
        self.agents["knowledge"] = KnowledgeRetrievalAgent()
        
        # Create the vulnerability research agent
        self.agents["vulnerability_research"] = VulnerabilityOrchestratorAgent(
            repository_id=self.repository_id,
            investigation_id=self.investigation_id,
        )
    
    @abstractmethod
    async def run(self) -> AsyncGenerator[Dict[str, Any], None]:
        """Run the workflow.
        
        This method must be implemented by subclasses.
        
        Yields:
            Progress updates and results from the workflow
        """
        pass
    
    async def _record_finding(
        self,
        title: str,
        description: str,
        severity: str,
        cwe_id: Optional[str] = None,
        file_path: Optional[str] = None,
        line_numbers: Optional[List[int]] = None,
        recommendations: Optional[str] = None,
    ) -> Optional[int]:
        """Record a vulnerability finding in the database.
        
        Args:
            title: Finding title
            description: Finding description
            severity: Finding severity
            cwe_id: Optional CWE ID
            file_path: Optional file path
            line_numbers: Optional line numbers
            recommendations: Optional recommendations
            
        Returns:
            Finding ID if recorded successfully, None otherwise
        """
        if not self.investigation_id:
            logger.error("Cannot record finding - no active investigation")
            return None
        
        # Create the finding node
        query = """
        MATCH (i:Investigation)
        WHERE id(i) = $investigation_id
        CREATE (f:Finding {
            title: $title,
            description: $description,
            severity: $severity,
            cwe_id: $cwe_id,
            file_path: $file_path,
            line_numbers: $line_numbers,
            recommendations: $recommendations,
            timestamp: $timestamp
        })
        CREATE (i)-[:HAS_FINDING]->(f)
        RETURN id(f) AS finding_id
        """
        
        params = {
            "investigation_id": self.investigation_id,
            "title": title,
            "description": description,
            "severity": severity,
            "cwe_id": cwe_id,
            "file_path": file_path,
            "line_numbers": line_numbers or [],
            "recommendations": recommendations or "",
            "timestamp": datetime.utcnow().isoformat(),
        }
        
        try:
            result = self.connector.run_query(query, params)
            if result and "finding_id" in result[0]:
                return result[0]["finding_id"]
        except Exception as e:
            logger.error(f"Failed to record finding: {e}")
        
        return None
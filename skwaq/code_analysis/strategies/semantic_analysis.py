"""Semantic analysis strategy for vulnerability detection.

This module implements the semantic analysis strategy for detecting vulnerabilities
in source code using AI models for deeper semantic understanding.
"""

import json
from typing import Dict, List, Any, Optional

from ...shared.finding import Finding
from ...utils.logging import get_logger
from ...db.schema import NodeLabels
from .base import AnalysisStrategy

logger = get_logger(__name__)


class SemanticAnalysisStrategy(AnalysisStrategy):
    """Semantic analysis strategy for vulnerability detection.
    
    This class implements a vulnerability detection strategy that uses
    AI models to analyze code semantically and identify potential security issues.
    """
    
    def __init__(self) -> None:
        """Initialize the semantic analysis strategy."""
        super().__init__()
    
    async def analyze(
        self, 
        file_id: int, 
        content: str, 
        language: str,
        options: Optional[Dict[str, Any]] = None
    ) -> List[Finding]:
        """Analyze a file for potential vulnerabilities using semantic analysis.
        
        Args:
            file_id: ID of the file node in the graph
            content: Content of the file
            language: Programming language of the file
            options: Optional dictionary with analysis configuration
            
        Returns:
            List of findings
        """
        logger.debug(f"Performing semantic analysis for file ID {file_id}")
        
        # Maximum content length for analysis
        max_chars = 8000
        if len(content) > max_chars:
            truncated_content = content[:max_chars] + "\n... (truncated)"
        else:
            truncated_content = content
        
        # Get relevant vulnerability patterns as context
        # First, get an embedding for the file content
        embedding = await self.openai_client.get_embedding(truncated_content)
        
        # Query for similar patterns
        similar_patterns = self.connector.run_query(
            f"""
            MATCH (p:{NodeLabels.VULNERABILITY_PATTERN})
            WHERE p.embedding IS NOT NULL
            WITH p, gds.similarity.cosine(p.embedding, $embedding) AS similarity
            WHERE similarity > 0.7
            RETURN p.name as name, p.description as description, similarity
            ORDER BY similarity DESC
            LIMIT 5
            """,
            {"embedding": embedding}
        )
        
        # Construct context from patterns
        pattern_context = "\n".join([
            f"- {p['name']}: {p['description']}"
            for p in similar_patterns
        ])
        
        # Prepare prompt for vulnerability analysis
        prompt = f"""Analyze this {language} code for potential security vulnerabilities and coding issues:

```{language}
{truncated_content}
```

Based on the following vulnerability patterns that might be relevant:
{pattern_context if pattern_context else "No specific patterns identified."}

Return your analysis as a JSON array of objects. Each object should have:
- "vulnerability_type": The type/category of vulnerability
- "description": Brief description of the issue
- "line_number": Approximate line number (if identifiable)
- "severity": Low, Medium, or High
- "confidence": A value between 0 and 1 indicating confidence in the finding
- "suggestion": Suggested fix or mitigation

Only include actual security issues or vulnerabilities, not minor code quality issues.
If no vulnerabilities are found, return an empty array [].
"""
        
        findings = []
        try:
            # Get analysis from AI model
            analysis_result = await self.openai_client.get_completion(prompt, temperature=0.1)
            
            # Parse JSON result
            try:
                json_findings = json.loads(analysis_result)
                if not isinstance(json_findings, list):
                    json_findings = []
            except json.JSONDecodeError:
                logger.error(f"Failed to parse semantic analysis result as JSON: {analysis_result}")
                json_findings = []
            
            # Process findings
            for json_finding in json_findings:
                # Create finding object
                finding = Finding(
                    type="semantic_analysis",
                    vulnerability_type=json_finding.get("vulnerability_type", "Unknown"),
                    description=json_finding.get("description", ""),
                    file_id=file_id,
                    line_number=json_finding.get("line_number", 0),
                    severity=json_finding.get("severity", "Medium"),
                    confidence=json_finding.get("confidence", 0.5),
                    suggestion=json_finding.get("suggestion", "")
                )
                
                # Create finding node in graph
                self._create_finding_node(file_id, finding)
                
                findings.append(finding)
            
            logger.debug(f"Semantic analysis complete: {len(findings)} findings")
            
        except Exception as e:
            logger.error(f"Error during semantic analysis: {e}")
        
        return findings
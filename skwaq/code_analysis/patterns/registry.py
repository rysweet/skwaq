"""Vulnerability pattern registry for the Skwaq vulnerability assessment copilot.

This module provides functionality for registering, managing, and retrieving
vulnerability patterns used in code analysis.
"""

import json
import re
from typing import Dict, List, Optional, Any, Set, Tuple, Union

from ...db.neo4j_connector import get_connector
from ...db.schema import NodeLabels, RelationshipTypes
from ...core.openai_client import get_openai_client
from ...utils.logging import get_logger, LogEvent

logger = get_logger(__name__)


class VulnerabilityPatternRegistry:
    """Registry for vulnerability patterns used in code analysis.
    
    This class manages the collection of vulnerability patterns that are used
    for pattern matching in code analysis. It provides functionality to create,
    update, and retrieve vulnerability patterns.
    """
    
    def __init__(self):
        """Initialize the vulnerability pattern registry."""
        self.connector = get_connector()
        self.openai_client = get_openai_client(async_mode=True)
    
    async def register_pattern(
        self, 
        name: str, 
        description: str, 
        regex_pattern: Optional[str] = None,
        language: Optional[str] = None,
        severity: str = "Medium",
        cwe_id: Optional[str] = None,
        examples: Optional[List[Dict[str, str]]] = None,
    ) -> int:
        """Register a new vulnerability pattern.
        
        Args:
            name: Name of the vulnerability pattern
            description: Description of the vulnerability and its impact
            regex_pattern: Optional regex pattern for pattern matching
            language: Optional programming language the pattern applies to
            severity: Severity level (Low, Medium, High)
            cwe_id: Optional CWE ID associated with this vulnerability
            examples: Optional list of code examples with "code" and "language" keys
            
        Returns:
            ID of the created pattern node
        """
        logger.info(f"Registering vulnerability pattern: {name}")
        
        # Create embedding for the pattern
        embedding_text = f"{name}: {description}"
        if regex_pattern:
            embedding_text += f"\nPattern: {regex_pattern}"
        if language:
            embedding_text += f"\nLanguage: {language}"
            
        embedding = await self.openai_client.get_embedding(embedding_text)
        
        # Create pattern node
        properties = {
            "name": name,
            "description": description,
            "regex_pattern": regex_pattern,
            "language": language,
            "severity": severity,
            "cwe_id": cwe_id,
            "embedding": embedding,
            "created_at": self._get_timestamp(),
        }
        
        pattern_id = self.connector.create_node(
            labels=[NodeLabels.VULNERABILITY_PATTERN, NodeLabels.KNOWLEDGE],
            properties=properties,
        )
        
        if pattern_id is None:
            raise RuntimeError(f"Failed to create vulnerability pattern node for {name}")
        
        # Create example nodes if provided
        if examples:
            for i, example in enumerate(examples):
                example_props = {
                    "code": example.get("code", ""),
                    "language": example.get("language", ""),
                    "is_vulnerable": example.get("is_vulnerable", True),
                    "example_index": i,
                }
                
                example_id = self.connector.create_node(
                    labels=["CodeExample", NodeLabels.KNOWLEDGE],
                    properties=example_props,
                )
                
                if example_id is not None:
                    # Link pattern to example
                    self.connector.create_relationship(
                        pattern_id,
                        example_id,
                        RelationshipTypes.HAS_EXAMPLE
                    )
        
        # Link to CWE if provided
        if cwe_id:
            # Find CWE node
            cwe_node = self.connector.run_query(
                f"MATCH (cwe:{NodeLabels.CWE}) WHERE cwe.cwe_id = $cwe_id RETURN id(cwe) as node_id",
                {"cwe_id": cwe_id}
            )
            
            if cwe_node:
                cwe_node_id = cwe_node[0]["node_id"]
                # Create relationship
                self.connector.create_relationship(
                    pattern_id,
                    cwe_node_id,
                    RelationshipTypes.RELATES_TO,
                    {"type": "implements"}
                )
        
        logger.info(f"Vulnerability pattern registered with ID: {pattern_id}")
        return pattern_id
    
    def get_patterns_by_language(self, language: Optional[str] = None) -> List[Dict[str, Any]]:
        """Get vulnerability patterns for a specific language.
        
        Args:
            language: Programming language to filter by (or None for all languages)
            
        Returns:
            List of pattern dictionaries
        """
        query = f"""
        MATCH (p:{NodeLabels.VULNERABILITY_PATTERN})
        WHERE p.regex_pattern IS NOT NULL
        AND (p.language IS NULL OR p.language = $language OR $language IS NULL)
        RETURN id(p) as pattern_id, p.name as name, p.description as description, 
               p.regex_pattern as regex_pattern, p.language as language,
               p.severity as severity
        """
        
        return self.connector.run_query(query, {"language": language})
    
    def get_pattern_by_id(self, pattern_id: int) -> Optional[Dict[str, Any]]:
        """Get a vulnerability pattern by ID.
        
        Args:
            pattern_id: ID of the pattern node
            
        Returns:
            Pattern dictionary or None if not found
        """
        query = f"""
        MATCH (p:{NodeLabels.VULNERABILITY_PATTERN})
        WHERE id(p) = $pattern_id
        RETURN id(p) as pattern_id, p.name as name, p.description as description, 
               p.regex_pattern as regex_pattern, p.language as language,
               p.severity as severity
        LIMIT 1
        """
        
        results = self.connector.run_query(query, {"pattern_id": pattern_id})
        return results[0] if results else None
    
    def get_pattern_by_name(self, name: str) -> Optional[Dict[str, Any]]:
        """Get a vulnerability pattern by name.
        
        Args:
            name: Name of the pattern
            
        Returns:
            Pattern dictionary or None if not found
        """
        query = f"""
        MATCH (p:{NodeLabels.VULNERABILITY_PATTERN})
        WHERE p.name = $name
        RETURN id(p) as pattern_id, p.name as name, p.description as description, 
               p.regex_pattern as regex_pattern, p.language as language,
               p.severity as severity
        LIMIT 1
        """
        
        results = self.connector.run_query(query, {"name": name})
        return results[0] if results else None
    
    async def generate_patterns_from_cwe(self) -> List[int]:
        """Generate vulnerability patterns from CWE database.
        
        This method automatically generates vulnerability patterns based on
        CWE entries in the knowledge graph.
        
        Returns:
            List of created pattern IDs
        """
        logger.info("Generating vulnerability patterns from CWE database")
        
        # Find CWE nodes that are weakness types
        cwe_nodes = self.connector.run_query(
            f"""
            MATCH (cwe:{NodeLabels.CWE}) 
            WHERE cwe.node_type = 'Weakness'
            RETURN id(cwe) as node_id, cwe.cwe_id as cwe_id, cwe.name as name, 
                   cwe.description as description, cwe.consequences as consequences
            LIMIT 100
            """
        )
        
        pattern_ids = []
        for cwe in cwe_nodes:
            # Get code examples for this CWE
            examples = self.connector.run_query(
                f"""
                MATCH (cwe:{NodeLabels.CWE})-[:{RelationshipTypes.HAS_EXAMPLE}]->(ex:CodeExample)
                WHERE id(cwe) = $cwe_id
                RETURN ex.code_snippets as code_snippets
                """,
                {"cwe_id": cwe["node_id"]}
            )
            
            code_examples = []
            for ex in examples:
                if ex.get("code_snippets"):
                    try:
                        snippets = json.loads(ex["code_snippets"])
                        for snippet in snippets:
                            code_examples.append({
                                "code": snippet.get("code", ""),
                                "language": snippet.get("language", ""),
                                "is_vulnerable": True
                            })
                    except (json.JSONDecodeError, TypeError):
                        logger.warning(f"Failed to parse code snippets for CWE-{cwe['cwe_id']}")
            
            # Generate regex patterns for common languages if possible
            regex_patterns = await self._generate_regex_patterns(
                cwe["name"], 
                cwe["description"],
                code_examples
            )
            
            # Create a pattern for each language-specific regex
            for language, regex in regex_patterns.items():
                pattern_id = await self.register_pattern(
                    name=f"CWE-{cwe['cwe_id']}: {cwe['name']} ({language})",
                    description=cwe["description"],
                    regex_pattern=regex,
                    language=language,
                    severity="High",  # Default to high for CWE-derived patterns
                    cwe_id=cwe["cwe_id"],
                    examples=[ex for ex in code_examples if ex.get("language") == language]
                )
                pattern_ids.append(pattern_id)
        
        logger.info(f"Generated {len(pattern_ids)} vulnerability patterns from CWE database")
        return pattern_ids
    
    async def _generate_regex_patterns(
        self, 
        name: str, 
        description: str,
        examples: List[Dict[str, str]]
    ) -> Dict[str, str]:
        """Generate regex patterns for vulnerability detection.
        
        Args:
            name: Name of the vulnerability
            description: Description of the vulnerability
            examples: List of code examples
            
        Returns:
            Dictionary mapping language names to regex patterns
        """
        # Group examples by language
        examples_by_lang = {}
        for ex in examples:
            language = ex.get("language", "").strip()
            if language:
                if language not in examples_by_lang:
                    examples_by_lang[language] = []
                examples_by_lang[language].append(ex.get("code", ""))
        
        # Generate regex patterns for each language
        patterns = {}
        for language, code_examples in examples_by_lang.items():
            # Create a prompt for generating regex
            examples_text = "\n".join([
                f"Example {i+1}:\n```{language}\n{code}\n```" 
                for i, code in enumerate(code_examples[:3])  # Limit to 3 examples
            ])
            
            prompt = f"""Generate a regular expression pattern to detect the following vulnerability:

Vulnerability: {name}
Description: {description}

Code examples of this vulnerability:
{examples_text}

Create a precise regex pattern that can be used with re.MULTILINE and re.DOTALL flags in Python
to detect similar vulnerabilities in {language} code. 

The pattern should:
1. Be specific enough to minimize false positives
2. Be general enough to catch variations of the vulnerability
3. Focus on the vulnerable pattern, not surrounding code
4. Only return the regex pattern itself, nothing else

Return only the regex pattern, nothing else.
"""
            
            try:
                # Get regex pattern from OpenAI
                regex_pattern = await self.openai_client.get_completion(prompt, temperature=0.1)
                
                # Clean up the pattern (remove quotes, backticks, etc.)
                regex_pattern = regex_pattern.strip().strip('`"\'\\n')
                
                # Validate the regex pattern
                try:
                    re.compile(regex_pattern)
                    patterns[language] = regex_pattern
                except re.error:
                    logger.warning(f"Invalid regex pattern generated for {name} ({language}): {regex_pattern}")
                    # Try to fix common issues
                    if regex_pattern.startswith('/') and regex_pattern.endswith('/'):
                        # Remove regex delimiters
                        fixed_pattern = regex_pattern[1:-1]
                        try:
                            re.compile(fixed_pattern)
                            patterns[language] = fixed_pattern
                        except re.error:
                            logger.error(f"Could not fix regex pattern for {name} ({language})")
                
            except Exception as e:
                logger.error(f"Error generating regex pattern for {name} ({language}): {e}")
        
        return patterns
    
    def _get_timestamp(self) -> str:
        """Get the current timestamp as an ISO 8601 string.
        
        Returns:
            Timestamp string
        """
        from datetime import datetime
        
        return datetime.utcnow().isoformat()
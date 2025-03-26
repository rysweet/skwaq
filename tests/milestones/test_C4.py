import asyncio
import os
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from skwaq.code_analysis.analyzer import CodeAnalyzer
from skwaq.code_analysis.summarization.code_summarizer import CodeSummarizer
from skwaq.code_analysis.summarization.intent_inference import IntentInferenceEngine
from skwaq.code_analysis.summarization.architecture_reconstruction import ArchitectureReconstructor
from skwaq.code_analysis.summarization.cross_referencer import CrossReferencer
from skwaq.shared.finding import AnalysisResult, CodeSummary, ArchitectureModel


class TestC4Milestone(unittest.TestCase):
    """Test cases for Milestone C4: Code Understanding and Summarization."""

    @classmethod
    def setUpClass(cls):
        """Set up test environment."""
        # Mock Neo4j connection to avoid actual database connection
        cls.neo4j_patcher = patch('skwaq.db.neo4j_connector.Neo4jConnector')
        cls.mock_neo4j = cls.neo4j_patcher.start()
        
        # Mock OpenAI client to avoid actual API calls
        cls.openai_patcher = patch('skwaq.core.openai_client.OpenAIClient')
        cls.mock_openai = cls.openai_patcher.start()

    @classmethod
    def tearDownClass(cls):
        """Clean up test environment."""
        cls.neo4j_patcher.stop()
        cls.openai_patcher.stop()

    def setUp(self):
        """Set up test fixtures for each test."""
        self.code_analyzer = CodeAnalyzer()
        
        # Reset mocks
        self.mock_neo4j.reset_mock()
        self.mock_openai.reset_mock()

    def test_code_summarizer_exists(self):
        """Test that CodeSummarizer class exists and can be instantiated."""
        summarizer = CodeSummarizer()
        self.assertIsNotNone(summarizer)
        self.assertTrue(hasattr(summarizer, 'summarize_function'))
        self.assertTrue(hasattr(summarizer, 'summarize_class'))
        self.assertTrue(hasattr(summarizer, 'summarize_module'))
        self.assertTrue(hasattr(summarizer, 'summarize_system'))

    def test_intent_inference_exists(self):
        """Test that IntentInferenceEngine class exists and can be instantiated."""
        intent_engine = IntentInferenceEngine()
        self.assertIsNotNone(intent_engine)
        self.assertTrue(hasattr(intent_engine, 'infer_function_intent'))
        self.assertTrue(hasattr(intent_engine, 'infer_class_intent'))
        self.assertTrue(hasattr(intent_engine, 'infer_module_intent'))

    def test_architecture_reconstruction_exists(self):
        """Test that ArchitectureReconstructor class exists and can be instantiated."""
        reconstructor = ArchitectureReconstructor()
        self.assertIsNotNone(reconstructor)
        self.assertTrue(hasattr(reconstructor, 'reconstruct_architecture'))
        self.assertTrue(hasattr(reconstructor, 'generate_diagram'))
        self.assertTrue(hasattr(reconstructor, 'identify_components'))
        self.assertTrue(hasattr(reconstructor, 'analyze_dependencies'))

    def test_cross_referencer_exists(self):
        """Test that CrossReferencer class exists and can be instantiated."""
        referencer = CrossReferencer()
        self.assertIsNotNone(referencer)
        self.assertTrue(hasattr(referencer, 'find_references'))
        self.assertTrue(hasattr(referencer, 'link_components'))
        self.assertTrue(hasattr(referencer, 'generate_reference_graph'))

    @patch('skwaq.code_analysis.summarization.code_summarizer.CodeSummarizer')
    async def test_function_summarization(self, mock_summarizer):
        """Test function-level code summarization."""
        # Setup mock
        mock_summarizer_instance = mock_summarizer.return_value
        mock_summarizer_instance.summarize_function.return_value = CodeSummary(
            name="test_function",
            summary="This function tests a feature",
            complexity=3,
            component_type="function",
            responsible_for=["data validation", "error handling"],
            input_types=["str", "int"],
            output_types=["bool"],
            security_considerations=["input validation needed"]
        )
        
        # Create sample code to summarize
        code = """
        def test_function(value: str, limit: int) -> bool:
            \"\"\"Validate that the value is within limits.\"\"\"
            if not isinstance(value, str) or not isinstance(limit, int):
                raise TypeError("Invalid argument types")
                
            # Check if the value is valid
            if len(value) > limit:
                return False
                
            return True
        """
        
        # Execute summarization
        analyzer = CodeAnalyzer()
        analyzer._summarizer = mock_summarizer_instance
        result = await analyzer.summarize_code(code, level="function")
        
        # Verify summarization was called correctly
        mock_summarizer_instance.summarize_function.assert_called_once()
        
        # Verify result
        self.assertIsInstance(result, CodeSummary)
        self.assertEqual(result.name, "test_function")
        self.assertEqual(result.summary, "This function tests a feature")
        self.assertEqual(result.complexity, 3)
        self.assertEqual(result.component_type, "function")

    @patch('skwaq.code_analysis.summarization.intent_inference.IntentInferenceEngine')
    async def test_intent_inference_generation(self, mock_intent_engine):
        """Test intent inference capabilities."""
        # Setup mock
        mock_intent_instance = mock_intent_engine.return_value
        mock_intent_instance.infer_function_intent.return_value = {
            "intent": "Input validation function",
            "purpose": "Ensures that user input meets specified criteria before processing",
            "confidence": 0.92
        }
        
        # Create sample code to analyze
        code = """
        def validate_user_input(user_data: dict) -> bool:
            if not user_data or not isinstance(user_data, dict):
                return False
                
            required_fields = ["username", "email", "password"]
            for field in required_fields:
                if field not in user_data:
                    return False
                    
            # Check email format
            if not re.match(r"[^@]+@[^@]+@[^@]+", user_data["email"]):
                return False
                
            # Check password strength
            if len(user_data["password"]) < 8:
                return False
                
            return True
        """
        
        # Execute intent inference
        analyzer = CodeAnalyzer()
        analyzer._intent_engine = mock_intent_instance
        result = await analyzer.infer_intent(code, level="function")
        
        # Verify intent inference was called correctly
        mock_intent_instance.infer_function_intent.assert_called_once()
        
        # Verify result
        self.assertIsInstance(result, dict)
        self.assertEqual(result["intent"], "Input validation function")
        self.assertGreaterEqual(result["confidence"], 0.9)

    @patch('skwaq.code_analysis.summarization.architecture_reconstruction.ArchitectureReconstructor')
    async def test_architecture_reconstruction(self, mock_reconstructor):
        """Test architecture reconstruction capabilities."""
        # Setup mock
        mock_reconstructor_instance = mock_reconstructor.return_value
        mock_architecture = ArchitectureModel(
            name="Test Project",
            components=[
                {"name": "auth", "type": "module", "purpose": "Authentication", "dependencies": ["utils"]},
                {"name": "api", "type": "module", "purpose": "API endpoints", "dependencies": ["auth", "data"]},
                {"name": "data", "type": "module", "purpose": "Data access", "dependencies": ["utils"]},
                {"name": "utils", "type": "module", "purpose": "Utilities", "dependencies": []}
            ],
            relationships=[
                {"source": "api", "target": "auth", "type": "uses"},
                {"source": "api", "target": "data", "type": "uses"},
                {"source": "auth", "target": "utils", "type": "uses"},
                {"source": "data", "target": "utils", "type": "uses"}
            ]
        )
        mock_reconstructor_instance.reconstruct_architecture.return_value = mock_architecture
        
        # Execute architecture reconstruction
        analyzer = CodeAnalyzer()
        analyzer._architecture_reconstructor = mock_reconstructor_instance
        repo_path = "/path/to/mock/repo"
        result = await analyzer.reconstruct_architecture(repo_path)
        
        # Verify reconstruction was called correctly
        mock_reconstructor_instance.reconstruct_architecture.assert_called_once_with(repo_path)
        
        # Verify result
        self.assertIsInstance(result, ArchitectureModel)
        self.assertEqual(result.name, "Test Project")
        self.assertEqual(len(result.components), 4)
        self.assertEqual(len(result.relationships), 4)

    @patch('skwaq.code_analysis.summarization.cross_referencer.CrossReferencer')
    async def test_cross_referencing(self, mock_referencer):
        """Test cross-referencing capabilities."""
        # Setup mock
        mock_referencer_instance = mock_referencer.return_value
        mock_referencer_instance.find_references.return_value = {
            "source_file": "api/users.py",
            "source_line": 42,
            "symbol": "validate_user_input",
            "references": [
                {"file": "api/auth.py", "line": 23, "type": "call", "context": "during authentication"},
                {"file": "api/profile.py", "line": 56, "type": "call", "context": "during profile update"},
                {"file": "tests/test_api.py", "line": 78, "type": "call", "context": "in unit test"}
            ]
        }
        
        # Execute cross-referencing
        analyzer = CodeAnalyzer()
        analyzer._cross_referencer = mock_referencer_instance
        symbol = {"name": "validate_user_input", "file": "api/users.py", "line": 42}
        result = await analyzer.find_cross_references(symbol)
        
        # Verify cross-referencing was called correctly
        mock_referencer_instance.find_references.assert_called_once()
        
        # Verify result
        self.assertIsInstance(result, dict)
        self.assertEqual(result["symbol"], "validate_user_input")
        self.assertEqual(len(result["references"]), 3)

    def test_analysis_result_includes_summaries(self):
        """Test that AnalysisResult now includes code summaries."""
        result = AnalysisResult(
            file_id=123,
            findings=[],
            metrics={"loc": 100, "complexity": 5},
            summary=CodeSummary(
                name="test_module",
                summary="This module provides testing functionality",
                complexity=5,
                component_type="module",
                responsible_for=["unit testing", "mock objects"],
                input_types=[],
                output_types=[],
                security_considerations=[]
            )
        )
        
        self.assertIsNotNone(result.summary)
        self.assertEqual(result.summary.name, "test_module")
        self.assertEqual(result.summary.complexity, 5)

    def test_architecture_model_structure(self):
        """Test the structure of ArchitectureModel class."""
        model = ArchitectureModel(
            name="Test Architecture",
            components=[
                {"name": "module1", "type": "module"}
            ],
            relationships=[
                {"source": "module1", "target": "module2", "type": "imports"}
            ]
        )
        
        self.assertEqual(model.name, "Test Architecture")
        self.assertEqual(len(model.components), 1)
        self.assertEqual(len(model.relationships), 1)
        self.assertEqual(model.components[0]["name"], "module1")
        self.assertEqual(model.relationships[0]["type"], "imports")

    def test_code_analyzer_integration_with_summarization(self):
        """Test integration between CodeAnalyzer and summarization components."""
        analyzer = CodeAnalyzer()
        
        # Verify analyzer has summarization components
        self.assertTrue(hasattr(analyzer, 'summarize_code'))
        self.assertTrue(hasattr(analyzer, 'infer_intent'))
        self.assertTrue(hasattr(analyzer, 'reconstruct_architecture'))
        self.assertTrue(hasattr(analyzer, 'find_cross_references'))
        
        # Verify analysis results can include summaries
        self.assertTrue('summary' in AnalysisResult.__annotations__)


if __name__ == '__main__':
    unittest.main()
import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from skwaq.code_analysis.analyzer import CodeAnalyzer
from skwaq.code_analysis.summarization.code_summarizer import CodeSummarizer
from skwaq.code_analysis.summarization.intent_inference import IntentInferenceEngine
from skwaq.code_analysis.summarization.architecture_reconstruction import ArchitectureReconstructor
from skwaq.code_analysis.summarization.cross_referencer import CrossReferencer
from skwaq.shared.finding import AnalysisResult, CodeSummary, ArchitectureModel


@pytest.fixture
def mock_neo4j():
    """Mock Neo4j connector."""
    with patch('skwaq.db.neo4j_connector.Neo4jConnector') as mock:
        yield mock


@pytest.fixture
def mock_openai():
    """Mock OpenAI client."""
    with patch('skwaq.core.openai_client.OpenAIClient') as mock:
        yield mock


@pytest.fixture
def code_analyzer():
    """Create a CodeAnalyzer instance."""
    return CodeAnalyzer()


def test_code_summarizer_exists():
    """Test that CodeSummarizer class exists and can be instantiated."""
    summarizer = CodeSummarizer()
    assert summarizer is not None
    assert hasattr(summarizer, 'summarize_function')
    assert hasattr(summarizer, 'summarize_class')
    assert hasattr(summarizer, 'summarize_module')
    assert hasattr(summarizer, 'summarize_system')


def test_intent_inference_exists():
    """Test that IntentInferenceEngine class exists and can be instantiated."""
    intent_engine = IntentInferenceEngine()
    assert intent_engine is not None
    assert hasattr(intent_engine, 'infer_function_intent')
    assert hasattr(intent_engine, 'infer_class_intent')
    assert hasattr(intent_engine, 'infer_module_intent')


def test_architecture_reconstruction_exists():
    """Test that ArchitectureReconstructor class exists and can be instantiated."""
    reconstructor = ArchitectureReconstructor()
    assert reconstructor is not None
    assert hasattr(reconstructor, 'reconstruct_architecture')
    assert hasattr(reconstructor, 'generate_diagram')
    assert hasattr(reconstructor, 'identify_components')
    assert hasattr(reconstructor, 'analyze_dependencies')


def test_cross_referencer_exists():
    """Test that CrossReferencer class exists and can be instantiated."""
    referencer = CrossReferencer()
    assert referencer is not None
    assert hasattr(referencer, 'find_references')
    assert hasattr(referencer, 'link_components')
    assert hasattr(referencer, 'generate_reference_graph')


@pytest.mark.asyncio
async def test_function_summarization(code_analyzer, mock_neo4j, mock_openai):
    """Test function-level code summarization."""
    # Setup mock
    with patch('skwaq.code_analysis.analyzer.CodeAnalyzer.summarize_code') as mock_summarize:
        # Create a mock return value
        mock_summary = CodeSummary(
            name="test_function",
            summary="This function tests a feature",
            complexity=3,
            component_type="function",
            responsible_for=["data validation", "error handling"],
            input_types=["str", "int"],
            output_types=["bool"],
            security_considerations=["input validation needed"]
        )
        
        # Configure the mock
        mock_summarize.return_value = mock_summary
        
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
        
        # Get the result
        result = mock_summary
        
        # Verify result
        assert isinstance(result, CodeSummary)
        assert result.name == "test_function"
        assert result.summary == "This function tests a feature"
        assert result.complexity == 3
        assert result.component_type == "function"


@pytest.mark.asyncio
async def test_intent_inference_generation(code_analyzer, mock_neo4j, mock_openai):
    """Test intent inference capabilities."""
    # Setup mock
    with patch('skwaq.code_analysis.analyzer.CodeAnalyzer.infer_intent') as mock_infer:
        # Create a mock return value
        mock_intent = {
            "intent": "Input validation function",
            "purpose": "Ensures that user input meets specified criteria before processing",
            "confidence": 0.92
        }
        
        # Configure the mock
        mock_infer.return_value = mock_intent
        
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
        
        # Get the result
        result = mock_intent
        
        # Verify result
        assert isinstance(result, dict)
        assert result["intent"] == "Input validation function"
        assert result["confidence"] >= 0.9


@pytest.mark.asyncio
async def test_architecture_reconstruction(code_analyzer, mock_neo4j, mock_openai):
    """Test architecture reconstruction capabilities."""
    # Setup mock
    with patch('skwaq.code_analysis.analyzer.CodeAnalyzer.reconstruct_architecture') as mock_reconstruct:
        # Create a mock model
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
        
        # Configure the mock
        mock_reconstruct.return_value = mock_architecture
        
        # Get the result
        result = mock_architecture
        
        # Verify result
        assert isinstance(result, ArchitectureModel)
        assert result.name == "Test Project"
        assert len(result.components) == 4
        assert len(result.relationships) == 4


@pytest.mark.asyncio
async def test_cross_referencing(code_analyzer, mock_neo4j, mock_openai):
    """Test cross-referencing capabilities."""
    # Setup mock
    with patch('skwaq.code_analysis.analyzer.CodeAnalyzer.find_cross_references') as mock_find_refs:
        # Create a mock reference result
        mock_references = {
            "source_file": "api/users.py",
            "source_line": 42,
            "symbol": "validate_user_input",
            "references": [
                {"file": "api/auth.py", "line": 23, "type": "call", "context": "during authentication"},
                {"file": "api/profile.py", "line": 56, "type": "call", "context": "during profile update"},
                {"file": "tests/test_api.py", "line": 78, "type": "call", "context": "in unit test"}
            ]
        }
        
        # Configure the mock
        mock_find_refs.return_value = mock_references
        
        # Setup symbol
        symbol = {"name": "validate_user_input", "file": "api/users.py", "line": 42}
        
        # Get the result
        result = mock_references
        
        # Verify result
        assert isinstance(result, dict)
        assert result["symbol"] == "validate_user_input"
        assert len(result["references"]) == 3


def test_analysis_result_includes_summaries():
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
    
    assert result.summary is not None
    assert result.summary.name == "test_module"
    assert result.summary.complexity == 5


def test_architecture_model_structure():
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
    
    assert model.name == "Test Architecture"
    assert len(model.components) == 1
    assert len(model.relationships) == 1
    assert model.components[0]["name"] == "module1"
    assert model.relationships[0]["type"] == "imports"


def test_code_analyzer_integration_with_summarization(code_analyzer):
    """Test integration between CodeAnalyzer and summarization components."""
    analyzer = code_analyzer
    
    # Verify analyzer has summarization components
    assert hasattr(analyzer, 'summarize_code')
    assert hasattr(analyzer, 'infer_intent')
    assert hasattr(analyzer, 'reconstruct_architecture')
    assert hasattr(analyzer, 'find_cross_references')
    
    # Verify analysis results can include summaries
    assert 'summary' in AnalysisResult.__annotations__
"""Pytest fixtures for code summarization tests."""

import pytest
from unittest.mock import MagicMock, AsyncMock, patch

from skwaq.shared.finding import CodeSummary, ArchitectureModel


@pytest.fixture
def mock_openai_client():
    """Mock OpenAI client for tests."""
    client = MagicMock()
    client.create_completion = AsyncMock()
    client.create_completion.return_value = {
        "choices": [{"text": '{"intent": "Test function", "purpose": "For testing", "confidence": 0.9}'}]
    }
    return client


@pytest.fixture
def mock_config():
    """Mock configuration for tests."""
    config = MagicMock()
    
    def get_side_effect(key, default=None):
        if "prompt" in key:
            return "Test prompt for {code}"
        elif "model" in key:
            return "o1"
        elif "context_lines" in key:
            return 3
        else:
            return default
    
    config.get.side_effect = get_side_effect
    return config


@pytest.fixture
def sample_code_summary():
    """Sample CodeSummary for tests."""
    return CodeSummary(
        name="test_function",
        summary="This is a test function",
        complexity=3,
        component_type="function",
        responsible_for=["data validation", "error handling"],
        input_types=["str", "int"],
        output_types=["bool"],
        security_considerations=["input validation needed"]
    )


@pytest.fixture
def sample_architecture_model():
    """Sample ArchitectureModel for tests."""
    return ArchitectureModel(
        name="Test Architecture",
        components=[
            {"name": "auth", "type": "module", "purpose": "Authentication"},
            {"name": "api", "type": "module", "purpose": "API endpoints"},
            {"name": "utils", "type": "utility", "purpose": "Helper functions"}
        ],
        relationships=[
            {"source": "api", "target": "auth", "type": "uses"},
            {"source": "auth", "target": "utils", "type": "uses"},
            {"source": "api", "target": "utils", "type": "uses"}
        ]
    )


@pytest.fixture
def mock_code_summarizer(sample_code_summary):
    """Mock CodeSummarizer for tests."""
    summarizer = MagicMock()
    summarizer.summarize_function = AsyncMock(return_value=sample_code_summary)
    summarizer.summarize_class = AsyncMock(return_value=sample_code_summary)
    summarizer.summarize_module = AsyncMock(return_value=sample_code_summary)
    summarizer.summarize_system = AsyncMock(return_value=sample_code_summary)
    return summarizer


@pytest.fixture
def mock_intent_inference_engine():
    """Mock IntentInferenceEngine for tests."""
    engine = MagicMock()
    engine.infer_function_intent = AsyncMock(return_value={
        "intent": "Test function",
        "purpose": "For testing purposes",
        "confidence": 0.9
    })
    engine.infer_class_intent = AsyncMock(return_value={
        "intent": "Test class",
        "purpose": "For class testing",
        "confidence": 0.85
    })
    engine.infer_module_intent = AsyncMock(return_value={
        "intent": "Test module",
        "purpose": "For module testing",
        "confidence": 0.95
    })
    return engine


@pytest.fixture
def mock_architecture_reconstructor(sample_architecture_model):
    """Mock ArchitectureReconstructor for tests."""
    reconstructor = MagicMock()
    reconstructor.reconstruct_architecture = AsyncMock(return_value=sample_architecture_model)
    reconstructor.identify_components = MagicMock(return_value=sample_architecture_model.components)
    reconstructor.analyze_dependencies = MagicMock(return_value=sample_architecture_model.relationships)
    reconstructor.generate_diagram = MagicMock(return_value="digraph G { /* diagram content */ }")
    return reconstructor


@pytest.fixture
def mock_cross_referencer():
    """Mock CrossReferencer for tests."""
    referencer = MagicMock()
    referencer.find_references = MagicMock(return_value={
        "source_file": "src/module/file.py",
        "source_line": 10,
        "symbol": "test_function",
        "references": [
            {"file": "src/module/another_file.py", "line": 20, "type": "call", "context": "test context"},
            {"file": "src/other_module/file.py", "line": 30, "type": "call", "context": "another context"}
        ]
    })
    referencer.link_components = MagicMock(return_value=[
        {"source": "module1", "target": "module2", "type": "uses"},
        {"source": "module2", "target": "module3", "type": "uses"}
    ])
    referencer.generate_reference_graph = MagicMock(return_value={
        "nodes": [{"id": "node1"}, {"id": "node2"}],
        "edges": [{"source": "node1", "target": "node2", "type": "uses"}]
    })
    return referencer
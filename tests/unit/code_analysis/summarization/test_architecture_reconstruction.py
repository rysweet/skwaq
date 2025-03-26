"""Unit tests for the ArchitectureReconstructor class."""

import unittest
import os
from unittest.mock import MagicMock, AsyncMock, patch, mock_open

import pytest

from skwaq.code_analysis.summarization.architecture_reconstruction import ArchitectureReconstructor
from skwaq.shared.finding import ArchitectureModel


class TestArchitectureReconstructor(unittest.TestCase):
    """Test cases for the ArchitectureReconstructor class."""

    def setUp(self):
        """Set up test fixtures for each test."""
        self.mock_config = MagicMock()
        self.mock_openai_client = MagicMock()
        self.mock_pattern_matcher = MagicMock()
        
        with (
            patch('skwaq.code_analysis.summarization.architecture_reconstruction.get_config', return_value=self.mock_config),
            patch('skwaq.code_analysis.summarization.architecture_reconstruction.get_openai_client', return_value=self.mock_openai_client),
            patch('skwaq.code_analysis.summarization.architecture_reconstruction.PatternMatcher', return_value=self.mock_pattern_matcher)
        ):
            self.reconstructor = ArchitectureReconstructor()
    
    def test_initialization(self):
        """Test that the ArchitectureReconstructor initializes correctly."""
        self.assertIsInstance(self.reconstructor, ArchitectureReconstructor)
        self.assertIn("python", self.reconstructor.dependency_patterns)
        self.assertIn("javascript", self.reconstructor.dependency_patterns)
        self.assertGreater(len(self.reconstructor.component_folder_patterns), 0)
    
    def test_get_file_language(self):
        """Test determining file language from extension."""
        self.assertEqual(self.reconstructor._get_file_language("test.py"), "python")
        self.assertEqual(self.reconstructor._get_file_language("test.js"), "javascript")
        self.assertEqual(self.reconstructor._get_file_language("test.ts"), "typescript")
        self.assertEqual(self.reconstructor._get_file_language("test.java"), "java")
        self.assertEqual(self.reconstructor._get_file_language("test.cs"), "csharp")
        self.assertEqual(self.reconstructor._get_file_language("test.unknown"), "unknown")
    
    @patch('skwaq.code_analysis.summarization.architecture_reconstruction.glob.glob')
    def test_get_files(self, mock_glob):
        """Test retrieving files from a repository."""
        # Mock glob to return some files
        mock_glob.return_value = [
            "/repo/src/module1/file1.py",
            "/repo/src/module1/file2.py",
            "/repo/src/module2/file3.py"
        ]
        
        files = self.reconstructor._get_files("/repo")
        
        self.assertEqual(len(files), 3)
        self.assertIn("/repo/src/module1/file1.py", files)
        self.assertIn("/repo/src/module2/file3.py", files)
    
    def test_extract_component_from_path(self):
        """Test extracting component name from file path."""
        repo_path = "/repo"
        
        # Test common component folders
        self.assertEqual(
            self.reconstructor._extract_component_from_path("/repo/src/auth/login.py", repo_path),
            "auth"
        )
        
        self.assertEqual(
            self.reconstructor._extract_component_from_path("/repo/app/user/profile.js", repo_path),
            "user"
        )
        
        self.assertEqual(
            self.reconstructor._extract_component_from_path("/repo/lib/utils/helpers.ts", repo_path),
            "utils"
        )
        
        # Test fallback to top-level directory
        self.assertEqual(
            self.reconstructor._extract_component_from_path("/repo/custom_folder/file.py", repo_path),
            "custom_folder"
        )
    
    @patch('builtins.open', new_callable=mock_open, read_data="import os\nimport sys\nfrom utils import helpers\n")
    def test_extract_dependencies(self, mock_file):
        """Test extracting dependencies from a file."""
        dependencies = self.reconstructor._extract_dependencies(
            "test.py", "python", content="import os\nimport sys\nfrom utils import helpers\n"
        )
        
        self.assertIn("os", dependencies)
        self.assertIn("sys", dependencies)
        self.assertIn("utils", dependencies)
    
    @patch('skwaq.code_analysis.summarization.architecture_reconstruction.glob.glob')
    @patch('builtins.open', new_callable=mock_open)
    def test_identify_components(self, mock_file, mock_glob):
        """Test identifying components in a repository."""
        # Setup mock files
        mock_glob.return_value = [
            "/repo/src/auth/login.py",
            "/repo/src/auth/register.py",
            "/repo/src/api/endpoints.py",
            "/repo/src/utils/helpers.py"
        ]
        
        # Mock file content to return appropriate language identification
        mock_file.return_value.read.return_value = "# Python file"
        
        # Identify components
        components = self.reconstructor.identify_components("/repo")
        
        # Verify components were identified correctly
        self.assertEqual(len(components), 3)  # auth, api, utils
        
        # Check that each component has the expected properties
        component_names = {c["name"] for c in components}
        self.assertIn("auth", component_names)
        self.assertIn("api", component_names)
        self.assertIn("utils", component_names)
        
        # Verify component details
        for component in components:
            self.assertIn("name", component)
            self.assertIn("type", component)
            self.assertIn("languages", component)
            self.assertIn("path", component)
            self.assertIn("file_count", component)
    
    @patch('skwaq.code_analysis.summarization.architecture_reconstruction.glob.glob')
    @patch('builtins.open', new_callable=mock_open)
    def test_analyze_dependencies(self, mock_file, mock_glob):
        """Test analyzing dependencies between components."""
        # Setup mock files
        mock_glob.return_value = [
            "/repo/src/auth/login.py",
            "/repo/src/api/endpoints.py",
            "/repo/src/utils/helpers.py"
        ]
        
        # Mock components
        components = [
            {"name": "auth", "files": ["/repo/src/auth/login.py"]},
            {"name": "api", "files": ["/repo/src/api/endpoints.py"]},
            {"name": "utils", "files": ["/repo/src/utils/helpers.py"]}
        ]
        
        # Mock extract_dependencies to return dependencies
        with patch.object(
            self.reconstructor, '_extract_dependencies',
            side_effect=lambda file_path, language, content=None: 
                ["utils", "auth"] if "api" in file_path else 
                ["utils"] if "auth" in file_path else []
        ):
            # Analyze dependencies
            dependencies = self.reconstructor.analyze_dependencies("/repo", components)
        
        # Verify results
        self.assertGreaterEqual(len(dependencies), 1)
    
    def test_generate_diagram(self):
        """Test generating a diagram from an architecture model."""
        # Create a sample architecture model
        model = ArchitectureModel(
            name="Test Architecture",
            components=[
                {"name": "auth", "type": "module"},
                {"name": "api", "type": "module"},
                {"name": "utils", "type": "utility"}
            ],
            relationships=[
                {"source": "api", "target": "auth", "type": "uses"},
                {"source": "auth", "target": "utils", "type": "uses"}
            ]
        )
        
        # Generate diagram
        diagram = self.reconstructor.generate_diagram(model)
        
        # Verify diagram structure
        self.assertIsInstance(diagram, str)
        self.assertTrue(diagram.startswith("digraph G {"))
        self.assertIn('"auth" [label="auth\\n(module)"]', diagram)
        self.assertIn('"api" -> "auth" [label="uses"]', diagram)
        self.assertIn('"auth" -> "utils" [label="uses"]', diagram)
    
    @patch('skwaq.code_analysis.summarization.architecture_reconstruction.ArchitectureReconstructor.identify_components')
    @patch('skwaq.code_analysis.summarization.architecture_reconstruction.ArchitectureReconstructor.analyze_dependencies')
    def test_reconstruct_architecture(self, mock_analyze_dependencies, mock_identify_components):
        """Test reconstructing the architecture of a repository."""
        # Mock component identification
        mock_identify_components.return_value = [
            {"name": "auth", "type": "module"},
            {"name": "api", "type": "module"},
            {"name": "utils", "type": "utility"}
        ]
        
        # Mock dependency analysis
        mock_analyze_dependencies.return_value = [
            {"source": "api", "target": "auth", "type": "uses"},
            {"source": "auth", "target": "utils", "type": "uses"}
        ]
        
        # Reconstruct architecture
        architecture = self.reconstructor.reconstruct_architecture("/repo")
        
        # Verify architecture model
        self.assertIsInstance(architecture, ArchitectureModel)
        self.assertEqual(len(architecture.components), 3)
        self.assertEqual(len(architecture.relationships), 2)
        
        # Check the model contains expected components and relationships
        component_names = {c["name"] for c in architecture.components}
        self.assertIn("auth", component_names)
        self.assertIn("api", component_names)
        self.assertIn("utils", component_names)
        
        relationship_pairs = {(r["source"], r["target"]) for r in architecture.relationships}
        self.assertIn(("api", "auth"), relationship_pairs)
        self.assertIn(("auth", "utils"), relationship_pairs)
    
    @patch('skwaq.code_analysis.summarization.architecture_reconstruction.ArchitectureReconstructor.identify_components')
    def test_reconstruct_architecture_error_handling(self, mock_identify_components):
        """Test error handling during architecture reconstruction."""
        # Mock component identification to raise an exception
        mock_identify_components.side_effect = Exception("Test error")
        
        # Attempt to reconstruct architecture
        architecture = self.reconstructor.reconstruct_architecture("/repo")
        
        # Verify error architecture model is returned
        self.assertIsInstance(architecture, ArchitectureModel)
        self.assertIn("Error", architecture.name)
        self.assertEqual(len(architecture.components), 1)
        self.assertEqual(architecture.components[0]["type"], "error")
        self.assertEqual(len(architecture.relationships), 0)


if __name__ == '__main__':
    unittest.main()
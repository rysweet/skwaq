"""Test configuration for pytest.

This module provides fixtures and configuration for testing.
"""

import pytest

# Configure pytest-asyncio to use strict mode
pytest.register_assert_rewrite("tests.unit.ingestion.test_isolated_github")

import sys
import os
import pytest
from unittest.mock import MagicMock, AsyncMock, patch
import importlib
from pathlib import Path

# List of modules to mock
MOCK_MODULES = [
    "autogen",
    "autogen.core",
    "autogen_core",
    "autogen_core.agent",
    "autogen_core.event",
    "autogen_core.code_utils",
    "autogen_core.memory",
    "git",  # Mock the GitPython library for all tests
]


def pytest_sessionstart(session):
    """Set up mocks for external dependencies before test collection begins."""
    # Create mock modules
    for mod_name in MOCK_MODULES:
        sys.modules[mod_name] = MagicMock()

    # Set up autogen_core modules with required classes
    if "autogen_core" in sys.modules:
        sys.modules["autogen_core"].agent = MagicMock()
        sys.modules["autogen_core"].event = MagicMock()
        sys.modules["autogen_core"].code_utils = MagicMock()
        sys.modules["autogen_core"].memory = MagicMock()

        # Add required classes
        sys.modules["autogen_core"].agent.Agent = MagicMock()
        sys.modules["autogen_core"].agent.ChatAgent = MagicMock()
        sys.modules["autogen_core"].event.BaseEvent = MagicMock()
        sys.modules["autogen_core"].event.Event = MagicMock()
        sys.modules["autogen_core"].event.EventHook = MagicMock()
        sys.modules["autogen_core"].event.register_hook = MagicMock()
        sys.modules["autogen_core"].memory.MemoryRecord = MagicMock()

    # Set up autogen.core
    if "autogen.core" in sys.modules:
        sys.modules["autogen.core"].chat_complete_tokens = MagicMock()

    # We'll set up GitHub mocks during test setup instead via fixtures
        
    # Set up Git mocks
    if "git" in sys.modules:
        git_repo_mock = MagicMock()
        git_repo_mock.active_branch.name = "main"
        
        # Mock commit properties
        commit_mock = MagicMock()
        commit_mock.hexsha = "abc123def456"
        commit_mock.author.name = "Test User"
        commit_mock.author.email = "test@example.com"
        commit_mock.committed_date = 1616161616  # Unix timestamp
        commit_mock.message = "Test commit message"
        
        # Link commit to repo
        git_repo_mock.head.commit = commit_mock
        
        sys.modules["git"].Repo = MagicMock(return_value=git_repo_mock)
        sys.modules["git"].Repo.clone_from = MagicMock(return_value=git_repo_mock)


@pytest.fixture(autouse=True)
def reset_registries_and_modules(monkeypatch):
    """Reset all service registries and critical modules before each test and enhance mocking.

    This fixture ensures that tests don't interfere with each other by completely
    resetting key modules and all service registries between tests.
    It also handles Path.exists mocking that can cause test interference.
    
    IMPORTANT: This fixture is crucial for test isolation. Each test should be
    completely independent, with no shared state or dependencies on other tests.
    """
    # Import the modules that have registries
    neo4j_connector_module = importlib.import_module("skwaq.db.neo4j_connector")
    openai_client_module = importlib.import_module("skwaq.core.openai_client")
    
    # Try to import the code_analysis module (which might not exist in all test scenarios)
    try:
        patterns_registry_module = importlib.import_module("skwaq.code_analysis.patterns.registry")
    except ModuleNotFoundError:
        patterns_registry_module = None
    
    # Import all critical modules that need to be reset between tests
    # These modules often contain singleton patterns or global state
    modules_to_reset = [
        "skwaq.ingestion.ingestion",
        "skwaq.ingestion.repository",
        "skwaq.ingestion.filesystem",
        "skwaq.ingestion.documentation",
        "skwaq.ingestion.ast_mapper",
        "skwaq.db.neo4j_connector",
        "skwaq.core.openai_client",
        "skwaq.utils.config",
        "skwaq.utils.logging"
    ]
    
    # Add code_analysis modules if they exist (they might not in all test configurations)
    code_analysis_modules = [
        "skwaq.code_analysis.analyzer",
        "skwaq.code_analysis.summarization.architecture_reconstruction",
        "skwaq.code_analysis.summarization.code_summarizer",
        "skwaq.code_analysis.summarization.cross_referencer",
        "skwaq.code_analysis.summarization.intent_inference"
    ]
    
    # Only include modules that actually exist
    for module_path in code_analysis_modules:
        try:
            importlib.import_module(module_path)
            modules_to_reset.append(module_path)
        except ImportError:
            pass
    
    module_cache = {}
    
    # Import modules safely
    for module_path in modules_to_reset:
        try:
            module = importlib.import_module(module_path)
            module_cache[module_path] = module
        except (ImportError, ModuleNotFoundError):
            module_cache[module_path] = None
            
    # Get references to important modules
    ingestion_module = module_cache.get("skwaq.ingestion.ingestion")
    # Legacy module reference for backward compatibility with existing tests
    code_ingestion_module = None
    
    # Reset critical modules state
    # We'll patch the modules directly rather than trying to replace them,
    # which can cause import errors for submodules in a complex package
    
    # First patch the github module 
    with patch.dict("sys.modules", {"github": MagicMock()}):
        # Create the Repository submodule mock
        repo_module_mock = MagicMock()
        repo_class_mock = MagicMock()
        repo_module_mock.Repository = repo_class_mock
        sys.modules["github.Repository"] = repo_module_mock
        
        # Create the Auth submodule mock
        auth_module_mock = MagicMock()
        auth_class_mock = MagicMock()
        auth_module_mock.Auth = auth_class_mock
        sys.modules["github.Auth"] = auth_module_mock
        
        # Set up the github instance
        github_instance = MagicMock()
        github_instance.get_rate_limit = MagicMock(return_value=MagicMock())
        github_instance.get_repo = MagicMock(return_value=MagicMock())
        
        # Set up repo mock
        repo_mock = github_instance.get_repo.return_value
        repo_mock.name = "test-repo"
        repo_mock.full_name = "test-user/test-repo"
        repo_mock.description = "Test repository for unit tests"
        repo_mock.stargazers_count = 10
        repo_mock.forks_count = 5
        repo_mock.default_branch = "main"
        repo_mock.get_languages.return_value = {"Python": 1000, "JavaScript": 500}
        repo_mock.html_url = "https://github.com/test-user/test-repo"
        repo_mock.clone_url = "https://github.com/test-user/test-repo.git"
        repo_mock.ssh_url = "git@github.com:test-user/test-repo.git"
        
        # Mock content iteration
        content_mock = MagicMock()
        content_mock.path = "test_file.py"
        content_mock.type = "file"
        content_mock.decoded_content = b"# Test content"
        repo_mock.get_contents.return_value = [content_mock]
        
        # Set up GitHub class in the module
        sys.modules["github"].Github = MagicMock(return_value=github_instance)
        sys.modules["github"].Auth = MagicMock()
        sys.modules["github"].Auth.Token = MagicMock()
        sys.modules["github"].GithubException = type("GithubException", (Exception,), {})
        
    # Next patch the git module    
    with patch.dict("sys.modules", {"git": MagicMock()}):
        git_repo_mock = MagicMock()
        git_repo_mock.active_branch.name = "main"
        
        # Mock commit properties
        commit_mock = MagicMock()
        commit_mock.hexsha = "abc123def456"
        commit_mock.author.name = "Test User"
        commit_mock.author.email = "test@example.com"
        commit_mock.committed_date = 1616161616
        commit_mock.message = "Test commit message"
        git_repo_mock.head.commit = commit_mock
        
        # Setup git repo's git obj for commands
        git_cmd_mock = MagicMock()
        git_cmd_mock.ls_files.return_value = "file1.py\nfile2.py\nREADME.md"
        git_repo_mock.git = git_cmd_mock
        
        # Mock the repo's remote info
        origin_mock = MagicMock()
        origin_mock.url = "https://github.com/test-user/test-repo.git"
        git_repo_mock.remotes.origin = origin_mock
        
        # Set up Git classes and exceptions in the module
        sys.modules["git"].Repo = MagicMock(return_value=git_repo_mock)
        sys.modules["git"].Repo.clone_from = MagicMock(return_value=git_repo_mock)
        sys.modules["git"].GitCommandError = type("GitCommandError", (Exception,), {})
        sys.modules["git"].InvalidGitRepositoryError = type("InvalidGitRepositoryError", (Exception,), {})
        sys.modules["git"].NoSuchPathError = type("NoSuchPathError", (Exception,), {})
    
    # Create a safe replacement for the GitHub client initialization
    def safe_init_github_client(self):
        """Mock implementation that doesn't try to validate GitHub credentials."""
        if not hasattr(self, "github_client") or self.github_client is None:
            # Create a mock client that won't try to validate credentials
            self.github_client = MagicMock()
            self.github_client.get_rate_limit = MagicMock(return_value=MagicMock())
            self.github_client.get_repo = MagicMock(return_value=MagicMock())
            
            # Setup repo attributes
            repo_mock = self.github_client.get_repo.return_value
            repo_mock.name = "test-repo"
            repo_mock.full_name = "test-user/test-repo"
            repo_mock.description = "Test repository for unit tests"
            repo_mock.stargazers_count = 10
            repo_mock.forks_count = 5
            repo_mock.default_branch = "main"
            repo_mock.get_languages.return_value = {"Python": 1000, "JavaScript": 500}
            repo_mock.html_url = "https://github.com/test-user/test-repo"
            repo_mock.clone_url = "https://github.com/test-user/test-repo.git"
            repo_mock.ssh_url = "git@github.com:test-user/test-repo.git"
            
            # Mock content iteration
            content_mock = MagicMock()
            content_mock.path = "test_file.py"
            content_mock.type = "file"
            content_mock.decoded_content = b"# Test content"
            repo_mock.get_contents.return_value = [content_mock]
            
        return self.github_client
    
    # Patch the GitHub client initialization method in RepositoryIngestor
    if code_ingestion_module is not None and hasattr(code_ingestion_module, "RepositoryIngestor"):
        monkeypatch.setattr(code_ingestion_module.RepositoryIngestor, "_init_github_client", safe_init_github_client)
    
    # Reset singleton instances
    try:
        # Reset CodeAnalyzer singleton
        analyzer_module = importlib.import_module("skwaq.code_analysis.analyzer")
        if hasattr(analyzer_module, "CodeAnalyzer") and hasattr(analyzer_module.CodeAnalyzer, "_instance"):
            analyzer_module.CodeAnalyzer._instance = None
            
        # Reset RepositoryIngestor singleton if it exists
        if hasattr(code_ingestion_module, "RepositoryIngestor") and hasattr(code_ingestion_module.RepositoryIngestor, "_instance"):
            code_ingestion_module.RepositoryIngestor._instance = None
    except (ImportError, AttributeError):
        pass
    
    # Reset all known registries before the test
    neo4j_connector_module.reset_connector_registry()
    openai_client_module.reset_client_registry()
    
    # Reset any global state in other modules
    if patterns_registry_module is not None and hasattr(patterns_registry_module, "reset_registry"):
        patterns_registry_module.reset_registry()
    
    # Create mock objects for global usage
    mock_neo4j_connector = MagicMock()
    mock_neo4j_connector.create_node.return_value = 1
    mock_neo4j_connector.create_relationship.return_value = True
    mock_neo4j_connector.run_query.return_value = []

    mock_openai_client = MagicMock()
    mock_openai_client.get_completion = MagicMock(return_value="Mock repository summary")
    # For async tests
    mock_async_openai_client = MagicMock()
    mock_async_openai_client.get_completion = AsyncMock(return_value="Mock repository summary")

    # Override the get_* functions to return consistent mocks for 'default' keys
    original_get_connector = neo4j_connector_module.get_connector
    original_get_openai_client = openai_client_module.get_openai_client

    def mock_get_connector(uri=None, user=None, password=None, registry_key="default"):
        if registry_key == "default":
            return mock_neo4j_connector
        return original_get_connector(uri, user, password, registry_key)

    def mock_get_openai_client(config=None, async_mode=False, registry_key=None):
        if registry_key is None:
            registry_key = "async" if async_mode else "sync"
        if registry_key == "sync":
            return mock_openai_client
        elif registry_key == "async":
            return mock_async_openai_client
        return original_get_openai_client(config, async_mode, registry_key)

    # Apply the patches for the registry functions
    monkeypatch.setattr("skwaq.db.neo4j_connector.get_connector", mock_get_connector)
    monkeypatch.setattr("skwaq.core.openai_client.get_openai_client", mock_get_openai_client)
    
    # Save original Path.exists to restore it after tests
    from pathlib import Path
    original_path_exists = Path.exists
    
    def safe_path_exists(self):
        """A safe default implementation that allows basic path checks.
        
        This allows Path.exists('/real/path') to work normally
        but returns True for common test paths like '/path/to/repo'.
        """
        # Common test paths that should return True
        test_paths = {
            "/path/to/repo", 
            "/tmp/mock_repo",
            "/tmp/mock_temp_dir",
            "/test/path",
            "/test/repo"
        }
        
        if str(self) in test_paths:
            return True
            
        # Fall back to the actual implementation for real paths
        return original_path_exists(self)
    
    # Apply Path.exists patch
    monkeypatch.setattr(Path, "exists", safe_path_exists)

    # Run the test
    yield

    # Import logging to avoid "logger not defined" errors in teardown
    import logging
    logger = logging.getLogger(__name__)
    
    try:
        # Reset registries after the test
        neo4j_connector_module.reset_connector_registry()
        openai_client_module.reset_client_registry()
        
        # Reset other global state as needed
        if patterns_registry_module is not None and hasattr(patterns_registry_module, "reset_registry"):
            patterns_registry_module.reset_registry()
            
        # Reset all singleton instances and global state in our modules
        for module_name, module in module_cache.items():
            if module is None:
                continue
                
            # Reset any class with an _instance attribute (common singleton pattern)
            for name in dir(module):
                try:
                    cls = getattr(module, name)
                    if isinstance(cls, type) and hasattr(cls, "_instance"):
                        setattr(cls, "_instance", None)
                        logger.debug(f"Reset singleton instance for {module_name}.{name}")
                except (AttributeError, TypeError):
                    continue
                    
            # Reset specific known global variables or attributes
            if module_name == "skwaq.db.neo4j_connector":
                if hasattr(module, "_connector"):
                    module._connector = None
                    
            elif module_name == "skwaq.core.openai_client":
                if hasattr(module, "_openai_client"):
                    module._openai_client = None
                    if hasattr(module, "_async_openai_client"):
                        module._async_openai_client = None
    except Exception as e:
        # Log any errors but don't let them crash the test teardown
        logger.error(f"Error during test teardown: {e}")
        pass


@pytest.fixture
def mock_connector():
    """Mock Neo4j connector."""
    connector = MagicMock()
    connector.create_node.return_value = 1  # Return a fake node ID
    connector.create_relationship.return_value = True
    connector.run_query.return_value = []

    with patch("skwaq.db.neo4j_connector.get_connector", return_value=connector):
        yield connector


@pytest.fixture
def mock_openai_client():
    """Mock OpenAI client."""
    client = MagicMock()
    client.get_completion = MagicMock(return_value="Mock repository summary")

    with patch("skwaq.core.openai_client.get_openai_client", return_value=client):
        yield client


@pytest.fixture
def mock_config():
    """Mock configuration."""
    config = MagicMock()

    with patch("skwaq.utils.config.get_config", return_value=config):
        yield config


@pytest.fixture(autouse=True)
def mock_github_everywhere(monkeypatch):
    """Mock GitHub API interactions globally across all tests.
    
    This fixture applies to all tests automatically and provides consistent
    GitHub API mocking to prevent any real GitHub API calls during testing.
    """
    # Create mock GitHub client
    github_instance = MagicMock()
    github_instance.get_rate_limit = MagicMock(return_value=MagicMock())
    github_instance.get_repo = MagicMock(return_value=MagicMock())
    
    # Set up repo attributes
    repo_mock = github_instance.get_repo.return_value
    repo_mock.name = "test-repo"
    repo_mock.full_name = "test-user/test-repo"
    repo_mock.description = "Test repository for unit tests"
    repo_mock.stargazers_count = 10
    repo_mock.forks_count = 5
    repo_mock.default_branch = "main"
    repo_mock.get_languages.return_value = {"Python": 1000, "JavaScript": 500}
    repo_mock.html_url = "https://github.com/test-user/test-repo"
    repo_mock.clone_url = "https://github.com/test-user/test-repo.git"
    repo_mock.ssh_url = "git@github.com:test-user/test-repo.git"
    
    # Mock content iteration
    content_mock = MagicMock()
    content_mock.path = "test_file.py"
    content_mock.type = "file"
    content_mock.decoded_content = b"# Test content"
    repo_mock.get_contents.return_value = [content_mock]
    
    # Mock the PyGithub Auth class
    auth_mock = MagicMock()
    auth_token_mock = MagicMock()
    auth_mock.Token = MagicMock(return_value=auth_token_mock)
    
    # Create system-wide mock for GitHub modules
    with patch.dict("sys.modules", {"github": MagicMock()}):
        sys.modules["github"].Github = MagicMock(return_value=github_instance)
        sys.modules["github"].Auth = auth_mock
        sys.modules["github"].Auth.Token = auth_mock.Token
        
        # Also mock github.GithubException for error handling tests
        exception_mock = type("GithubException", (Exception,), {})
        sys.modules["github"].GithubException = exception_mock
        
        yield github_instance


@pytest.fixture
def mock_github():
    """Mock GitHub client for specific tests that need direct access to the mock."""
    github_instance = MagicMock()
    github_instance.get_rate_limit = MagicMock(return_value=MagicMock())
    github_instance.get_repo = MagicMock(return_value=MagicMock())
    
    # Set up repo attributes
    repo_mock = github_instance.get_repo.return_value
    repo_mock.name = "test-repo"
    repo_mock.full_name = "test-user/test-repo"
    repo_mock.description = "Test repository for unit tests"
    repo_mock.stargazers_count = 10
    repo_mock.forks_count = 5
    repo_mock.default_branch = "main"
    repo_mock.get_languages.return_value = {"Python": 1000, "JavaScript": 500}
    repo_mock.html_url = "https://github.com/test-user/test-repo"
    
    yield github_instance


@pytest.fixture(autouse=True)
def mock_git_everywhere(monkeypatch):
    """Mock Git interactions globally across all tests.
    
    This fixture applies to all tests automatically and provides consistent
    Git mocking to prevent any real Git operations during testing.
    """
    # Create a mock git module
    git_module_mock = MagicMock()
    
    # Set up the Repo class
    git_repo_mock = MagicMock()
    git_repo_mock.active_branch.name = "main"
    
    # Mock commit properties
    commit_mock = MagicMock()
    commit_mock.hexsha = "abc123def456"
    commit_mock.author.name = "Test User"
    commit_mock.author.email = "test@example.com"
    commit_mock.committed_date = 1616161616  # Unix timestamp
    commit_mock.message = "Test commit message"
    
    # Link commit to repo
    git_repo_mock.head.commit = commit_mock
    
    # Setup git repo's git obj for commands
    git_cmd_mock = MagicMock()
    git_cmd_mock.ls_files.return_value = "file1.py\nfile2.py\nREADME.md"
    git_repo_mock.git = git_cmd_mock
    
    # Mock the repo's remote info
    origin_mock = MagicMock()
    origin_mock.url = "https://github.com/test-user/test-repo.git"
    git_repo_mock.remotes.origin = origin_mock
    
    # Setup the Repo constructor and class methods
    git_module_mock.Repo = MagicMock(return_value=git_repo_mock)
    git_module_mock.Repo.clone_from = MagicMock(return_value=git_repo_mock)
    
    # Git exceptions
    git_module_mock.GitCommandError = type("GitCommandError", (Exception,), {})
    git_module_mock.InvalidGitRepositoryError = type("InvalidGitRepositoryError", (Exception,), {})
    git_module_mock.NoSuchPathError = type("NoSuchPathError", (Exception,), {})
    
    # Apply the mock to sys.modules
    monkeypatch.setitem(sys.modules, "git", git_module_mock)
    
    yield git_repo_mock

@pytest.fixture
def mock_git_repo():
    """Mock Git repository for tests that need direct access to the mock."""
    # Use the global mock from mock_git_everywhere
    yield sys.modules["git"].Repo()

    
@pytest.fixture
def isolated_test_environment(monkeypatch):
    """Set up an isolated test environment for specific tests that need stronger isolation.
    
    This fixture prevents interference from other tests and globally applied mocks.
    Use this fixture for tests marked with pytest.mark.isolated.
    """
    # Create isolated mocks for GitHub
    github_instance = MagicMock()
    github_instance.get_rate_limit = MagicMock(return_value=MagicMock())
    github_instance.get_repo = MagicMock(return_value=MagicMock())
    
    # Setup mock repo
    repo_mock = github_instance.get_repo.return_value
    repo_mock.name = "isolated-test-repo"
    repo_mock.full_name = "test-user/isolated-test-repo"
    
    # Create mock Auth classes
    auth_mock = MagicMock()
    auth_token_mock = MagicMock()
    auth_mock.Token = MagicMock(return_value=auth_token_mock)
    
    # Create a clean GitHub module mock
    github_module_mock = MagicMock()
    github_module_mock.Github = MagicMock(return_value=github_instance)
    github_module_mock.Auth = auth_mock
    github_module_mock.GithubException = type("IsolatedGithubException", (Exception,), {})
    github_repository_mock = MagicMock()
    github_repository_mock.Repository = MagicMock()
    
    # Apply the mocks
    monkeypatch.setitem(sys.modules, "github", github_module_mock)
    monkeypatch.setitem(sys.modules, "github.Repository", github_repository_mock)
    monkeypatch.setitem(sys.modules, "github.Auth", auth_mock)
    
    # Create clean connector and client mocks
    mock_connector = MagicMock()
    mock_connector.create_node.return_value = 1
    mock_connector.run_query.return_value = []
    
    mock_openai_client = MagicMock()
    mock_openai_client.create_completion = AsyncMock(return_value={"choices": [{"text": "Isolated test summary"}]})
    
    # Yield our isolated environment setup
    yield {
        "github": github_instance,
        "connector": mock_connector,
        "openai_client": mock_openai_client
    }

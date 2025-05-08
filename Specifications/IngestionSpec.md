# Comprehensive Software Specification for the Ingestion Module

## Overview

The Ingestion Module is a core component of the Vulnerability Assessment Copilot system, responsible for importing, parsing, and analyzing code repositories to create a comprehensive graph representation that can be used for security analysis. The module processes code from various sources, extracts the syntax structure using parsers like Blarify, maps the syntax tree to files, and enriches the representation with AI-generated summaries of code functionality and intent.

This specification details the architecture, components, interfaces, data structures, and implementation guidelines for building a robust ingestion pipeline that handles different repository sources and produces a high-quality knowledge graph for security analysis workflows.

## Core Components

The Ingestion Module is composed of the following core components:

1. **Repository Handler**: Manages repository access, including local filesystem access and Git repository cloning
2. **AST Parsers**: Extracts abstract syntax trees from code using tools like Blarify
3. **AST Mapper**: Maps AST nodes to file nodes in the graph database
4. **Code Summarizers**: Generates natural language descriptions of code using LLMs
5. **Graph Construction**: Creates nodes and relationships in the Neo4j database
6. **Documentation Processing**: Analyzes and connects documentation to code entities
7. **Status Tracking**: Monitors and reports on the ingestion process

## Detailed API Specification

### 1. Ingestion Class

The main entry point for ingesting codebases.

```python
class Ingestion:
    def __init__(
        self,
        local_path: Optional[str] = None,
        repo: Optional[str] = None,
        branch: Optional[str] = None,
        model_client: Optional[Any] = None,
        max_parallel: int = 3,
        doc_path: Optional[str] = None,
        doc_uri: Optional[str] = None,
        context_token_limit: int = 20000,
        parse_only: bool = False,
    ):
        """Initialize the ingestion process.

        Args:
            local_path: Path to a local codebase directory
            repo: Git repository URL
            branch: Git branch to clone
            model_client: OpenAI model client for code summarization
            max_parallel: Maximum number of parallel threads for processing
            doc_path: Path to additional documentation
            doc_uri: URI to additional documentation
            context_token_limit: Maximum number of tokens to keep in context
            parse_only: Flag to only parse the codebase without LLM summarization

        Raises:
            ValueError: If neither local_path nor repo is provided, or if both are provided
        """
        pass

    async def ingest(self) -> str:
        """Start the ingestion process.

        Returns:
            Ingestion ID that can be used to track the process
        """
        pass

    async def get_status(self, ingestion_id: str) -> IngestionStatus:
        """Get the current status of an ingestion process.

        Args:
            ingestion_id: ID of the ingestion process

        Returns:
            Current status of the ingestion process

        Raises:
            ValueError: If the ingestion ID is not found
        """
        pass
```

### 2. IngestionStatus Class

Tracks the state and progress of an ingestion process.

```python
@dataclass
class IngestionStatus:
    """Status of an ingestion process.

    Attributes:
        id: Unique identifier for the ingestion
        state: Current state of the ingestion process (e.g., "initializing", "processing", "completed", "failed")
        progress: Progress percentage (0-100)
        start_time: Timestamp when ingestion started
        end_time: Timestamp when ingestion completed or failed
        error: Error message if ingestion failed
        files_processed: Number of files processed so far
        total_files: Total number of files to process
        errors: List of errors encountered during ingestion
        message: Current status message
        parsing_stats: Statistics about parsing process
        summarization_stats: Statistics about summarization process
    """
    id: str
    state: str = "initializing"
    progress: float = 0.0
    start_time: float = field(default_factory=time.time)
    end_time: Optional[float] = None
    error: Optional[str] = None
    files_processed: int = 0
    total_files: int = 0
    errors: List[Dict[str, Any]] = field(default_factory=list)
    message: str = "Initializing ingestion process"
    parsing_stats: Dict[str, Any] = field(default_factory=dict)
    summarization_stats: Dict[str, Any] = field(default_factory=dict)

    @property
    def time_elapsed(self) -> float:
        """Calculate time elapsed since ingestion started.

        Returns:
            Time elapsed in seconds
        """
        pass

    def to_dict(self) -> Dict[str, Any]:
        """Convert status to dictionary.

        Returns:
            Dictionary representation of the status
        """
        pass
```

### 3. Repository Handler

Manages access to repositories from different sources.

```python
class RepositoryHandler:
    """Handles repository operations such as cloning and accessing metadata."""
    
    def clone_repository(self, repo_url: str, branch: Optional[str] = None) -> str:
        """Clone a Git repository to a temporary location.
        
        Args:
            repo_url: URL of the Git repository to clone
            branch: Optional branch to checkout
            
        Returns:
            Path to the cloned repository
            
        Raises:
            ValueError: If the repository URL is invalid or cannot be cloned
        """
        pass
        
    def get_repository_metadata(self, repo_path: str) -> Dict[str, Any]:
        """Get metadata about a repository.
        
        Args:
            repo_path: Path to the repository
            
        Returns:
            Dictionary with repository metadata
        """
        pass
        
    def cleanup(self) -> None:
        """Clean up temporary resources."""
        pass
```

### 4. Repository Manager

Manages repository nodes in the database.

```python
class RepositoryManager:
    """Manages repository nodes in the graph database."""
    
    def __init__(self, connector: Neo4jConnector):
        """Initialize with a Neo4j connector.
        
        Args:
            connector: Neo4j connector instance
        """
        pass
        
    def create_repository_node(
        self, 
        ingestion_id: str, 
        local_path: str, 
        repo_url: Optional[str],
        metadata: Dict[str, Any]
    ) -> int:
        """Create a repository node in the database.
        
        Args:
            ingestion_id: ID of the ingestion process
            local_path: Local path to the repository
            repo_url: URL of the Git repository (if applicable)
            metadata: Repository metadata
            
        Returns:
            ID of the created repository node
        """
        pass
        
    def update_status(self, repo_node_id: int, status: Dict[str, Any]) -> None:
        """Update the status of a repository node.
        
        Args:
            repo_node_id: ID of the repository node
            status: Status information
        """
        pass
```

### 5. CodebaseFileSystem

Provides a unified interface for accessing files in a codebase.

```python
class CodebaseFileSystem:
    """Interface for accessing files in a codebase."""
    
    def __init__(self, root_path: str):
        """Initialize with the root path of the codebase.
        
        Args:
            root_path: Root path of the codebase
        """
        pass
        
    def get_all_files(self) -> List[str]:
        """Get all files in the codebase.
        
        Returns:
            List of file paths
        """
        pass
        
    def read_file(self, file_path: str) -> str:
        """Read the content of a file.
        
        Args:
            file_path: Path to the file
            
        Returns:
            Content of the file
        """
        pass
```

### 6. FilesystemGraphBuilder

Creates a graph representation of the filesystem structure.

```python
class FilesystemGraphBuilder:
    """Builds a graph representation of the filesystem structure."""
    
    def __init__(self, connector: Neo4jConnector):
        """Initialize with a Neo4j connector.
        
        Args:
            connector: Neo4j connector instance
        """
        pass
        
    async def build_graph(
        self, 
        repo_node_id: int, 
        fs: CodebaseFileSystem
    ) -> Dict[str, int]:
        """Build a graph representation of the filesystem.
        
        Args:
            repo_node_id: ID of the repository node
            fs: CodebaseFileSystem instance
            
        Returns:
            Mapping of file paths to node IDs
        """
        pass
```

### 7. CodeParser Base Class

Abstract base class for code parsers.

```python
class CodeParser(ABC):
    """Abstract base class for code parsers.

    Code parsers analyze a codebase and produce a structured representation
    that can be stored in the graph database.
    """

    @abstractmethod
    async def parse(self, codebase_path: str) -> Dict[str, Any]:
        """Parse a codebase and create a graph representation.

        Args:
            codebase_path: Path to the codebase to parse

        Returns:
            Dictionary with parsing results and statistics
        """
        pass

    @abstractmethod
    async def connect_ast_to_files(
        self, repo_node_id: int, file_path_mapping: Dict[str, int]
    ) -> None:
        """Connect AST nodes to their corresponding file nodes.

        Args:
            repo_node_id: ID of the repository node
            file_path_mapping: Mapping of file paths to file node IDs
        """
        pass
```

### 8. BlarifyParser Implementation

Blarify-specific implementation of the CodeParser interface.

```python
class BlarifyParser(CodeParser):
    """Blarify parser implementation for code analysis.

    This parser uses the Blarify library to extract the syntax structure of a codebase
    and store it in the Neo4j graph database.
    """

    def __init__(self):
        """Initialize the Blarify parser.

        Raises:
            ImportError: If Blarify is not installed
        """
        pass

    async def parse(self, codebase_path: str) -> Dict[str, Any]:
        """Parse a codebase using Blarify and create a graph representation.

        Args:
            codebase_path: Path to the codebase to parse

        Returns:
            Dictionary with parsing results and statistics

        Raises:
            ValueError: If codebase path is invalid or if parsing fails
        """
        pass

    async def _parse_with_docker(
        self, codebase_path: str, stats: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Parse a codebase using Blarify in a Docker container.

        Args:
            codebase_path: Path to the codebase to parse
            stats: Statistics dictionary to update

        Returns:
            Dictionary with parsing results and statistics
        """
        pass

    async def connect_ast_to_files(
        self, repo_node_id: int, file_path_mapping: Dict[str, int]
    ) -> None:
        """Connect AST nodes to their corresponding file nodes.

        Note:
            This method is deprecated. Use the ASTFileMapper instead.

        Args:
            repo_node_id: ID of the repository node
            file_path_mapping: Mapping of file paths to file node IDs
        """
        pass
```

### 9. ASTFileMapper

Maps AST nodes to filesystem file nodes.

```python
class ASTFileMapper:
    """Maps AST nodes to filesystem file nodes.

    This class provides methods to establish relationships between syntax tree nodes
    and the corresponding filesystem file nodes.
    """

    def __init__(self, connector: Neo4jConnector):
        """Initialize the AST-to-file mapper.

        Args:
            connector: Neo4j connector instance
        """
        pass

    async def map_ast_to_files(
        self, repo_node_id: int, file_nodes: Dict[str, int]
    ) -> Dict[str, Any]:
        """Connect AST nodes to their corresponding file nodes.

        Args:
            repo_node_id: ID of the repository node
            file_nodes: Mapping of file paths to file node IDs

        Returns:
            Dictionary with mapping statistics
        """
        pass
```

### 10. CodeSummarizer Base Class

Abstract base class for code summarizers.

```python
class CodeSummarizer(ABC):
    """Abstract base class for code summarizers.

    Code summarizers generate natural language descriptions of code files.
    """

    @abstractmethod
    def configure(self, **kwargs) -> None:
        """Configure the summarizer with additional parameters.

        Args:
            **kwargs: Configuration parameters
        """
        pass

    @abstractmethod
    async def summarize_files(
        self, file_nodes: List[Dict[str, Any]], fs: Any, repo_node_id: int
    ) -> Dict[str, Any]:
        """Generate summaries for a list of files.

        Args:
            file_nodes: List of file nodes with IDs and paths
            fs: Filesystem interface for reading file contents
            repo_node_id: ID of the repository node

        Returns:
            Dictionary with summarization results and statistics
        """
        pass
```

### 11. LLMSummarizer Implementation

LLM-based implementation of the CodeSummarizer interface.

```python
class LLMSummarizer(CodeSummarizer):
    """LLM-based code summarizer implementation.

    This summarizer uses Large Language Models (e.g., GPT-4) to generate
    natural language descriptions of code files.
    """

    def __init__(self):
        """Initialize the LLM summarizer."""
        pass

    def configure(self, **kwargs) -> None:
        """Configure the summarizer with additional parameters.

        Args:
            model_client: OpenAI model client for generating summaries
            max_parallel: Maximum number of parallel summarization tasks
            context_token_limit: Maximum number of tokens to keep in context
        """
        pass

    async def summarize_files(
        self, file_nodes: List[Dict[str, Any]], fs: Any, repo_node_id: int
    ) -> Dict[str, Any]:
        """Generate summaries for a list of files.

        Args:
            file_nodes: List of file nodes with IDs and paths
            fs: Filesystem interface for reading file contents
            repo_node_id: ID of the repository node

        Returns:
            Dictionary with summarization results and statistics

        Raises:
            ValueError: If model client is not configured
        """
        pass

    async def _summarize_file(
        self,
        file_id: int,
        file_path: str,
        language: str,
        fs: Any,
        stats: Dict[str, Any],
        errors: List[Dict[str, Any]],
    ) -> None:
        """Summarize a single file using LLM.

        Args:
            file_id: ID of the file node
            file_path: Path of the file to summarize
            language: Programming language of the file
            fs: Filesystem interface for reading file contents
            stats: Dictionary to collect statistics
            errors: List to collect errors
        """
        pass

    def _create_summary_prompt(
        self, file_name: str, content: str, language: str
    ) -> str:
        """Create a prompt for summarizing a code file.

        Args:
            file_name: Name of the file
            content: Content of the file
            language: Programming language of the file

        Returns:
            Prompt string for the LLM
        """
        pass

    def _add_to_context(self, file_name: str, content: str) -> None:
        """Add file information to the context buffer, managing token limit.

        Args:
            file_name: Name of the file
            content: Content of the file
        """
        pass
```

### 12. DocumentationProcessor

Processes documentation and links it to code entities.

```python
class DocumentationProcessor:
    """Processes documentation and links it to code entities."""

    def __init__(self, model_client: Any, connector: Neo4jConnector):
        """Initialize the documentation processor.

        Args:
            model_client: OpenAI model client for processing documentation
            connector: Neo4j connector instance
        """
        pass

    async def process_local_docs(self, doc_path: str, repo_node_id: int) -> Dict[str, Any]:
        """Process documentation from a local path.

        Args:
            doc_path: Path to the documentation
            repo_node_id: ID of the repository node

        Returns:
            Dictionary with processing statistics
        """
        pass

    async def process_remote_docs(self, doc_uri: str, repo_node_id: int) -> Dict[str, Any]:
        """Process documentation from a remote URI.

        Args:
            doc_uri: URI of the documentation
            repo_node_id: ID of the repository node

        Returns:
            Dictionary with processing statistics
        """
        pass
```

## Parser Registry System

The Ingestion Module uses a registry system to manage different parser implementations.

```python
# Registry of available parsers
_parser_registry: Dict[str, Type[CodeParser]] = {}

def register_parser(name: str, parser_class: Type[CodeParser]) -> None:
    """Register a parser in the parser registry.

    Args:
        name: Name of the parser
        parser_class: Parser class to register
    """
    pass

def get_parser(name: str) -> Optional[CodeParser]:
    """Get a parser instance by name.

    Args:
        name: Name of the parser

    Returns:
        Parser instance or None if not found
    """
    pass

def register_parsers() -> None:
    """Register all available parsers.

    This function loads and registers all parser implementations.
    """
    pass
```

## Summarizer Registry System

Similar to parsers, code summarizers are managed through a registry system.

```python
# Registry of available summarizers
_summarizer_registry: Dict[str, Type[CodeSummarizer]] = {}

def register_summarizer(name: str, summarizer_class: Type[CodeSummarizer]) -> None:
    """Register a summarizer in the summarizer registry.

    Args:
        name: Name of the summarizer
        summarizer_class: Summarizer class to register
    """
    pass

def get_summarizer(name: str) -> Optional[CodeSummarizer]:
    """Get a summarizer instance by name.

    Args:
        name: Name of the summarizer

    Returns:
        Summarizer instance or None if not found
    """
    pass

def register_summarizers() -> None:
    """Register all available summarizers.

    This function loads and registers all summarizer implementations.
    """
    pass
```

## Ingestion Workflow

The standard ingestion workflow consists of the following steps:

1. **Input validation**: Verify that either a local path or a Git repository URL is provided
2. **Repository preparation**: Clone the repository if needed or access the local filesystem
3. **Filesystem graph construction**: Create nodes for files and directories
4. **AST parsing**: Parse the code to extract the syntax structure
5. **AST-to-file mapping**: Connect AST nodes to their corresponding file nodes
6. **Documentation processing**: Process any provided documentation
7. **Code summarization**: Generate summaries of code files using LLM
8. **Status reporting**: Update status throughout the process

## Implementation Details

### Docker Integration for Blarify Parser

The Blarify parser includes a Docker-based implementation for macOS compatibility. This approach uses a Docker container to run the Blarify parser when direct installation is not possible or encounters issues. The implementation creates a temporary Dockerfile and Python script that runs inside the container.

### AST-to-File Mapping

The AST-to-file mapping is critical for maintaining the connection between syntax tree nodes and their source files. The AST mapper uses the following approach:

1. Query for AST nodes with various path properties (`file_path`, `path`, `full_path`)
2. For each AST node, try to find a matching file node using these properties
3. For matching, consider different normalization approaches:
   - Direct path matching
   - Path suffix matching
   - Path normalization (replacing backslashes with forward slashes)
   - Basename matching
   - Basename without extension matching
4. Create bidirectional relationships between matching nodes:
   - AST node is `PART_OF` the file
   - File `DEFINES` the AST node

### Code Summarization

The code summarization process:

1. For each file, read its content through the filesystem interface
2. Create a prompt that includes the file name, language, and content
3. Generate a summary using the LLM
4. Store the summary in the graph database:
   - Create a `CodeSummary` node
   - Connect it to the file with a `DESCRIBES` relationship
   - Update the file node with the summary text
5. Maintain a context buffer to provide context for subsequent summaries

### Error Handling and Resilience

The ingestion process should be resilient to failures:

1. Track errors for each processed file
2. Allow for retries on error
3. Continue processing even if some files fail
4. Provide detailed error information in the status

## Schema Design

The graph database schema for the ingestion module includes:

### Node Types
- `Repository`: Represents a code repository
- `File`: Represents a file in the repository
- `Directory`: Represents a directory in the repository
- `Function`: Represents a function in the code
- `Class`: Represents a class in the code
- `Method`: Represents a method in a class
- `Parameter`: Represents a parameter to a function or method
- `Variable`: Represents a variable in the code
- `CodeSummary`: Represents an AI-generated summary of code

### Relationship Types
- `CONTAINS`: Directory contains file or directory
- `PART_OF`: Entity is part of another entity (e.g., AST node is part of a file)
- `DEFINES`: Entity defines another entity (e.g., file defines a function)
- `IMPORTS`: File imports another file
- `CALLS`: Function calls another function
- `REFERENCES`: Entity references another entity
- `INHERITS_FROM`: Class inherits from another class
- `DESCRIBES`: Summary describes an entity

## Example Usage

```python
from skwaq.ingestion import Ingestion
from skwaq.core.openai_client import get_openai_client

async def main():
    # Get the OpenAI client
    model_client = get_openai_client()
    
    # Example 1: Ingesting a local repository
    local_path = "/path/to/local/codebase"
    ingestion = Ingestion(local_path=local_path, model_client=model_client)
    ingestion_id = await ingestion.ingest()
    
    # Monitor status
    status = await ingestion.get_status(ingestion_id)
    print(f"Progress: {status.progress}%")
    print(f"Status: {status.state}")
    print(f"Message: {status.message}")
    
    # Example 2: Ingesting a remote Git repository
    repo_url = "https://github.com/dotnet/eShop"
    branch = "main"
    ingestion = Ingestion(repo=repo_url, branch=branch, model_client=model_client)
    ingestion_id = await ingestion.ingest()
    
    # Monitor status
    status = await ingestion.get_status(ingestion_id)
    print(f"Progress: {status.progress}%")
    print(f"Status: {status.state}")
    print(f"Message: {status.message}")
```

## Configuration Options

The ingestion module supports the following configuration options:

- **parse_only**: If set to True, skip the LLM summarization step
- **max_parallel**: Maximum number of parallel threads for summarization (default: 3)
- **context_token_limit**: Maximum number of tokens to keep in context buffer (default: 20000)
- **doc_path/doc_uri**: Path or URI to additional documentation

## Testing Guidelines

### Unit Tests

Unit tests should cover each component of the ingestion pipeline:

- Repository handling
- Filesystem graph construction
- AST parsing
- AST-to-file mapping
- Code summarization
- Documentation processing
- Status tracking

### Integration Tests

Integration tests should verify the end-to-end ingestion process using the [eShop](https://github.com/dotnet/eShop) repository as a test codebase.

### Test Data

Tests should include sample repositories of different sizes and complexities to verify the robustness of the ingestion process.

## Implementation Recommendations

### AST-to-File Mapping

The AST-to-file mapping is a critical component that has caused issues in the past. Make sure to implement the following:

1. **Handle multiple property names**: AST nodes might have their file paths stored in different properties (`file_path`, `path`, `full_path`). Use `COALESCE` in your queries to handle this.

2. **Use multiple matching strategies**: Implement several strategies for matching paths, including:
   - Exact matching
   - Path suffix matching
   - Normalized path matching (consistent slash direction)
   - Basename matching
   - Basename without extension matching

3. **Create bidirectional relationships**: Ensure that both `PART_OF` and `DEFINES` relationships are created for each matched pair.

4. **Handle case sensitivity**: Depending on the filesystem, paths might be case-sensitive or case-insensitive. Consider normalizing case when matching.

### Docker Integration for macOS Compatibility

Blarify might not work directly on macOS, so the Docker-based approach is essential:

1. **Detect platform automatically**: Use `platform.system()` to detect macOS and default to Docker in that case.

2. **Check Docker availability**: Verify that Docker is installed and available before attempting to use it.

3. **Fallback mechanism**: If Docker fails, provide a clear error message and fallback to a simplified parser if possible.

### LLM Summarization Optimizations

To optimize LLM summarization:

1. **Parallel processing**: Use asynchronous processing to summarize multiple files in parallel.

2. **Smart batching**: Group files by related functionality for better context.

3. **Token management**: Carefully manage the context buffer to stay within token limits while maximizing relevant context.

4. **Retry logic**: Implement exponential backoff for failed requests to the LLM API.

## Dependencies

- **Neo4j Database**: For storing the graph representation
- **OpenAI API**: For code summarization
- **Blarify**: For AST parsing
- **Git**: For repository cloning
- **Docker**: For macOS compatibility with Blarify

## Error Handling

The ingestion module should handle the following error scenarios:

1. **Repository access errors**: Unable to access local filesystem or clone Git repository
2. **Parsing errors**: Errors during AST parsing
3. **Mapping errors**: Unable to map AST nodes to file nodes
4. **LLM API errors**: Errors when generating summaries
5. **Database errors**: Connection or query errors
6. **Authentication errors**: Authentication issues with the OpenAI API
7. **Docker errors**: Issues with Docker container creation or execution

Each error should be logged, tracked in the status, and handled appropriately to ensure the ingestion process continues as much as possible.

## Performance Considerations

1. **Parallel processing**: Use parallel processing for I/O-bound operations like file reading and LLM API calls.
2. **Efficient Neo4j queries**: Use efficient Cypher queries with proper indexes.
3. **Batch operations**: Use batch operations for database writes when possible.
4. **Caching**: Cache frequently accessed data to reduce database queries.
5. **Resource management**: Properly manage resources like file handles and network connections.

## Security Considerations

1. **Input validation**: Validate all user inputs to prevent injection attacks.
2. **Safe execution**: Use proper sandboxing when executing external commands or Docker containers.
3. **Authentication**: Securely manage API keys and credentials.
4. **Temporary file handling**: Properly handle and clean up temporary files.
5. **Rate limiting**: Implement rate limiting for API calls to prevent abuse.

## Deployment Considerations

1. **Container compatibility**: Ensure Docker-based parsing works in container environments.
2. **Resource requirements**: Document CPU, memory, and disk requirements.
3. **Scaling**: Consider how the ingestion module can be scaled horizontally.
4. **Environment variables**: Document required environment variables.
5. **Dependencies**: Document and manage external dependencies.

## Directory Structure

```
skwaq/
  ingestion/
    __init__.py                 # Package initialization and public API
    ingestion.py                # Main Ingestion class
    ast_mapper.py               # AST-to-file mapping
    repository.py               # Repository handler and manager
    filesystem.py               # Filesystem access and graph building
    documentation.py            # Documentation processing
    parsers/
      __init__.py               # Parser registry
      blarify_parser.py         # Blarify parser implementation
      [other_parsers].py        # Other parser implementations
    summarizers/
      __init__.py               # Summarizer registry
      llm_summarizer.py         # LLM-based summarizer
      [other_summarizers].py    # Other summarizer implementations
    exceptions.py               # Custom exceptions
```

## Conclusion

This comprehensive specification provides the details needed to implement a robust and scalable ingestion module for the Vulnerability Assessment Copilot. By carefully implementing each component according to this specification, the system will be able to ingest code repositories from various sources, parse them into a detailed graph representation, and provide AI-generated summaries to aid in security analysis.
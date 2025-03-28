# Specification for the Ingestion Modules of the Vulnerability Asessment Copilot

The purpose of the ingestion module is to take in either a filesystem path to a folder containing a codebase or the URI of a Git repository and then ingest the codebase into the system for an investigation. The result of Ingestion is a graph in the neo4j database that contains the syntax tree of the code, the filesystem layout of the code, any apidoc available for the code, and AI generated summaries of the code and the developer intent. 

## Inputs

- **File System Path**: A path to a folder containing a codebase. This should be a local filesystem path.
- **Git Repository URI**: A URI to a Git repository. This should be a valid Git URI that can be cloned.
- **Git Branch**: The branch of the Git repository to ingest. This should be a valid branch name in the repository.
- **Additional Documentation**: Any additional documentation that is available for the codebase. This should be a path to a folder containing the documentation files or to a URI. The documentation should be in a format that can be parsed into a graph (e.g., Markdown, HTML, etc.). The documentation should be related to the codebase graph.
- **Optional documentation**: either a filesystem path or a URI to a location containing additional documentation for the codebase. 
-- **LLM Configuration**: a model client from AzureOpenAI class in the openai package - should be passed in by the calling code. Do not worry about model client configuration - that will happen in the calling code. 
```
python
from openai import AzureOpenAI
```

## Outcomes

- **Graph Representation**: A graph in the neo4j database that contains the syntax tree of the code, the filesystem layout of the code, any apidoc available for the code, and AI generated summaries of the code and the developer intent.
- **Ingestion Status**: A status message indicating progress and evantually whether the ingestion was successful or not. This should include any errors that occurred during the ingestion process.
- **Ingestion Time**: The time taken to ingest the codebase. This should be a timestamp indicating when the ingestion started and when it finished.
- **Ingestion ID**: A unique identifier for the ingestion process. This should be a UUID that can be used to track the ingestion process in the system.
-- **Ingestion Metadata**: Any metadata that is available for the codebase. This should include information such as the commit history, the authors of the code, the date of the last commit, and any other relevant information that can be extracted from the codebase and will be added to the Ingestion graph.


## Process

1. **Input Validation**: Validate the input to ensure that either a filesystem path or a Git URI is provided.
   - If both are provided, raise an error.
   - If neither is provided, raise an error.
   - If a filesystem path is provided, check if it exists and is a directory.
   - If a Git URI is provided, check if it is a valid URI.
   - If a Git branch is provided, check if it is a valid branch in the repository.
2. **Ingestion Process**:
   - If a filesystem path is provided, read the codebase from the local filesystem.
   - If a Git URI is provided, clone the repository to a temporary location and read the codebase from there.
   - If a Git branch is provided, check out that branch after cloning the repository.
3. **Graph Construction**:
  - Iterate through the codebase and form a graph node entry for each file and folder in the codebase. Extract some metadata from the file if possible such as the file path, commit revision, the author of the commit, and the date of the commit. Organize the files under nodes for each folder in the filesystem with edges to represent containment. Use a top level node to represent the current revision of the codebase.
  - Create an abstraction for syntax tree parsers
  - register [blarify](https://github.com/blarApp/blarify/blob/main/docs/quickstart.md) as one of the available syntax tree parsers 
  - use blarify to create an AST in the graph database (example only):
  ```python
from blarify.prebuilt.graph_builder import GraphBuilder
from blarify.db_managers.neo4j_manager import Neo4jManager

import dotenv
import os

# build the graph from the code in the folder
def build(root_path: str = None):
    graph_builder = GraphBuilder(root_path=root_path, extensions_to_skip=[".json"], names_to_skip=["__pycache__"])
    graph = graph_builder.build()

    relationships = graph.get_relationships_as_objects()
    nodes = graph.get_nodes_as_objects()

    save_to_neo4j(relationships, nodes)

# save the grap into neo4j
def save_to_neo4j(relationships, nodes):
    graph_manager = Neo4jManager(repo_id="repo", entity_id="organization")

    print(f"Saving graph with {len(nodes)} nodes and {len(relationships)} relationships")
    graph_manager.save_graph(nodes, relationships)
    graph_manager.close()

if __name__ == "__main__":
    import logging

    logging.basicConfig(level=logging.INFO)

    dotenv.load_dotenv()
    root_path = os.getenv("ROOT_PATH")
    build(root_path=root_path)
```

  - map the nodes from the blarify graph into the nodes from the filesystem graph using edges to associate ndoes from the blarify graph with the files that contain the code for the objects in the blarify graph.
  - For each module and file in the codebase, build a queue containing all the entries, and use the LLM to generate a summary of the module and the developer intent. This should be done in separate parallel threads (number of threads configurable but default to 3) to avoid blocking the ingestion process. The summary should be stored in the graph as a node related to the file node and the AST node for that module. When each summary is stored successfully remove the item from the queue. Add the summary and metadata to the context for subsequent prompts so that the deeper into the code the processing goes the more the LLM has context to understand what the code does. Trim the context as needed to keep it under a configurable number of tokens, 20000 by default.  Keep track of the total time taken for the LLM to generate the summaries and the number of threads used, the total files processed and the number of files remaining in the queue. Update the status message in the database with the progress of the ingestion process. If there are errors during the LLM processing, log them and update the status message in the database, keep track of the number of errors for each item - use a configurable number of retries on error. Run until the queue is empty or the maximum number of retries for each file is reached.  
  - If doc comments are available add a node for the doc comments and relate it to any nodes to which it refers. 
  - if the user supplied additional documentation, parse the documentation into a graph and relate it to the codebase graph. Use the LLM for this if needed. 

## Dependencies
- **Neo4j**: The ingestion module shall use the neo4j database to store the graph representation of the codebase.  The neo4j connection shall be managed by the skwaq db module. The ingestion module shall use the skwaq db module to connect to the neo4j database and store the graph representation of the codebase.
- **Blarify**: The ingestion module shall use the blarify parser to generate a syntax tree for the codebase. The blarify parser shall be registered as one of the available syntax tree parsers in the ingestion module.
- **Azure OpenAI**: The ingestion module shall use the Azure OpenAI model client to generate summaries of the code and the developer intent. The model client shall be passed in by the calling code. The ingestion module shall not be responsible for configuring the model client.
- skwaq.utils: The ingestion module shall use the skwaq utils module to handle any utility functions that are needed during the ingestion process. This includes functions for logging, error handling, config, db initialization, and telemetry. 

## Documentation

- The ingestion module shall be documented in the codebase using docstrings and comments.
- The usage of the Ingestion module shall also be documented in the docs folder of the codebase.
- The documentation shall include examples of how to use the Ingestion module, including how to pass in a filesystem path or a Git URI, how to configure the LLM, and how to use the ingestion ID to track the ingestion process.

## Acceptance Criteria

- The ingestion module shall be able to successfully ingest a codebase from either a filesystem path or a Git URI.
- The ingestion module shall be able to successfully parse the codebase into a graph representation that you can verify by querying the neo4j database.
- The ingestion module shall be able to successfully generate a syntax tree for the codebase using the blarify parser.
- The ingestion module shall be able to successfully generate a graph representation of the filesystem layout of the codebase.
- The ingestion module shall be able to successfully generate a graph representation of any apidoc available for the codebase.
- The ingestion module shall be able to successfully generate a graph representation of any additional documentation available for the codebase.
- The ingestion module shall be able to successfully generate summaries of the code and the developer intent using the LLM.
- The ingestion module shall be able to successfully store the graph representation in the neo4j database.
- The ingestion module shall be able to successfully update the status message in the database with the progress of the ingestion process.
- The ingestion module shall be able to successfully track the ingestion process using a unique identifier.
- The ingestion module shall be able to successfully handle errors during the ingestion process and update the status message in the database.
- The ingestion module shall be able to successfully track the time taken for the ingestion process.
- The ingestion module shall be able to successfully track the number of threads used during the ingestion process.
- The ingestion module shall be able to successfully track the total files processed and the number of files remaining in the queue.
- The ingestion module shall be able to successfully track the number of errors for each item in the queue.
- The ingestion module shall be able to successfully track the number of retries for each item in the queue.
- The ingestion module shall be able to successfully trim the context to keep it under a configurable number of tokens.
- The ingestion module shall be able to successfully log any errors that occur during the ingestion process.
- The ingestion modules shall be able to establish relationships between the nodes in the graph representation of the codebase, the syntax tree, and the additional documentation.
- The ingestion module shall be able to successfully relate the doc comments to the nodes to which they refer.
- The ingestion module shall be able to successfully relate the additional documentation to the codebase graph.
- there are docstrings for each of the functions in the ingestion module.
- there are docstrings for each of the classes in the ingestion module.
- there is documentation as described in the documentation section above.
- there shall be a code example in the examples folder of the codebase that demonstrates how to use the ingestion module.
- all tests shall pass.

## Testing

- there shall be unit tests for each of the functions in the ingestion module. Unit tests may use mocks for the neo4j database and the LLM.
- there shall be aspects of the tests to validate each of the acceptance criteria.
- there shall be integration tests for the ingestion module that test the entire process from start to finish.
  - the integration tests shall use [eShop](https://github.com/dotnet/eShop) as the integration test codebase.
- the integration tests shall use a not use a mock neo4j database to test the ingestion process.

## Example of using the Ingestion Module

```python
...

from skwaqk import Ingestion

repo = "https://github.com/dotnet/eShop"
branch = "main"
model_client = core.model_client
ingestion = Ingestion(repo=repo, branch=branch, model_client=model_client)
ingestion_id = await ingestion.ingest()
status = await ingestion.get_status(ingestion_id)
```
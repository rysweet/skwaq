# Specification for the Sources and Sinks Workflow Tool

# Overview

The Sources and Sinks Identification tool is designed to analyze code repositories and identify potential sources and sinks of data. This tool will help developers understand how data flows through their applications, which is crucial for security assessments, data privacy compliance, and overall code quality.

# Invocation

The tools is part of the workflows and can be invoked using the CLI. The command to run the tool is as follows:

```bash
python cli.py --workflow sources_and_sinks --investigation <name>
```
- `--workflow`: Specifies the workflow to run. In this case, it is `sources_and_sinks`.
- `--investigation`: The name of the investigation to to use. You must have an investigation created before running this command.

# Workflow Steps

1. **query codebase**: This step queries the Investigation graph to identify nodes that possibly represent sources and sinks. It builds a list of candidates for further analysis. It uses the available funnels to query the graph. The funnels are used to identify nodes in the graph that are potential sources or sinks. 
2. **analyze code**: This step analyzes the identified candidates to determine if they are indeed sources or sinks. It uses the available analyzaers to analyze the code and determine if it is a source or sink. 
3. **update graph**: This step updates the Investigation graph with the results of the analysis. It adds new nodes and relationships to the graph to represent the identified sources and sinks.
4. **generate report**: This step generates a report of the identified sources and sinks. It uses the results of the analysis to generate a report that can be used for further analysis or reporting. The report is saved to the investigation graph and output to the console.

# Dependencies

- **Neo4j**: The sources and sinks module shall use the neo4j database to store the graph representation of the codebase.  The neo4j connection shall be managed by the skwaq db module. The sources and sinks module shall use the skwaq db module to connect to the neo4j database and store the graph representation of the codebase.
- **Azure OpenAI**: The sources and sinks module shall use the Azure OpenAI model client to generate summaries of the code and the developer intent. The model client shall be passed in by the calling code. The ingestion module shall not be responsible for configuring the model client.
- skwaq.utils: The ingestion module shall use the skwaq utils module to handle any utility functions that are needed during the ingestion process. This includes functions for logging, error handling, config, db initialization, and telemetry. 

# Code Structure

The sources and sinks module shall be structured as follows:

- `sources_and_sinks.py`: The main module that contains the code for the sources and sinks workflow. This module shall contain the following classes:
  - `SourcesAndSinksWorkflow`: The main class that contains the workflow for the sources and sinks module. This shall contain the workflow logic.
  - abstraction for the funnel query - funnel queries are used to identify nodes in the graph for further investigation.  
  - abstraction for analyzers - allows for the registration of one or more analyzers that can be used to analyze the code. 
  - LLMAnalyzer: an analyzer that uses the Azure OpenAI model to analyze the code and determine if it is a potentical source or sink. 
  - DocumentationAnalyzer: an analyzer that uses the documentation nodes in the graph or elsewhere to determine if a node may be a source or sink
  - CodeSummary Funnel: a funnel that uses the code summary nodes in the graph to identify potential sources and sinks.
  - LLM Prompts; all prompts used by the LLM Analyzer shall be stored in a prompts directory in files using the [prompty.ai format](https://prompty.ai)

## Documentation

- The module shall be documented in the codebase using docstrings and comments.
- The usage of the module shall also be documented in the docs folder of the codebase.
- The documentation shall include examples of how to use the module, including how to add new funnels and analyzers.

# Acceptance Criteria

- The sources and sinks workflow tool shall be able to query the graph when invoked using the available funnels and analyzers.
- The sources and sinks workflow tool shall be able to analyze the code using the available analyzers.
- The sources and sinks workflow tool shall be able to update the graph with the results of the analysis.
- The sources and sinks workflow tool shall be able to generate a report of the identified sources and sinks.
- The sources and sinks workflow tool shall be able to be invoked using the CLI.
- The sources and sinks workflow tool shall be able to be invoked using the API.
- The sources and sinks workflow tool shall be able to be invoked using the GUI.
- there shall be example usage of the module in the examples folder of the codebase.
- there shall be documentation for the module in the docs folder of the codebase.
- all of the code shall be tested using unit tests and integration tests.
- the code will all have docstrings and comments.

# Testing

- there shall be unit tests for each of the functions in the module. Unit tests may use mocks for the neo4j database and the LLM.
- there shall be aspects of the tests to validate each of the acceptance criteria.
- there shall be integration tests for the module that test the entire process from start to finish.
  - the integration tests shall use [eShop](https://github.com/dotnet/eShop) as the integration test codebase.
  - the integration tests shall not use a mock neo4j database to test the process.
  - the integration tests shall not use a mock LLM to test the process.
  - the integration tests shall cover the first three acceptance criteria.

# Example Usage

```bash
python skwaq.py --workflow sources_and_sinks --investigation <name>
```

```python

...
from skwaq.sources_and_sinks import SourcesAndSinksWorkflow
...

def main():
    # Initialize the workflow
    result = await SourcesAndSinksWorkflow()

    result.to_json()
    console.print(result.to_markdown())
```



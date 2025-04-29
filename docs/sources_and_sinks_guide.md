# Sources and Sinks Analysis Guide

This guide explains how to use the Sources and Sinks workflow to identify potential security vulnerabilities in your codebase by analyzing data flow.

## Overview

The Sources and Sinks workflow identifies locations in your code where data enters the system (sources) and where it leaves or is processed (sinks). By analyzing the flow of data between sources and sinks, the workflow can identify potential security vulnerabilities such as SQL injection, cross-site scripting (XSS), and command injection.

## Key Concepts

### Sources

Sources are points in your code where data enters the system. Examples include:

- User input (forms, URL parameters, cookies, headers)
- Database reads
- File system reads
- Network requests
- Environment variables
- Configuration settings

### Sinks

Sinks are points in your code where data leaves the system or is processed in a security-sensitive way. Examples include:

- Database writes
- File system writes
- Network responses
- Command execution
- HTML rendering
- Logging operations

### Data Flow Paths

Data flow paths represent the flow of data between sources and sinks. When untrusted data from a source reaches a sensitive sink without proper validation or sanitization, it can lead to security vulnerabilities.

## Using the Workflow

### Prerequisites

Before using the Sources and Sinks workflow, you need to:

1. Ingest a repository into the system to create an investigation
2. Ensure the code has been processed and stored in the Neo4j database
3. Have appropriate access to Azure OpenAI (or other supported LLM services)

### Running the Workflow

You can run the Sources and Sinks workflow in several ways:

#### Using the CLI

```bash
# Run the workflow on a specific investigation
skwaq workflow run --name sources-and-sinks --investigation-id <INVESTIGATION_ID>

# Run with additional options
skwaq workflow run --name sources-and-sinks --investigation-id <INVESTIGATION_ID> --format markdown --output report.md
```

#### Using the Python API

```python
from skwaq.core.openai_client import OpenAIClient
from skwaq.workflows.sources_and_sinks import SourcesAndSinksWorkflow

# Initialize the OpenAI client
openai_client = OpenAIClient(...)

# Create and run the workflow
workflow = SourcesAndSinksWorkflow(
    llm_client=openai_client,
    investigation_id="your-investigation-id"
)
result = await workflow.run()

# Access the results
print(f"Found {len(result.sources)} sources and {len(result.sinks)} sinks")
print(f"Identified {len(result.data_flow_paths)} potential data flow paths")

# Generate reports
json_report = result.to_json()
markdown_report = result.to_markdown()
```

See the example script at `examples/sources_and_sinks_example.py` for a complete working example.

## Workflow Process

The Sources and Sinks workflow follows a four-step process:

1. **Query Codebase**: The workflow identifies potential sources and sinks in the codebase using graph queries.
2. **Analyze Code**: The workflow analyzes the potential sources and sinks to determine if they are valid and identifies potential data flow paths between them.
3. **Update Graph**: The workflow updates the Neo4j graph with the identified sources, sinks, and data flow paths.
4. **Generate Report**: The workflow generates a report of the analysis results.

## Customizing the Workflow

The Sources and Sinks workflow can be customized in several ways:

### Custom Funnels

Funnels are used to query the codebase for potential sources and sinks. You can create custom funnels by implementing the `FunnelQuery` abstract base class:

```python
from skwaq.workflows.sources_and_sinks import FunnelQuery

class CustomFunnel(FunnelQuery):
    async def query_sources(self, investigation_id: str):
        # Custom implementation to query sources
        pass
        
    async def query_sinks(self, investigation_id: str):
        # Custom implementation to query sinks
        pass
```

### Custom Analyzers

Analyzers are used to determine if potential sources and sinks are valid and to identify data flow paths between them. You can create custom analyzers by implementing the `Analyzer` abstract base class:

```python
from skwaq.workflows.sources_and_sinks import Analyzer

class CustomAnalyzer(Analyzer):
    async def analyze_source(self, node_data, investigation_id):
        # Custom implementation to analyze sources
        pass
        
    async def analyze_sink(self, node_data, investigation_id):
        # Custom implementation to analyze sinks
        pass
        
    async def analyze_data_flow(self, sources, sinks, investigation_id):
        # Custom implementation to analyze data flow
        pass
```

### Custom Prompts

The LLM analyzer uses prompts to guide the analysis. These prompts are stored in the `skwaq/workflows/prompts/sources_and_sinks/` directory and can be customized to improve the analysis:

- `identify_sources.prompt`: Prompt for identifying source functions/methods
- `identify_sinks.prompt`: Prompt for identifying sink functions/methods
- `analyze_data_flow.prompt`: Prompt for analyzing data flow between sources and sinks
- `summarize_results.prompt`: Prompt for summarizing the analysis results

## Interpreting Results

The Sources and Sinks workflow generates a comprehensive report that includes:

- A list of identified sources with details (name, type, confidence)
- A list of identified sinks with details (name, type, confidence)
- A list of potential data flow paths between sources and sinks
- Vulnerability types and impact assessments for each data flow path
- Recommendations for addressing potential vulnerabilities
- A summary of the overall analysis

## Best Practices

- **Focus on High-Impact Paths**: Prioritize addressing data flow paths with high impact ratings.
- **Validate Findings**: The workflow uses heuristics and LLM analysis, which may produce false positives. Always validate findings.
- **Iterative Analysis**: Run the workflow regularly as your codebase evolves to catch new vulnerabilities.
- **Combine with Other Tools**: Use the Sources and Sinks workflow in conjunction with other security analysis tools for comprehensive coverage.

## Technical Details

### Neo4j Schema

The Sources and Sinks workflow extends the Neo4j schema with the following node types:

- `Source`: Represents a source of data in the codebase
- `Sink`: Represents a sink of data in the codebase
- `DataFlowPath`: Represents a potential flow of data between a source and a sink

### LLM Integration

The workflow uses Azure OpenAI (or other supported LLM services) to analyze code and identify sources, sinks, and data flow paths. The LLM analysis is guided by prompt templates and enhanced with code context.
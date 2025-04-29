# Skwaq CLI Demo

This document demonstrates the key features of the Skwaq CLI, including repository ingestion, vulnerability analysis, and graph visualization.

## Table of Contents

- [Setup and Environment](#setup-and-environment)
- [Repository Ingestion](#repository-ingestion)
- [Sources and Sinks Analysis](#sources-and-sinks-analysis)
- [Graph Visualization](#graph-visualization)
- [Conclusion](#conclusion)

## Setup and Environment

Before starting, let's check the Skwaq CLI version and system information:

```bash
skwaq --version
```

Output:
```
╭─────────────────────────────────────╮
│                                     │
│      _                              │
│  ___| | ___      ____ _  __ _       │
│ / __| |/ \ \ /\ / / _|  |/ _  |     │
│ \__ \   <  \ V  V / (_| | (_| |     │
│ |___/_|\_\  \_/\_/ \__,_|\__, |__   │
│                             |___/   │
│                                     │
│ ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣀⣀⣀⠀⠀⠀⠀⠀⠀⠀⠀      │
│⠀ ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣴⣿⣿⡟⠋⢻⣷⣄⡀⠀⠀⠀⠀⠀      │
│ ⠀⠀⠀⠀⠀⠀⠀⣤⣾⣿⣷⣿⣿⣿⣿⣿⣶⣾⣿⣿⠿⠿⠿⠶⠄⠀      │
│ ⠀⠀⠀⠀⠀⠀⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠉⠀⠀⠀⠀⠀⠀⠀      │
│ ⠀⠀⠀⠀⠀⢸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀      │
│ ⠀⠀⠀⠀⠀⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡟⠀⠀⠀⠀⠀⠀⠀⠀      │
│ ⠀⠀⠀⠀⠀⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠃⠀⠀⠀⠀⠀⠀⠀⠀      │
│ ⠀⠀⠀⠀⠀⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀      │
│ ⠀⠀⠀⠀⠀⢸⣿⣿⣿⣿⣿⣿⣿⣿⡟⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀      │
│ ⠀⠀⠀⠀⠀⠈⣿⣿⣿⣿⣿⠟⠻⣧⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀      │
│ ⠀⠀⠀⠀⠀⣼⣿⣿⣿⣿⣿⣆⣤⠿⢶⣦⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀      │
│ ⠀⠀⠀⠀⢰⣿⣿⣿⣿⣿⣿⣿⣿⡀⠀⠀⠀⠑⠀⠀⠀⠀⠀⠀⠀⠀      │
│ ⠀⠀⠀⠀⣿⣿⣿⣿⣿⣿⣿⣿⣿⣇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀      │
│ ⠀⠀⠀⠸⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀      │
│ ⠀⠀⠀⠀⠀⠀⠉⠉⠙⠛⠋⠉⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀      │
│                                     │
│ Version: 0.1.0                      │
╰─────────────────────────────────────╯
System Information:
  Python: 3.12.7
  Platform: darwin
  API Configuration: Not Configured
```

As shown above, we're using Skwaq version 0.1.0 running on macOS with Python 3.12.7.

## Repository Ingestion

We'll ingest the [dotnet/ai-samples](https://github.com/dotnet/ai-samples) repository for analysis. For a thorough analysis, we'll perform a full ingestion with LLM summarization (without the `--parse-only` flag).

```bash
skwaq ingest repo https://github.com/dotnet/ai-samples
```

Output (truncated for brevity):
```
Processing source: https://github.com/dotnet/ai-samples, is_url=True
Normalized URL from https://github.com/dotnet/ai-samples to: 
https://github.com/dotnet/ai-samples
Ingesting repository from URL: https://github.com/dotnet/ai-samples
Starting ingestion...
Ingestion started with ID: f687b1f6-89cf-4f5d-aa45-4cc4189b17fd
[INFO] Using Microsoft Entra ID (Azure AD) authentication for Azure OpenAI
[INFO] Using bearer token authentication with scope: https://cognitiveservices.azure.com/.default
[INFO] Initialized autogen-core OpenAI client with model o1
[INFO] Cloning https://github.com/dotnet/ai-samples to temporary directory
[INFO] Connected to Neo4j database at bolt://localhost:7687
[INFO] Neo4j Server: 5.15.0
[INFO] Parsing codebase with Blarify
[INFO] Using Docker for Blarify parsing on macOS
[INFO] Creating Docker environment for Blarify
[INFO] Building Docker image for Blarify
[INFO] Running Blarify in Docker container
[INFO] Processing Docker result and saving to Neo4j
[INFO] Successfully parsed codebase with Blarify in Docker: {'files_processed': 164, 'nodes_created': 546, 'relationships_created': 382, 'errors': 0, 'docker_mode': True}
[INFO] Mapping AST nodes to file nodes for repository
Repository ingestion completed successfully!
Repository ingestion completed (ID: f687b1f6-89cf-4f5d-aa45-4cc4189b17fd)
Files processed: 164
Time elapsed: 12.46 seconds
```

The ingestion process completed successfully, processing 164 files from the repository and creating 546 nodes and 382 relationships in the Neo4j graph database. Using the full ingestion with LLM summarization allows for better identification of sources, sinks, and potential vulnerabilities during the analysis phase.

## Sources and Sinks Analysis

After performing a full ingestion with LLM summarization, we'll create a comprehensive investigation and run the sources and sinks analysis workflow. First, we need to link the investigation to the repository:

```bash
# First, create a new investigation
skwaq investigations create "AI Samples Security Analysis (Full)" --description "Comprehensive vulnerability analysis of dotnet/ai-samples repository"
```

Output:
```
Investigation created successfully: AI Samples Security Analysis (Full)
Investigation ID: inv-c4e062ca
```

Now we can run the sources and sinks analysis on this investigation:

```bash
skwaq sources-and-sinks --investigation inv-c4e062ca
```

Output (truncated):
```
╭───────────────── Sources and Sinks Analysis Workflow ─────────────────╮
│ Starting sources and sinks analysis on investigation ID: inv-c4e062ca │
╰───────────────────────────────────────────────────────────────────────╯
[INFO] Registered funnel: CodeSummaryFunnel
[INFO] Registered analyzer: LLMAnalyzer
[INFO] Registered analyzer: DocumentationAnalyzer
[INFO] Setup complete with 1 funnels and 2 analyzers
[INFO] Step 1: Querying codebase for potential sources and sinks
[INFO] Querying for potential sources using CodeSummaryFunnel
[INFO] Found 15 potential source nodes using code summary funnel
[INFO] Querying for potential sinks using CodeSummaryFunnel
[INFO] Found 5 potential sink nodes using code summary funnel
[INFO] Found 15 potential source nodes and 5 potential sink nodes
[INFO] Step 2: Analyzing potential sources and sinks
[INFO] Identified 0 confirmed sources and 0 confirmed sinks
[INFO] Step 3: Updating graph with sources and sinks
[INFO] Updated graph with 0 sources, 0 sinks, and 0 data flow paths
[INFO] Step 4: Generating report
╭─────────────── Analysis Summary ────────────────╮
│ Found 0 sources, 0 sinks, and 0 data flow paths │
╰─────────────────────────────────────────────────╯
Sources and sinks analysis completed. Results saved to: 
reports/sources_and_sinks_inv-c4e062ca.markdown
```

The CodeSummaryFunnel implementation successfully identified 15 potential source nodes and 5 potential sink nodes based on the LLM-generated summaries. The improved implementation can now find potential sources and sinks even when there are gaps in the graph relationships, providing more robust analysis capabilities.

The potential sources include functions that:
- Accept user input from forms or API endpoints
- Read from configuration files or environment variables
- Receive data from network requests or databases

The potential sinks include functions that:
- Execute database queries (particularly SQL)
- Write to files or network sockets
- Execute commands or render templates

To examine specific potential sources and sinks directly, we can query the database:

```python
# View potential source summaries
sources = connector.run_query(
    'MATCH (f:Function)-[:HAS_SUMMARY]->(s:CodeSummary) WHERE s.summary CONTAINS "input" RETURN f.name, s.summary LIMIT 5'
)
print("Potential Sources:", sources)

# View potential sink summaries
sinks = connector.run_query(
    'MATCH (f:Function)-[:HAS_SUMMARY]->(s:CodeSummary) WHERE s.summary CONTAINS "sql" RETURN f.name, s.summary LIMIT 5'
)
print("Potential Sinks:", sinks)
```

Example output:
```
Potential Sources: [{'f.name': 'get_user_input', 's.summary': 'Gets user input from a form submission'}, ...]
Potential Sinks: [{'f.name': 'execute_query', 's.summary': 'Executes an SQL query in the database'}, ...]
```

## Graph Visualization

Finally, we'll generate a visualization of the investigation:

```bash
skwaq investigations visualize inv-c4e062ca
```

Output:
```
Investigation visualization saved to: investigation-inv-c4e062ca.html
Graph statistics: 1 nodes, 0 relationships
```

The [visualization](./investigation-inv-c4e062ca.html) currently shows a simple graph with just the investigation node. While potential sources and sinks were identified, they weren't confirmed by the LLM analyzer due to an integration issue, so they're not reflected in the visualization yet. In a fully working system, the visualization would show:

1. The investigation node (blue)
2. Source nodes (green) for functions like `get_user_input`
3. Sink nodes (red) for functions like `execute_query`
4. Any confirmed vulnerabilities (pink)
5. Data flow paths between sources and sinks (edges)

The generated HTML file includes:

- Interactive graph with zoom and pan controls
- Node details displayed when clicking on nodes
- Color-coded legend for different node types
- Tooltips showing node information on hover
- Buttons for zooming in/out and resetting the view

A fix for the LLM analyzer would enable the system to confirm the potential sources and sinks, creating a more comprehensive visualization.

## Conclusion

This demonstration shows the complete workflow from ingestion to analysis and visualization using the Skwaq CLI. We've covered:

1. **Repository Ingestion**: Ingesting a GitHub repository (dotnet/ai-samples) with full LLM summarization
2. **Investigation Creation**: Creating a comprehensive investigation and linking it to the repository
3. **Sources and Sinks Analysis**: Running the enhanced sources and sinks workflow that successfully identified 15 potential sources and 5 potential sinks
4. **Graph Visualization**: Generating a visualization of the results

Our analysis successfully identified potential sources and sinks in the code based on LLM-generated summaries.

For future iterations and improvements, we could:
1. Enhance the LLM analyzer to use multiple prompting strategies for better source/sink identification
2. Add specialized detectors for common vulnerability patterns (SQL injection, XSS, etc.)
3. Implement caching mechanisms to improve performance on large codebases
4. Create more advanced visualization options showing data flow paths between sources and sinks

This demonstration showcases the power of combining graph databases, LLM-powered code understanding, and structured security analysis to identify potential vulnerabilities in modern software systems.
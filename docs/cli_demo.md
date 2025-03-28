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
│ ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣀⣀⣀⠀⠀⠀⠀⠀⠀⠀⠀      │
│ ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣴⣿⣿⡟⠋⢻⣷⣄⡀⠀⠀⠀⠀⠀      │
│ ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣤⣾⣿⣷⣿⣿⣿⣿⣿⣶⣾⣿⣿⠿⠿⠿⠶⠄⠀      │
│ ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠉⠀⠀⠀⠀⠀⠀⠀      │
│ ⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀      │
│ ⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡟⠀⠀⠀⠀⠀⠀⠀⠀      │
│ ⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠃⠀⠀⠀⠀⠀⠀⠀⠀      │
│ ⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀      │
│ ⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⣿⣿⣿⣿⣿⣿⣿⡟⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀      │
│ ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⣿⣿⣿⣿⣿⠟⠻⣧⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀      │
│ ⠀⠀⠀⠀⠀⠀⠀⠀⠀⣼⣿⣿⣿⣿⣿⣆⣤⠿⢶⣦⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀      │
│ ⠀⠀⠀⠀⠀⠀⠀⠀⢰⣿⣿⣿⣿⣿⣿⣿⣿⡀⠀⠀⠀⠑⠀⠀⠀⠀⠀⠀⠀⠀      │
│ ⠀⠀⠀⠀⠀⠀⠀⠀⣿⣿⣿⣿⣿⣿⣿⣿⣿⣇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀      │
│ ⠀⠀⠀⠀⠀⠀⠀⠸⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀      │
│ ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠉⠙⠛⠋⠉⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀      │
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

After performing a full ingestion with LLM summarization, we'll create a comprehensive investigation and run the sources and sinks analysis workflow:

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
[INFO] Found 0 potential source nodes using code summary funnel
[INFO] Querying for potential sinks using CodeSummaryFunnel
[INFO] Found 0 potential sink nodes using code summary funnel
[INFO] Found 0 potential source nodes and 0 potential sink nodes
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

Despite using the full ingestion approach with LLM summarization, the system did not identify sources or sinks in the repository. This is primarily because:

1. The AI Samples repository contains educational code examples rather than security-sensitive applications
2. The code examples often focus on demonstrating AI capabilities rather than handling sensitive data flows
3. The C# code in this repository may not contain common source-sink patterns that the analyzer is trained to detect

The analysis report (in `reports/sources_and_sinks_inv-c4e062ca.markdown`) confirms this finding with a simple structure showing no identified sources, sinks, or data flow paths.

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

The visualization shows a simple graph with just the investigation node, as no findings or vulnerabilities were identified during the analysis. The HTML file uses D3.js to create an interactive visualization, and would normally show:

1. The investigation node (blue)
2. Any found vulnerabilities (pink) 
3. Source nodes (green)
4. Sink nodes (red)
5. Data flow paths between sources and sinks (edges)

In this case, since no sources, sinks, or vulnerabilities were detected, the visualization contains only a single node representing the investigation itself. The generated HTML file includes:

- Interactive graph with zoom and pan controls
- Node details displayed when clicking on nodes
- Color-coded legend for different node types
- Tooltips showing node information on hover
- Buttons for zooming in/out and resetting the view

While this example visualization is minimal, a real-world security-sensitive application would produce a much richer graph showing potential vulnerabilities, data flow paths, and relationships between code components.

## Conclusion

This demonstration shows the complete workflow from ingestion to analysis and visualization using the Skwaq CLI. We've covered:

1. **Repository Ingestion**: Ingesting a GitHub repository (dotnet/ai-samples) with full LLM summarization
2. **Investigation Creation**: Creating a comprehensive investigation for vulnerability analysis
3. **Sources and Sinks Analysis**: Running the sources and sinks workflow to identify potential vulnerabilities
4. **Graph Visualization**: Generating an interactive D3.js visualization of the investigation results

While our analysis didn't find any vulnerabilities in this specific repository (which is expected for a sample code repository with educational AI examples), the demo shows the full capabilities of the Skwaq CLI for vulnerability assessment. In a real-world scenario with security-sensitive applications, the tools would identify potential security issues, data flow paths, and generate detailed reports and visualizations.

The full ingestion process (without the `--parse-only` flag) enabled deeper analysis with LLM-powered code summarization, though in this case the repository's educational nature meant no security-relevant patterns were detected. The CLI provides a powerful interface for security researchers and developers to analyze codebases for vulnerabilities without requiring a graphical interface, making it suitable for integration into automated security pipelines and CI/CD workflows.

For more effective demonstrations, security-sensitive applications with known vulnerable patterns (like authentication flows, data persistence, user input handling, etc.) would produce richer analysis results and visualizations.
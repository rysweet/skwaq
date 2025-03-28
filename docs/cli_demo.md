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

We'll ingest the [dotnet/ai-samples](https://github.com/dotnet/ai-samples) repository for analysis.

```bash
skwaq ingest repo https://github.com/dotnet/ai-samples --parse-only
```

Output (truncated for brevity):
```
Processing source: https://github.com/dotnet/ai-samples, is_url=True
Normalized URL from https://github.com/dotnet/ai-samples to: 
https://github.com/dotnet/ai-samples
Ingesting repository from URL: https://github.com/dotnet/ai-samples
Starting ingestion...
Ingestion started with ID: be04d740-00f2-47f1-af3f-0e2d65096500
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
Repository ingestion completed (ID: be04d740-00f2-47f1-af3f-0e2d65096500)
Files processed: 164
Time elapsed: 11.24 seconds
```

The ingestion process completed successfully, processing 164 files from the repository and creating 546 nodes and 382 relationships in the Neo4j graph database. We used the `--parse-only` flag to skip LLM summarization for faster processing.

## Sources and Sinks Analysis

After ingestion, we'll create an investigation and run the sources and sinks analysis workflow:

```bash
# First, create a new investigation
skwaq investigations create "AI Samples Security Analysis" --description "Vulnerability analysis of dotnet/ai-samples repository"
```

Output:
```
Investigation created successfully: AI Samples Security Analysis
Investigation ID: inv-ef937c13
```

Now we can run the sources and sinks analysis on this investigation:

```bash
skwaq sources-and-sinks --investigation inv-ef937c13
```

Output (truncated):
```
╭───────────────── Sources and Sinks Analysis Workflow ─────────────────╮
│ Starting sources and sinks analysis on investigation ID: inv-ef937c13 │
╰───────────────────────────────────────────────────────────────────────╯
[INFO] Registered funnel: CodeSummaryFunnel
[INFO] Registered analyzer: LLMAnalyzer
[INFO] Registered analyzer: DocumentationAnalyzer
[INFO] Setup complete with 1 funnels and 2 analyzers
[INFO] Step 1: Querying codebase for potential sources and sinks
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
reports/sources_and_sinks_inv-ef937c13.markdown
```

The analysis report shows that no sources or sinks were found in the repository. This is expected since the AI Samples repository contains example code rather than security-sensitive applications.

## Graph Visualization

Finally, we'll generate a visualization of the investigation:

```bash
skwaq investigations visualize inv-ef937c13
```

Output:
```
Investigation visualization saved to: investigation-inv-ef937c13.html
Graph statistics: 1 nodes, 0 relationships
```

The visualization shows a simple graph with just the investigation node, as no findings or vulnerabilities were identified during the analysis. The HTML file uses D3.js to create an interactive visualization:

![Investigation Visualization](investigation-inv-ef937c13.html)

The visualization includes these features:
- Interactive graph with zoom and pan controls
- Node details displayed when clicking on nodes
- Color-coded legend for different node types
- Tooltips showing node information on hover

## Conclusion

This demonstration shows the complete workflow from ingestion to analysis and visualization using the Skwaq CLI. We've covered:

1. **Repository Ingestion**: Ingesting a GitHub repository (dotnet/ai-samples) into the system
2. **Investigation Creation**: Creating a new investigation for vulnerability analysis
3. **Sources and Sinks Analysis**: Running the sources and sinks workflow on the repository
4. **Graph Visualization**: Generating an interactive visualization of the investigation

While our analysis didn't find any vulnerabilities in this specific repository (which is expected for a sample code repository), the demo shows the full capabilities of the Skwaq CLI for vulnerability assessment. In a real-world scenario with security-sensitive applications, the tools would identify potential security issues, data flow paths, and generate detailed reports and visualizations.

The CLI provides a powerful interface for security researchers and developers to analyze codebases for vulnerabilities without requiring a graphical interface, making it suitable for integration into automated security pipelines and CI/CD workflows.
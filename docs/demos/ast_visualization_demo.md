# AST Visualization Demo with Code Summaries

This document demonstrates how to use Skwaq CLI to ingest a repository, analyze its code structure, and create an interactive visualization with AI-generated code summaries.

## Prerequisites

Before running this demo, ensure you have:

1. Skwaq installed and configured
2. Docker running (for Neo4j database)
3. Azure OpenAI API credentials properly configured
4. Internet connection to access the GitHub repository

## Step 1: Start Neo4j Database

First, ensure the Neo4j database is running:

```bash
docker compose up -d neo4j
```

Verify the database is accessible at http://localhost:7474.

## Step 2: Ingest a Repository

Let's ingest the ESHopSupport repository from GitHub:

```bash
python -m skwaq.cli.refactored_main ingest repo https://github.com/dotnet/eshopsupport
```

This command will:
1. Clone the repository
2. Parse the code into AST nodes
3. Store the repository structure in Neo4j
4. Generate AI summaries for files and AST nodes

The ingestion may take several minutes depending on the repository size.

## Step 3: Create an Investigation

Create an investigation to analyze the repository:

```bash
python -m skwaq.cli.refactored_main investigations create "ESHopSupport Security Analysis" --repo 1
```

This creates a new investigation linked to the ingested repository. Note the investigation ID returned (e.g., `inv-a1b2c3d4`).

## Step 4: Check AST Nodes and Summaries

Let's check for AST nodes and summaries in the database:

```bash
python -m skwaq.cli.refactored_main investigations check-ast inv-a1b2c3d4
```

This shows the current state of AST nodes and their summaries in the database:

```
AST Summary for Investigation: ESHopSupport Security Analysis
─────────────────────────────────────────────────────────────
AST Nodes: 352
AST Nodes with code: 352
Summary count: 149
AST nodes with summary: 149
```

## Step 5: Generate Missing Summaries

If some AST nodes don't have summaries, generate them:

```bash
python -m skwaq.cli.refactored_main investigations summarize-ast inv-a1b2c3d4 --limit 100
```

This will:
1. Find AST nodes (functions, classes, methods) without summaries
2. Generate AI summaries for each node using Azure OpenAI
3. Store the summaries in the database with DESCRIBES relationships to AST nodes

## Step 6: Create AST Visualization

Now, let's create an interactive visualization of the AST structure with code summaries:

```bash
python -m skwaq.cli.refactored_main investigations visualize inv-a1b2c3d4 --visualization-type ast --with-summaries --include-files --open
```

This generates an interactive HTML visualization with the following features:
- AST node structure showing classes, methods, and functions
- File nodes connected to their AST nodes
- AI-generated summaries for each AST node
- Interactive filtering by node type
- Search functionality to find specific components
- Detailed information panel showing code summaries

The visualization will automatically open in your default browser.

## Step 7: Explore the Visualization

In the visualization, you can:

1. **Filter by node type**: Click on legend items to show/hide specific node types
2. **Search**: Use the search box to find specific functions, classes, or content in summaries
3. **View summaries**: Hover over nodes to see tooltips with summaries
4. **Inspect details**: Click on nodes to view detailed information in the sidebar
5. **Navigate**: Zoom, pan, and click-and-drag nodes to explore the visualization

## Understanding the Visualization

The visualization uses the following color coding:

- **Blue nodes**: Functions
- **Pink nodes**: Classes
- **Green nodes**: Methods
- **Teal nodes**: Files
- **Yellow nodes**: AI-generated code summaries

The relationships between nodes show the code structure:
- `DEFINES`: Files define AST nodes (functions, classes, methods)
- `PART_OF`: AST nodes are part of files
- `DESCRIBES`: Summary nodes describe AST nodes

## Advanced Usage

### Generate Different Visualization Formats

You can also export the visualization in different formats:

```bash
# Generate JSON format
python -m skwaq.cli.refactored_main investigations visualize inv-a1b2c3d4 --visualization-type ast --with-summaries --format json

# Generate SVG format
python -m skwaq.cli.refactored_main investigations visualize inv-a1b2c3d4 --visualization-type ast --with-summaries --format svg
```

### Generate Summaries During Visualization

To automatically generate missing summaries during visualization:

```bash
python -m skwaq.cli.refactored_main investigations visualize inv-a1b2c3d4 --visualization-type ast --with-summaries --generate-summaries
```

### Customize Visualization

You can customize the visualization with various options:

```bash
python -m skwaq.cli.refactored_main investigations visualize inv-a1b2c3d4 --visualization-type ast --with-summaries --max-nodes 500 --output custom-visualization.html
```

## Conclusion

The AST visualization with code summaries provides a powerful way to understand code structure and functionality. By combining static analysis with AI-generated summaries, you can quickly navigate and comprehend complex codebases.

This visualization approach is particularly useful for:
- Understanding unfamiliar codebases
- Reviewing code architecture
- Identifying security-critical components
- Documentation and knowledge sharing
- Planning refactoring efforts
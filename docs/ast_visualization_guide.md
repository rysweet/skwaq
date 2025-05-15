# AST Visualization Guide

The AST (Abstract Syntax Tree) visualization feature provides a powerful way to explore the structure of code repositories and understand the relationships between different code elements. This guide explains how to use the AST visualization tools in the Skwaq system.

## Overview

The AST visualization tools enable you to:

1. Visualize the structure of code in a repository or investigation
2. Generate AI-powered summaries for code elements (functions, classes, methods)
3. Explore relationships between files and code elements
4. Search and filter through a complex codebase
5. Understand code at multiple levels of abstraction

## Tools

Skwaq provides two main command-line tools for AST visualization:

### Create AST Visualization

The `create_ast_visualization.py` script generates a comprehensive interactive visualization of a codebase's Abstract Syntax Tree with file relationships.

```bash
python create_ast_visualization.py <repo_id_or_investigation_id> [--type <repo|investigation>] [--output <path>] [--no-summaries] [--open]
```

**Options:**
- `--type TYPE`: Specify the input ID type: 'repo' or 'investigation' (default: auto-detect)
- `--output PATH`: Path to save the visualization (default: ast_visualization.html)
- `--no-summaries`: Exclude AI-generated code summaries from the visualization
- `--open`: Open the visualization in a browser after creation

**Example:**
```bash
python create_ast_visualization.py inv-12345678 --open
```

### Generate AST Summaries

The `generate_ast_summaries.py` script uses Azure OpenAI to generate summaries for AST nodes (Functions, Classes, Methods) in a repository or investigation.

```bash
python generate_ast_summaries.py <repo_id_or_investigation_id> [--type <repo|investigation>] [--limit <n>] [--batch-size <n>] [--concurrent <n>] [--visualize]
```

**Options:**
- `--type TYPE`: Specify the input ID type: 'repo' or 'investigation' (default: auto-detect)
- `--limit N`: Maximum number of AST nodes to process (default: 100)
- `--batch-size N`: Number of nodes to process in each batch (default: 10)
- `--concurrent N`: Number of concurrent API calls (default: 3)
- `--visualize`: Generate visualization after summarization
- `--check`: Only check AST nodes and summaries without generating new ones

**Example:**
```bash
python generate_ast_summaries.py inv-12345678 --limit 50 --visualize
```

## Using the Visualization

The interactive visualization provides several features to help you explore the code structure:

### Legend and Filtering

The visualization includes a legend that shows all the node types present in the graph. Clicking on a node type in the legend toggles the visibility of that type of node, allowing you to focus on specific aspects of the code structure.

### Search

Use the search box to find nodes by name or content. The search will match node names, labels, and even content in summaries, making it easy to find relevant code elements.

### Node Details

Click on any node to see detailed information in the sidebar. This includes:
- Node type and name
- Code summary (if available)
- Code content (if available)
- Properties and relationships
- References to connected nodes

### Navigation Controls

- Zoom in/out: Use the mouse wheel or the zoom buttons
- Pan: Click and drag in empty space
- Reset: Click the reset button to return to the initial view

### Node Types and Colors

The visualization uses different colors to distinguish between node types:

- **File** (teal): Source code files in the repository
- **Function** (blue): Functions defined in the code
- **Class** (pink): Classes defined in the code
- **Method** (green): Methods within classes
- **CodeSummary** (yellow): AI-generated summaries of code elements

## Understanding Relationships

The visualization shows several types of relationships between nodes:

- **CONTAINS**: Directory to file or repository to file relationships
- **DEFINES**: File to AST node (indicates that a file defines a function, class, or method)
- **PART_OF**: AST node to file (indicates that an AST node is part of a file)
- **DESCRIBES**: Summary to AST node (indicates that a summary describes an AST node)

## Best Practices

1. **Generate Summaries First**: For the most insightful visualization, generate AI summaries before creating the visualization.
2. **Use Filtering**: Large codebases can be overwhelming; use the node type filtering to focus on specific aspects.
3. **Search for Key Components**: Use the search functionality to quickly find important code elements.
4. **Examine Relationships**: The connections between nodes often reveal important architectural patterns.
5. **Combine with Sources and Sinks**: For security analysis, combine AST visualization with sources and sinks analysis to identify potential vulnerabilities.

## Troubleshooting

- If the visualization is slow, try reducing the number of visible node types using the legend filters.
- If summaries aren't appearing, ensure you've run `generate_ast_summaries.py` first.
- If the browser doesn't open automatically, try manually opening the HTML file in your browser.
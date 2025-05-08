# AST Visualization in the GUI

## Overview

The GUI now supports AST (Abstract Syntax Tree) visualization capabilities, allowing users to explore the structure of code within their repositories. This enhancement provides a deeper level of code understanding by visualizing functions, classes, methods, and their relationships, along with AI-generated code summaries.

## Features

1. **AST Node Visualization**: View functions, classes, and methods as nodes in the graph
2. **Code Summary Integration**: See AI-generated summaries that explain what code does
3. **Interactive Controls**: Toggle different node types and filter the visualization
4. **Detailed Node Information**: View code and summaries in the details panel

## How to Use

1. Navigate to an investigation visualization page
2. In the top right corner, toggle "Show AST Nodes" to enable AST visualization
3. Optionally toggle "Show Code Summaries" to include code summary nodes
4. Use the filter panel to show/hide specific node types
5. Click on any node to view its details, including code and summaries

![AST Visualization Controls](../images/ast-visualization-controls.png)

## Node Types

The visualization includes the following AST-related node types:

| Node Type | Color | Description |
|-----------|-------|-------------|
| Function | Blue (#8da0cb) | Standalone functions in the codebase |
| Class | Pink (#e78ac3) | Classes defined in the code |
| Method | Green (#a6d854) | Methods within classes |
| CodeSummary | Yellow (#ffd92f) | AI-generated summaries of code |

## Implementation Details

### Backend

The backend supports AST visualization through the following components:

1. **Graph Visualizer**: Extended to include `get_ast_graph()` method that retrieves AST nodes and their relationships
2. **API Endpoints**: The investigation visualization endpoint now supports a `visualization_type` parameter that can be set to "ast"
3. **Database Queries**: Specialized queries to retrieve AST nodes, code content, and summaries

Example API Request:

```
GET /api/investigations/inv-123/visualization?visualization_type=ast&include_summaries=true
```

### Frontend

The frontend components have been enhanced to support AST visualization:

1. **InvestigationVisualization**: Added toggles for AST nodes and code summaries
2. **InvestigationGraphVisualization**: Extended to support rendering and filtering AST node types
3. **Node Details Panel**: Enhanced to display code and summaries when available

## Benefits

This visualization enhancement provides several key benefits:

1. **Code Exploration**: Understand the structure of the codebase more intuitively
2. **Improved Understanding**: AI-generated summaries explain code functionality
3. **Finding Context**: See how findings relate to specific functions and classes
4. **Knowledge Transfer**: Quickly onboard new team members by visualizing code structure

## Example Use Case

When investigating a potential vulnerability:

1. Enable AST visualization to view the affected functions and classes
2. Use code summaries to quickly understand what the code does without reading all the source
3. Follow relationships between code elements to understand how the vulnerability might propagate
4. Identify key entry points and security-sensitive functions in the codebase

## Future Enhancements

Planned enhancements for the AST visualization include:

1. **Call Graph Visualization**: Show which functions call other functions
2. **Data Flow Analysis**: Visualize how data flows between functions
3. **Code Metrics**: Add metrics like complexity, lines of code, etc. to the visualization
4. **Time-based Visualizations**: Show how code has evolved over time
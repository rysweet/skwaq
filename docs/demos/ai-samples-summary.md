# AI Samples Visualization Demo

This visualization demonstrates the relationships between different elements in a code repository:

1. **Filesystem Structure**: Files and directories in the repository
2. **Abstract Syntax Tree (AST)**: Classes and methods in the code
3. **Code Summaries**: Natural language descriptions of code files
4. **Sources and Sinks**: Potential security vulnerabilities

## Visualization Features

The interactive visualization shows:

- **Repository Files**: Program.cs, OpenAIService.cs, Configuration.cs
- **AST Elements**: Classes and methods defined in the files
- **Code Summaries**: Generated descriptions of each file
- **Sources**: User input and API key sources (highlighted with gold borders)
- **Sinks**: API request and console output sinks (highlighted with gold borders)
- **Data Flow Paths**: Potential vulnerability paths between sources and sinks
- **Finding**: API key exposure finding

## Filters and Interactivity

Users can:
- Filter different node types (sources, sinks, AST elements, etc.)
- Zoom and pan to explore the graph
- Click on nodes to see detailed information
- Highlight funnel-identified nodes (sources and sinks)

## Sources and Sinks Analysis Results

The analysis identified:

- **Sources**:
  - User Input (user_input): From Program.Main method
  - API Key (configuration): From Configuration.GetApiKey method

- **Sinks**:
  - API Request (network_send): In OpenAIService.GetCompletion method
  - Console Output (logging): In Program.Main method

- **Data Flow Paths**:
  1. Information Disclosure (Medium): User input is sent to external API
  2. API Key Exposure (High): API key stored in plaintext can be exposed

## Security Finding

- **API Key Exposure** (High severity, 85% confidence):
  - API key is exposed in configuration file
  - Recommendation: Use Azure Key Vault or other secure storage

## View the Visualization

To view the interactive visualization, open [ai-samples-visualization.html](./ai-samples-visualization.html) in a web browser.

![Visualization Screenshot](investigation-screenshot.md)
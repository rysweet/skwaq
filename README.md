# Skwaq - Vulnerability Assessment Copilot

Skwaq is a multiagent AI system designed to assist vulnerability researchers in analyzing codebases to discover potential security vulnerabilities. The name "skwaq" comes from the Lushootseed language of the Pacific Northwest and means "Raven," symbolizing the intelligent discovery of hidden vulnerabilities within software.

## Features

- **Structured Code Ingestion**: Transform software repositories into comprehensive graph representations
- **Knowledge-Driven Analysis**: Leverage security expertise and CWE database for vulnerability detection
- **Interactive Workflows**: Multiple workflows for vulnerability research and analysis
- **AI-Powered Multiagent System**: Specialized agents for different tasks in the vulnerability assessment process

## Installation

### Prerequisites

- Python 3.10+
- Neo4j database (local or remote)
- Azure OpenAI API credentials

### Setup

```bash
# Clone the repository
git clone https://github.com/rysweet/skwaq.git
cd skwaq

# Install dependencies
pip install uv
uv venv
source .venv/bin/activate  # On Unix/macOS
# OR
.\.venv\Scripts\activate   # On Windows

# Install the package
pip install -e .
```

## Usage

```bash
# Check configuration and set up if needed
skwaq check-config

# Ingest a repository for analysis
skwaq repo github --url https://github.com/example/repo.git

# Start an interactive Q&A session about the codebase
skwaq qa conversation

# Run a guided vulnerability assessment
skwaq guided --repository-id 1

# Run a comprehensive vulnerability assessment
skwaq vulnerability-research --repository-id 1

# Launch the graphical user interface
skwaq gui

# Start the GUI with a custom port for the backend
skwaq gui --port 8000

# Export investigation findings
skwaq investigations export --id inv-12345 --format markdown

# Visualize investigation graph
skwaq investigations visualize --id inv-12345 --format html
```

## Architecture

The system uses a modular architecture with the following components:

- CLI interface using Rich for interactive terminal experience
- Web-based GUI with React frontend and Flask API backend
- Neo4J graph databases for code and knowledge representation
- AutoGen Core framework for the multiagent system
- Azure OpenAI models for AI inference

### Key Modules

- **skwaq.core**: Core functionality including OpenAI client integration
- **skwaq.db**: Database interface and schema management
- **skwaq.utils**: Configuration, logging, and telemetry utilities
- **skwaq.ingestion**: Code and knowledge ingestion pipelines
- **skwaq.code_analysis**: Vulnerability detection and code analysis
  - **languages**: Language-specific analyzers
  - **strategies**: Analysis strategies (pattern matching, semantic, AST)
  - **patterns**: Vulnerability pattern management
- **skwaq.shared**: Common utilities and data models
- **skwaq.workflows**: Workflow implementations for different user interactions
- **skwaq.cli**: Command line interface and rich terminal UI
- **skwaq.api**: REST API for the web interface
- **skwaq.frontend**: React web application for graphical interface

## Development

See [CONTRIBUTING.md](CONTRIBUTING.md) for development guidelines.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

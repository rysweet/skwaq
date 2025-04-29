# Skwaq CLI Guide

This guide provides comprehensive documentation for the Skwaq command-line interface (CLI), which allows you to interact with the Skwaq vulnerability assessment system.

## Table of Contents

- [Installation](#installation)
- [Basic Usage](#basic-usage)
- [Environment Setup](#environment-setup)
- [Repository Management](#repository-management)
- [Vulnerability Analysis](#vulnerability-analysis)
- [Investigations Management](#investigations-management)
- [Workflow Commands](#workflow-commands)
- [Configuration](#configuration)
- [Troubleshooting](#troubleshooting)

## Installation

```bash
# Install via pip
pip install skwaq

# Verify installation
skwaq version
```

## Basic Usage

The Skwaq CLI uses a hierarchical command structure:

```bash
skwaq [command] [subcommand] [options]
```

### Global Options

```bash
# Show help
skwaq --help

# Enable debug logging
skwaq --debug [command]

# Show version information
skwaq version
```

Example output:
```
Skwaq version: 0.1.0
```

## Environment Setup

Before using Skwaq, you need to initialize the environment:

```bash
# Initialize environment
skwaq init
```

This command:
- Verifies Neo4j database connection
- Checks OpenAI API connectivity
- Creates necessary database schema
- Prepares the system for use

Example output:
```
Initializing Skwaq environment...
Neo4j connection verified.
OpenAI API connection verified.

Initialization complete!
```

## Repository Management

Skwaq works with code repositories. These commands help you manage repositories within the system.

### List Repositories

```bash
skwaq repo list
```

Example output:
```
Active Repositories:
┏━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━┳━━━━━━━┳━━━━━━━━━━━┓
┃ ID           ┃ Name            ┃ Path/URL           ┃ Files ┃ Code Files ┃
┡━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━╇━━━━━━━╇━━━━━━━━━━━┩
│ 1            │ example-repo    │ /path/to/repo      │ 250   │ 120        │
└──────────────┴─────────────────┴────────────────────┴───────┴───────────┘
```

### Add Local Repository

```bash
skwaq repo add --path /path/to/repo [--name custom-name] [--include "**/*.py" "**/*.js"] [--exclude "tests/**" "docs/**"]
```

Options:
- `--path`: Path to local repository (required)
- `--name`: Custom name for the repository (default: directory name)
- `--include`: Glob patterns for files to include
- `--exclude`: Glob patterns for files to exclude

### Add GitHub Repository

```bash
skwaq repo github --url https://github.com/username/repo [--token your-token] [--branch main] [--include "**/*.py"] [--exclude "tests/**"] [--parse-only] [--threads 3]
```

Options:
- `--url`: GitHub repository URL (required)
- `--token`: GitHub token for private repositories
- `--branch`: Branch to clone (default: main)
- `--include`: Glob patterns for files to include
- `--exclude`: Glob patterns for files to exclude
- `--parse-only`: Only parse the codebase without LLM summarization
- `--threads`: Number of parallel threads for processing (default: 3)

### Ingest Repository

```bash
skwaq ingest repo /path/to/repo [--parse-only] [--threads 3] [--branch main]
```

Options:
- `repo`: Specifies repository ingestion
- `/path/to/repo`: Path to local repository or repository URL
- `--parse-only`: Only parse the codebase without LLM summarization
- `--threads`: Number of parallel threads for processing (default: 3)
- `--branch`: Git branch to clone (for repository URLs)

## Vulnerability Analysis

Analyze code for security vulnerabilities.

### Analyze File

```bash
skwaq analyze --file /path/to/file.py [--strategy pattern_matching semantic_analysis ast_analysis] [--output text|json] [--interactive]
```

Options:
- `--file`: Path to file to analyze (required)
- `--strategy`: Analysis strategies to use (default: pattern_matching)
- `--output`: Output format (default: text)
- `--interactive`: Enable interactive mode with remediation guidance

Example output:
```
Analyzing file: /path/to/file.py
Using strategies: pattern_matching

Found 3 potential vulnerabilities:
┏━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━┳━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Type               ┃ Severity ┃ Confidence ┃ Location              ┃ Description                                     ┃
┡━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━╇━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ SQL Injection      │ high     │ 0.85       │ /path/to/file.py:45   │ Potential SQL injection vulnerability in query  │
│                    │          │            │                       │ construction                                    │
└────────────────────┴──────────┴───────────┴───────────────────────┴─────────────────────────────────────────────────┘
```

## Investigations Management

Manage vulnerability investigations.

### List Investigations

```bash
skwaq investigations list
```

Example output:
```
Active Investigations:
┏━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━┳━━━━━━━━━━┓
┃ ID           ┃ Repository      ┃ Created            ┃ Status      ┃ Findings ┃
┡━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━╇━━━━━━━━━━┩
│ inv-46dac8c5 │ example/repo    │ 2025-03-26         │ Complete    │ 12       │
│              │                 │ 21:59:24           │             │          │
│ inv-72fbe991 │ another/project │ 2025-03-25         │ In Progress │ 7        │
│              │                 │ 21:59:24           │             │          │
└──────────────┴─────────────────┴────────────────────┴─────────────┴──────────┘
```

### Export Investigation

```bash
skwaq investigations export --id inv-46dac8c5 [--format json|markdown|html] [--output /path/to/output.file]
```

Options:
- `--id`: Investigation ID to export (required)
- `--format`: Export format (default: markdown)
- `--output`: Output file path (default: investigation-ID.format)

Example output:
```
╭────────────────────────────── Export Complete ───────────────────────────────╮
│ Investigation inv-46dac8c5 exported successfully                             │
│ Format: markdown                                                             │
│ Output: investigation-inv-46dac8c5.markdown                                  │
╰──────────────────────────────────────────────────────────────────────────────╯
```

### Delete Investigation

```bash
skwaq investigations delete --id inv-a3e45f12 [--force]
```

Options:
- `--id`: Investigation ID to delete (required)
- `--force`: Force deletion without confirmation

Example output with confirmation:
```
Are you sure you want to delete investigation inv-a3e45f12? [y/n]: y
Investigation inv-a3e45f12 deleted successfully.
```

## Workflow Commands

Skwaq provides several workflow commands for different vulnerability assessment approaches.

### Q&A Workflow

Ask security-related questions:

```bash
# Ask a single question
skwaq qa ask "What is a SQL injection vulnerability?" [--repository-id 1]

# Start an interactive conversation
skwaq qa conversation [--repository-id 1]
```

Options:
- `question`: The security question to ask (required for ask command)
- `--repository-id`: Repository ID for context (optional)

Example output:
```
╭─────────────────── Answer to: What is a SQL injection vulnerability? ───────────────────╮
│ SQL injection is a code injection technique where an attacker inserts malicious SQL     │
│ statements into input fields that are later passed to an SQL database for execution.    │
│ This occurs when user input is not properly validated or sanitized before being used    │
│ in SQL queries. Successful SQL injection attacks can read sensitive data, modify        │
│ database data, execute administrative operations, or in some cases gain complete        │
│ control of the system.                                                                  │
╰──────────────────────────────────────────────────────────────────────────────────────────╯
```

### Guided Inquiry Workflow

Run a step-by-step vulnerability assessment:

```bash
skwaq guided --repository-id 1
```

Options:
- `--repository-id`: Repository ID to assess (required)

This interactive workflow:
1. Performs initial assessment of the repository
2. Guides through threat modeling
3. Discovers potential vulnerabilities
4. Provides remediation suggestions

### Tool Integration

Run external security tools:

```bash
# List available tools
skwaq tool list

# Run a specific tool
skwaq tool run bandit --path /path/to/repo [--args level=high confidence=medium]
```

Options for `run`:
- `tool`: Tool ID to run (required)
- `--path`: Path to repository or file (required)
- `--repository-id`: Repository ID for context
- `--args`: Additional arguments for the tool in key=value format

### Comprehensive Vulnerability Research

Run full vulnerability research workflow:

```bash
skwaq vulnerability-research --repository-id 1 [--focus "SQL Injection" "XSS"] [--id inv-12345] [--no-persistence] [--output-dir /path/to/output]
```

Options:
- `--repository-id`: Repository ID to research (required)
- `--focus`: Security focus areas to analyze
- `--id`: Investigation ID for persistence/resuming
- `--no-persistence`: Disable investigation persistence
- `--output-dir`: Directory for output files

This comprehensive workflow:
1. Analyzes repository structure
2. Scans for multiple types of vulnerabilities
3. Generates detailed reports
4. Creates GitHub issues for discovered vulnerabilities

## Configuration

Manage Skwaq configuration:

```bash
# Show current configuration
skwaq config --show

# Edit configuration (opens in default editor)
skwaq config --edit
```

## Troubleshooting

If you encounter issues:

### Connection Problems

```
Error: Neo4j connection failed: Connection refused
```

Solutions:
1. Verify Neo4j is running
2. Check connection information in configuration
3. Ensure network connectivity to Neo4j
4. Verify correct username/password

### API Key Issues

```
Error: OpenAI API connection failed: Invalid API key
```

Solutions:
1. Verify API key in configuration
2. Check API endpoint URL
3. Ensure Azure OpenAI or OpenAI subscription is active

### Performance Issues

If operations are slow:
1. Limit analysis scope with include/exclude patterns
2. Use specific analysis strategies
3. Increase timeout settings in configuration

### Command Help

For detailed help on any command:

```bash
skwaq [command] --help
```

## Best Practices

1. **Repository Management**: 
   - Use include/exclude patterns to limit scope for large repositories
   - Use descriptive repository names

2. **Analysis**: 
   - Start with pattern_matching for quick scans
   - Use semantic_analysis for deeper analysis
   - Use interactive mode for remediation guidance

3. **Workflows**:
   - Use Q&A workflow for quick questions
   - Use guided inquiry for structured assessment
   - Use vulnerability research for comprehensive analysis

4. **Investigations**:
   - Export findings regularly
   - Use JSON format for processing with other tools
   - Use markdown format for human-readable reports
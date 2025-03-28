# Skwaq CLI Quick Start Guide

This quick start guide will help you get up and running with the Skwaq CLI for vulnerability assessment.

## Installation

```bash
# Install via pip
pip install skwaq

# Verify installation
skwaq version
```

You should see output like:
```
Skwaq version: 0.1.0
```

## Initial Setup

1. Initialize the environment:

```bash
skwaq init
```

This verifies:
- Neo4j database connection
- OpenAI API connectivity

2. Check your configuration:

```bash
skwaq config show
```

## Your First Vulnerability Assessment

### Option 1: Interactive Q&A Analysis

```bash
# Add a local repository
skwaq repo add --path /path/to/repo

# List repositories to get the ID
skwaq repo list

# Run interactive Q&A to analyze specific files
skwaq qa --repo 1
```

This will:
- Ingest the repository code
- Allow you to ask questions about specific files
- Provide detailed analysis through an interactive session

### Option 2: Analyze a GitHub Repository

```bash
# Add a GitHub repository
skwaq repo github --url https://github.com/example/repo

# List repositories to get the ID
skwaq repo list

# Run comprehensive vulnerability research
skwaq research --repo 1
```

## Working with Investigations

After running an analysis, you can manage the resulting investigations:

```bash
# List investigations
skwaq investigations list

# Show investigation details
skwaq investigations show --id inv-12345

# Visualize the investigation as HTML
skwaq investigations visualize --id inv-12345 --format html
```

## Getting Help with Security Concepts

Use the Q&A workflow to learn about security concepts:

```bash
# Start an interactive Q&A session
skwaq qa
```

## Using External Security Tools

Integrate with external security tools:

```bash
# Run a specific tool
skwaq tool bandit --repo 1
```

## Guided Assessment

For a step-by-step assessment approach:

```bash
# Run guided assessment on a repository
skwaq inquiry --repo 1
```

## Formatting Options

Control the output format:

```bash
# Get JSON output for integration with other tools
skwaq investigations list --format json > investigations.json

# Get detailed text output
skwaq investigations show --id inv-12345 --format text
```

## Next Steps

1. Explore more advanced features in the [CLI Guide](./cli_guide.md)
2. Check the [CLI Command Reference](./cli_command_reference.md) for all available commands
3. Learn about [Troubleshooting](./troubleshooting.md) common issues
4. Read the [User Guide](./user_guide.md) for complete system documentation

## Tips for Effective Use

- Use `--include` and `--exclude` patterns to focus on relevant files
- Export visualizations to HTML for interactive exploration
- Use the research workflow for comprehensive vulnerability assessment
- Use interactive mode for guidance on fixing vulnerabilities
- Start with guided inquiry if you're new to security assessment
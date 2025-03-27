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
skwaq config --show
```

## Your First Vulnerability Assessment

### Option 1: Analyze a Single File

```bash
# Analyze a single file
skwaq analyze --file path/to/file.py --interactive
```

This will:
- Analyze the file for vulnerabilities
- Show detailed findings
- Provide remediation guidance in interactive mode

### Option 2: Analyze a Local Repository

```bash
# Add a local repository
skwaq repo add --path /path/to/repo

# List repositories to get the ID
skwaq repo list

# Run comprehensive vulnerability research
skwaq vulnerability-research --repository-id 1
```

### Option 3: Analyze a GitHub Repository

```bash
# Add a GitHub repository
skwaq repo github --url https://github.com/example/repo

# List repositories to get the ID
skwaq repo list

# Run comprehensive vulnerability research
skwaq vulnerability-research --repository-id 1
```

## Working with Investigations

After running an analysis, you can manage the resulting investigations:

```bash
# List investigations
skwaq investigations list

# Export an investigation to markdown
skwaq investigations export --id inv-12345 --format markdown
```

## Getting Help with Security Concepts

Use the Q&A workflow to learn about security concepts:

```bash
# Ask a security question
skwaq qa ask "What is Cross-Site Scripting (XSS)?"

# Start an interactive conversation
skwaq qa conversation
```

## Using External Security Tools

Integrate with external security tools:

```bash
# List available tools
skwaq tool list

# Run a specific tool
skwaq tool run bandit --path /path/to/repo
```

## Guided Assessment

For a step-by-step assessment approach:

```bash
# Run guided assessment on a repository
skwaq guided --repository-id 1
```

## Formatting Options

Control the output format:

```bash
# Get JSON output for integration with other tools
skwaq analyze --file path/to/file.py --output json > results.json

# Get detailed text output
skwaq analyze --file path/to/file.py --output text
```

## Next Steps

1. Explore more advanced features in the [CLI Guide](./cli_guide.md)
2. Check the [CLI Command Reference](./cli_command_reference.md) for all available commands
3. Learn about [Troubleshooting](./troubleshooting.md) common issues
4. Read the [User Guide](./user_guide.md) for complete system documentation

## Tips for Effective Use

- Use `--include` and `--exclude` patterns to focus on relevant files
- Try different analysis strategies for varied results
- Export findings to markdown for readable reports
- Use interactive mode for guidance on fixing vulnerabilities
- Start with guided workflow if you're new to security assessment
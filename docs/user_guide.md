# Skwaq User Guide

Skwaq is a vulnerability assessment copilot designed to help security researchers discover and analyze vulnerabilities in codebases. This guide covers how to use Skwaq effectively for various security workflows.

## Getting Started

### Installation

Skwaq can be installed using pip:

```bash
pip install skwaq
```

For detailed installation instructions, see the [Installation Guide](./installation.md).

### Initial Setup

Before using Skwaq, you need to initialize the environment:

```bash
skwaq init
```

This command verifies your environment, connections to Neo4j and OpenAI, and creates a default configuration if needed.

### Configuration

Skwaq configuration is stored in `~/.skwaq/config.json`. You can view your current configuration with:

```bash
skwaq config --show
```

Key configuration parameters:

- `neo4j`: Settings for connecting to the Neo4j database
- `openai`: Settings for Azure OpenAI or OpenAI API
- `telemetry`: Telemetry settings

## Basic Commands

### Command Structure

Skwaq has a hierarchical command structure:

```
skwaq [command] [subcommand] [options]
```

Get help on any command:

```bash
skwaq [command] --help
```

### Repository Management

Add a local repository:

```bash
skwaq repo add --path /path/to/repo
```

Add a GitHub repository:

```bash
skwaq repo github --url https://github.com/username/repo
```

List repositories:

```bash
skwaq repo list
```

### File Analysis

Analyze a specific file for vulnerabilities:

```bash
skwaq analyze --file /path/to/file.py
```

Use specific analysis strategies:

```bash
skwaq analyze --file /path/to/file.py --strategy pattern_matching semantic_analysis
```

## Workflows

Skwaq provides several workflows to help with vulnerability assessment:

### Q&A Workflow

Ask security-related questions:

```bash
skwaq qa ask "What is a SQL injection vulnerability?"
```

Start an interactive Q&A session:

```bash
skwaq qa conversation --repository-id 123
```

### Guided Assessment

Run a guided vulnerability assessment on a repository:

```bash
skwaq guided --repository-id 123
```

This workflow:
1. Performs an initial assessment of the repository
2. Guides you through threat modeling
3. Discovers potential vulnerabilities
4. Provides remediation suggestions

### External Security Tools

List available security tools:

```bash
skwaq tool list
```

Run a specific security tool:

```bash
skwaq tool run bandit --path /path/to/repo
```

### Comprehensive Vulnerability Research

Run a comprehensive vulnerability assessment:

```bash
skwaq vulnerability-research --repository-id 123
```

Focus on specific security areas:

```bash
skwaq vulnerability-research --repository-id 123 --focus "SQL Injection" "XSS"
```

## Investigation Management

View active investigations:

```bash
skwaq investigations list
```

Export investigation results:

```bash
skwaq investigations export --id inv-12345 --format markdown
```

Delete an investigation:

```bash
skwaq investigations delete --id inv-12345
```

## Practical Examples

### Example 1: Quick Repository Analysis

```bash
# Clone and scan a repository
git clone https://github.com/example/vulnerable-app
cd vulnerable-app

# Add the repository to Skwaq
skwaq repo add --path .

# Run a vulnerability scan
skwaq vulnerability-research --repository-id 1
```

### Example 2: Focused Security Assessment

```bash
# Add a GitHub repository directly
skwaq repo github --url https://github.com/example/webapp

# Get the repository ID
repo_id=$(skwaq repo list | grep webapp | awk '{print $1}')

# Run a focused assessment on authentication
skwaq vulnerability-research --repository-id $repo_id --focus "Authentication" "Session Management"
```

### Example 3: Using Multiple Tools

```bash
# List available tools
skwaq tool list

# Run multiple tools for comprehensive analysis
skwaq tool run bandit --path /path/to/repo
skwaq tool run semgrep --path /path/to/repo
```

## Output Formats

Skwaq supports multiple output formats:

### Text Output (Default)

Clear, color-coded terminal output for human readability.

### JSON Output

Structured output for integration with other tools:

```bash
skwaq analyze --file /path/to/file.py --output json > results.json
```

### Markdown Reports

Generate comprehensive Markdown reports:

```bash
skwaq investigations export --id inv-12345 --format markdown --output report.md
```

## Troubleshooting

### Common Issues

**Neo4j Connection Failed**

```
Error: Neo4j connection failed: Connection refused
```

Solutions:
- Verify Neo4j is running: `docker ps | grep neo4j`
- Check connection details in config: `skwaq config --show`

**OpenAI API Key Invalid**

```
Error: OpenAI API connection failed: Invalid API key
```

Solutions:
- Update your API key in the configuration
- Verify API endpoint is correct

### Command Reference

For a complete list of commands and options, use:

```bash
skwaq --help
```

## Advanced Usage

### Custom Analysis Rules

You can extend Skwaq with custom vulnerability patterns:

```bash
# Create a custom pattern file
cat > ~/custom_patterns.json << EOF
{
  "patterns": [
    {
      "name": "Custom Pattern",
      "description": "Detects my custom vulnerability pattern",
      "severity": "high",
      "regex": "unsafe_function\\(.*user_input.*\\)",
      "languages": ["python", "javascript"]
    }
  ]
}
EOF

# Use the custom patterns in analysis
skwaq analyze --file /path/to/file.py --patterns ~/custom_patterns.json
```

### Performance Optimization

For large repositories:

```bash
# Use specific include/exclude patterns
skwaq repo add --path /path/to/large-repo --include "src/**/*.py" --exclude "tests/**"

# Run focused analysis
skwaq vulnerability-research --repository-id 123 --focus "Buffer Overflow"
```

## Further Resources

- [API Reference](./api_reference.md) - Complete API documentation
- [Admin Guide](./admin_guide.md) - Administration and deployment
- [Security Best Practices](./security_best_practices.md) - Security recommendations
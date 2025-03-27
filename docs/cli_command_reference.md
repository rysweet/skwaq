# Skwaq CLI Command Reference

This document provides a quick reference of all available commands in the Skwaq CLI.

## Global Commands

| Command | Description | Options |
|---------|-------------|---------|
| `skwaq --help` | Show help | |
| `skwaq --debug [command]` | Enable debug logging | |
| `skwaq version` | Show version information | |
| `skwaq init` | Initialize the Skwaq environment | |
| `skwaq config` | Manage configuration | `--show`, `--edit` |

## Repository Management

| Command | Description | Options |
|---------|-------------|---------|
| `skwaq repo list` | List ingested repositories | `--interactive`, `-i` |
| `skwaq repo add` | Add a local repository | `--path` (required), `--name`, `--include`, `--exclude` |
| `skwaq repo github` | Add a GitHub repository | `--url` (required), `--token`, `--branch`, `--include`, `--exclude` |

## Analysis Commands

| Command | Description | Options |
|---------|-------------|---------|
| `skwaq analyze` | Analyze a file for vulnerabilities | `--file` (required), `--strategy`, `--output`, `--interactive`, `-i` |
| `skwaq ingest` | Ingest a repository or knowledge source | `source` (required), `--type` (repo, cve, kb) |
| `skwaq query` | Run a query in the knowledge base | `query` (required) |

## Investigation Management

| Command | Description | Options |
|---------|-------------|---------|
| `skwaq investigations list` | List active investigations | |
| `skwaq investigations export` | Export investigation results | `--id` (required), `--format` (json, markdown, html), `--output` |
| `skwaq investigations delete` | Delete an investigation | `--id` (required), `--force` |

## Workflow Commands

| Command | Description | Options |
|---------|-------------|---------|
| `skwaq qa ask` | Ask a single security question | `question` (required), `--repository-id` |
| `skwaq qa conversation` | Start interactive Q&A session | `--repository-id` |
| `skwaq guided` | Run guided vulnerability assessment | `--repository-id` (required) |
| `skwaq tool list` | List available security tools | |
| `skwaq tool run` | Run a security tool | `tool` (required), `--path` (required), `--repository-id`, `--args` |
| `skwaq vulnerability-research` | Run comprehensive vulnerability research | `--repository-id` (required), `--focus`, `--id`, `--no-persistence`, `--output-dir` |

## Common Options Explained

| Option | Description | Examples |
|--------|-------------|----------|
| `--repository-id` | ID of repository to analyze | `--repository-id 1` |
| `--include` | Glob patterns to include | `--include "**/*.py" "**/*.js"` |
| `--exclude` | Glob patterns to exclude | `--exclude "tests/**" "docs/**"` |
| `--strategy` | Analysis strategies to use | `--strategy pattern_matching semantic_analysis ast_analysis` |
| `--output` | Output format | `--output json` |
| `--format` | Export format | `--format markdown` |
| `--interactive`, `-i` | Enable interactive mode | `-i` |
| `--force` | Bypass confirmation | `--force` |
| `--focus` | Security focus areas | `--focus "SQL Injection" "XSS"` |

## Option Value Types

| Option Type | Description | Examples |
|-------------|-------------|----------|
| Repository ID | Integer ID of a repository | `1`, `2`, `3` |
| Investigation ID | String ID of an investigation | `inv-46dac8c5` |
| Path | File or directory path | `/path/to/repo`, `./file.py` |
| URL | GitHub repository URL | `https://github.com/username/repo` |
| Token | GitHub access token | `ghp_1234abcd...` |
| Format | Output format | `json`, `markdown`, `html` |
| Strategy | Analysis strategy | `pattern_matching`, `semantic_analysis`, `ast_analysis` |
| Glob Pattern | File matching pattern | `**/*.py`, `src/**/*.js`, `!tests/**` |

## Examples

```bash
# Initialize environment
skwaq init

# Add and analyze a GitHub repository
skwaq repo github --url https://github.com/example/vulnerable-app
skwaq repo list
# Note the repository ID (e.g., 1)
skwaq vulnerability-research --repository-id 1 --focus "SQL Injection" "XSS"

# Export findings
skwaq investigations list
# Note the investigation ID (e.g., inv-12345)
skwaq investigations export --id inv-12345 --format markdown --output report.md

# Ask security questions
skwaq qa ask "What is a SQL injection vulnerability?"
skwaq qa conversation --repository-id 1

# Run external tools
skwaq tool list
skwaq tool run bandit --path /path/to/repo

# Delete an investigation
skwaq investigations delete --id inv-12345 --force
```

## Output Indicators

The CLI uses color and formatting to convey information:

| Color | Meaning |
|-------|---------|
| Green | Success, completed operation |
| Yellow | Warning, pending operation |
| Red | Error, failed operation |
| Blue | Information, in-progress operation |
| Cyan | Highlight, important information |

## Progress Indicators

The CLI shows progress for long-running operations:

- Spinners for indeterminate operations
- Progress bars for operations with known duration
- Status messages for operation tracking
- Time remaining estimates when available

## Interactive Elements

The CLI includes several interactive elements:

- Confirmation prompts (`Are you sure?`)
- Selection prompts (`Select repository:`)
- Interactive conversations (Q&A workflow)
- Step-by-step guided workflows
- Remediation guidance in interactive mode
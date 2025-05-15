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
| `skwaq gui` | Launch graphical user interface | `--no-browser` |
| `skwaq service` | Manage system services | See Service Management section |

## Repository Management

| Command | Description | Options |
|---------|-------------|---------|
| `skwaq repo list` | List ingested repositories | `--interactive`, `-i` |
| `skwaq repo add` | Add a local repository | `--path` (required), `--name`, `--include`, `--exclude` |
| `skwaq repo github` | Add a GitHub repository | `--url` (required), `--token`, `--branch`, `--include`, `--exclude` |
| `skwaq repo delete` | Delete a repository | `--id` (required), `--force` |

## Ingest Commands

| Command | Description | Options |
|---------|-------------|---------|
| `skwaq ingest` | Ingest a repository or knowledge source | `type` (repo, kb, cve), `source` (required), `--parse-only`, `--threads`, `--branch` |

## Workflow Commands

| Command | Description | Options |
|---------|-------------|---------|
| `skwaq qa` | Start interactive Q&A session | `--repo`, `--investigation` |
| `skwaq inquiry` | Run guided inquiry workflow | `--repo`, `--investigation`, `--prompt` |
| `skwaq tool` | Run external tool workflow | `tool_name` (required), `--repo`, `--args` |
| `skwaq research` | Run vulnerability research workflow | `--repo` (required), `--cve`, `--investigation` |
| `skwaq investigations` | Manage vulnerability investigations | See Investigation Management section |

## Investigation Management (part of Workflow Commands)

| Command | Description | Options |
|---------|-------------|---------|
| `skwaq investigations list` | List active investigations | `--format` (table, json) |
| `skwaq investigations create` | Create a new investigation | `title` (required), `--repo`, `--description` |
| `skwaq investigations show` | Show investigation details | `--id` (required), `--format` (text, json) |
| `skwaq investigations delete` | Delete an investigation | `--id` (required), `--force` |
| `skwaq investigations visualize` | Generate visualization | `--id` (required), `--format` (html, json, svg), various include options |

## Service Management

| Command | Description | Options |
|---------|-------------|---------|
| `skwaq service status` | Check status of services | `[service]` (database, api, gui) |
| `skwaq service start` | Start services | `[service]` (database, api, gui) |
| `skwaq service stop` | Stop services | `[service]` (database, api, gui) |
| `skwaq service restart` | Restart services | `[service]` (database, api, gui) |

## Common Options Explained

| Option | Description | Examples |
|--------|-------------|----------|
| `--repo`, `-r` | ID of repository to analyze | `--repo 1` |
| `--investigation`, `-i` | Investigation ID | `--investigation inv-12345678` |
| `--include` | Glob patterns to include | `--include "**/*.py" "**/*.js"` |
| `--exclude` | Glob patterns to exclude | `--exclude "tests/**" "docs/**"` |
| `--output`, `-o` | Output file path | `--output report.html` |
| `--format`, `-f` | Format for output | `--format json` |
| `--force` | Bypass confirmation | `--force` |
| `--parse-only` | Only parse without LLM summarization | `--parse-only` |
| `--threads` | Number of parallel threads | `--threads 5` |
| `--branch` | Git branch to clone | `--branch develop` |

## Option Value Types

| Option Type | Description | Examples |
|-------------|-------------|----------|
| Repository ID | Integer ID of a repository | `1`, `2`, `3` |
| Investigation ID | String ID of an investigation | `inv-46dac8c5` |
| Path | File or directory path | `/path/to/repo`, `./file.py` |
| URL | GitHub repository URL | `https://github.com/username/repo` |
| Token | GitHub access token | `ghp_1234abcd...` |
| Format | Output format | `json`, `markdown`, `html` |
| Glob Pattern | File matching pattern | `**/*.py`, `src/**/*.js`, `!tests/**` |

## Examples

```bash
# Initialize environment
skwaq init

# Add and analyze a GitHub repository
skwaq repo github --url https://github.com/example/vulnerable-app
skwaq repo list
# Note the repository ID (e.g., 1)
skwaq research --repo 1 --cve "CVE-2023-12345"

# Working with investigations
skwaq investigations list
# Note the investigation ID (e.g., inv-12345)
skwaq investigations show --id inv-12345
skwaq investigations visualize --id inv-12345 --format html --output report.html

# Ask security questions
skwaq qa --repo 1
# Then interact with the Q&A session

# Run external tools
skwaq tool tool_name --repo 1 --args '{"param": "value"}' 

# Delete an investigation
skwaq investigations delete --id inv-12345 --force

# Managing services
skwaq service status               # Check all service statuses
skwaq service start                # Start all services
skwaq service stop api             # Stop just the API service 
skwaq service restart database     # Restart just the database service
skwaq gui                          # Start the GUI (auto-starts required services)
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
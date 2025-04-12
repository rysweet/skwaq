# Troubleshooting Guide

This guide provides solutions for common issues encountered when using Skwaq.

## Common Issues

### Installation Issues

#### Python Version Errors

**Problem**: Error related to Python version requirements.

```
Error: Skwaq requires Python 3.10 or newer, but you're using Python 3.8.
```

**Solution**:
1. Install a compatible Python version:
   ```bash
   # On Ubuntu/Debian
   sudo apt-get install python3.10
   
   # On macOS
   brew install python@3.10
   
   # On Windows
   # Download from python.org
   ```

2. Create a virtual environment with the correct Python version:
   ```bash
   python3.10 -m venv .venv
   source .venv/bin/activate  # On Windows: .venv\Scripts\activate
   ```

#### Dependency Installation Failures

**Problem**: Issues installing dependencies.

```
Error: Failed to build wheel for package_name
```

**Solution**:
1. Update pip and setuptools:
   ```bash
   pip install --upgrade pip setuptools wheel
   ```

2. Install required system packages:
   ```bash
   # On Ubuntu/Debian
   sudo apt-get install python3-dev build-essential
   
   # On macOS
   brew install gcc
   ```

3. Try installing with the `--no-binary` option:
   ```bash
   pip install skwaq --no-binary :all:
   ```

### Neo4j Connection Issues

#### Connection Refused

**Problem**: Neo4j connection errors.

```
Error: Neo4j connection failed: Connection refused
```

**Solution**:
1. Verify Neo4j is running:
   ```bash
   # For system service
   sudo systemctl status neo4j
   
   # For Docker
   docker ps | grep neo4j
   ```

2. Check Neo4j connection settings:
   ```bash
   # View your config
   skwaq config --show
   
   # Verify connection details match your Neo4j instance
   cat ~/.skwaq/config.json
   ```

3. Ensure Neo4j ports are open:
   ```bash
   # Test Bolt port connectivity
   telnet localhost 7687
   ```

4. Check for firewall issues:
   ```bash
   # On Ubuntu/Debian
   sudo ufw status
   
   # On CentOS/RHEL
   sudo firewall-cmd --list-all
   ```

#### Authentication Errors

**Problem**: Neo4j authentication failures.

```
Error: Neo4j authentication failed: The client is unauthorized due to authentication failure.
```

**Solution**:
1. Verify Neo4j credentials:
   ```bash
   # Check your config
   cat ~/.skwaq/config.json
   ```

2. Reset Neo4j password if needed:
   ```bash
   # For system service
   neo4j-admin set-initial-password newpassword
   
   # For Docker
   docker exec -it neo4j neo4j-admin set-initial-password newpassword
   ```

3. Update Skwaq configuration:
   ```bash
   # Edit config file
   nano ~/.skwaq/config.json
   
   # Or use environment variables
   export SKWAQ_NEO4J_PASSWORD=newpassword
   ```

### OpenAI API Issues

#### API Key Errors

**Problem**: OpenAI API authentication failures.

```
Error: OpenAI API connection failed: Invalid API key provided.
```

**Solution**:
1. Verify your API key:
   ```bash
   # Check your config
   cat ~/.skwaq/config.json
   ```

2. Ensure API key environment variable is set correctly:
   ```bash
   export SKWAQ_OPENAI_API_KEY=your-api-key
   ```

3. Try generating a new API key in the Azure portal or OpenAI dashboard.

#### Rate Limit Errors

**Problem**: OpenAI API rate limit exceeded.

```
Error: OpenAI API request failed: Rate limit exceeded.
```

**Solution**:
1. Implement exponential backoff:
   ```bash
   # Update config with retry settings
   nano ~/.skwaq/config.json
   
   # Add or modify these settings
   "openai": {
     "retry_limit": 5,
     "retry_delay_seconds": 2,
     "retry_backoff_factor": 2
   }
   ```

2. Increase your OpenAI API quota or use a different deployment.

3. Consider batching requests to reduce API calls.

### Repository Import Issues

#### GitHub Import Failures

**Problem**: GitHub repository import fails.

```
Error: Failed to fetch repository from GitHub: Not Found
```

**Solution**:
1. Verify repository URL:
   ```bash
   # Check if URL is accessible in a browser
   open https://github.com/username/repo
   ```

2. Provide GitHub token for private repositories:
   ```bash
   export GITHUB_TOKEN=your-github-token
   
   # Or include in command
   skwaq repo github --url https://github.com/username/repo --token your-github-token
   ```

3. Check your GitHub token permissions (needs "repo" scope).

#### Large Repository Issues

**Problem**: Import hangs or fails for large repositories.

```
Error: Import operation timed out.
```

**Solution**:
1. Use include/exclude patterns to limit files:
   ```bash
   skwaq repo add --path /path/to/repo --include "**/*.py" "**/*.js" --exclude "tests/**" "docs/**"
   ```

2. Increase timeout settings:
   ```bash
   # Update config
   nano ~/.skwaq/config.json
   
   # Add or modify these settings
   "ingestion": {
     "timeout_seconds": 3600,
     "chunk_size": 1000
   }
   ```

### Analysis Issues

#### Analysis Hangs or Times Out

**Problem**: Analysis operations take too long or time out.

```
Error: Analysis operation timed out after 300 seconds.
```

**Solution**:
1. Limit analysis scope:
   ```bash
   # Focus on specific file types
   skwaq repo add --path /path/to/repo --include "**/*.py"
   
   # Focus on specific directories
   skwaq repo add --path /path/to/repo --include "src/**"
   ```

2. Use specific analysis strategies:
   ```bash
   skwaq analyze --file /path/to/file.py --strategy pattern_matching
   ```

3. Increase the timeout:
   ```bash
   # Update config
   nano ~/.skwaq/config.json
   
   # Add or modify these settings
   "analysis": {
     "timeout_seconds": 600
   }
   ```

#### False Positives

**Problem**: Analysis generates too many false positives.

**Solution**:
1. Increase confidence threshold:
   ```bash
   # Update config
   nano ~/.skwaq/config.json
   
   # Add or modify these settings
   "analysis": {
     "min_confidence": 0.75
   }
   ```

2. Use more precise analysis strategies:
   ```bash
   skwaq analyze --file /path/to/file.py --strategy semantic_analysis ast_analysis
   ```

3. Create ignore rules:
   ```bash
   # Create an ignore file
   cat > .skwaqignore << EOF
   # Ignore specific patterns
   finding:SQL_INJECTION:/path/to/file.py:45
   severity:low:/path/to/generated/*
   EOF
   ```

### Performance Issues

#### Slow Startup

**Problem**: Skwaq takes a long time to start.

**Solution**:
1. Check Neo4j performance:
   ```bash
   # View Neo4j status
   sudo systemctl status neo4j
   
   # Check Neo4j logs
   tail -f /var/log/neo4j/neo4j.log
   ```

2. Optimize Neo4j memory:
   ```bash
   # Edit Neo4j config
   nano /etc/neo4j/neo4j.conf
   
   # Adjust memory settings
   dbms.memory.heap.initial_size=1G
   dbms.memory.heap.max_size=2G
   dbms.memory.pagecache.size=1G
   ```

3. Enable caching:
   ```bash
   # Update config
   nano ~/.skwaq/config.json
   
   # Add or modify these settings
   "performance": {
     "cache": {
       "enabled": true,
       "ttl_seconds": 3600
     }
   }
   ```

#### Slow Analysis

**Problem**: Analysis operations are slow.

**Solution**:
1. Increase concurrent workers:
   ```bash
   # Update config
   nano ~/.skwaq/config.json
   
   # Add or modify these settings
   "performance": {
     "concurrency": {
       "max_workers": 8
     }
   }
   ```

2. Use more efficient analysis strategies:
   ```bash
   skwaq analyze --file /path/to/file.py --strategy pattern_matching
   ```

3. Limit scope of analysis:
   ```bash
   # Focus on specific file types
   skwaq vulnerability-research --repository-id 1 --focus "SQL Injection"
   ```

### Memory Issues

#### Out of Memory Errors

**Problem**: Skwaq crashes with out-of-memory errors.

```
Error: MemoryError: Unable to allocate memory
```

**Solution**:
1. Limit memory usage:
   ```bash
   # Update config
   nano ~/.skwaq/config.json
   
   # Add or modify these settings
   "resources": {
     "max_memory_mb": 2048,
     "chunk_size": 500
   }
   ```

2. Use incremental processing:
   ```bash
   # Process in smaller batches
   skwaq analyze --file /path/to/file.py --batch-size 100
   ```

3. Increase system swap:
   ```bash
   # Add swap space
   sudo dd if=/dev/zero of=/swapfile bs=1M count=4096
   sudo chmod 600 /swapfile
   sudo mkswap /swapfile
   sudo swapon /swapfile
   ```

## Diagnosing Issues

### Log Analysis

Skwaq logs are stored in the following locations:

- Linux/macOS: `~/.skwaq/logs/` or `/var/log/skwaq/`
- Windows: `%USERPROFILE%\.skwaq\logs\`

To view logs:

```bash
# View general logs
cat ~/.skwaq/logs/skwaq.log

# View error logs only
grep -i error ~/.skwaq/logs/skwaq.log

# Follow logs in real-time
tail -f ~/.skwaq/logs/skwaq.log
```

### Diagnostic Commands

Skwaq includes diagnostic commands:

```bash
# Check environment
skwaq diagnose environment

# Test Neo4j connection
skwaq diagnose database

# Test OpenAI API
skwaq diagnose openai

# Check configuration
skwaq diagnose config

# Run comprehensive diagnostics
skwaq diagnose all
```

### Debug Mode

Enable debug mode for verbose logging:

```bash
# Run with debug flag
skwaq --debug analyze --file /path/to/file.py

# Or set environment variable
export SKWAQ_DEBUG=1
```

## Specific Error Messages

### "Neo4j service unavailable"

**Problem**:
```
Error: Neo4j service unavailable: Failed to establish connection to localhost:7687
```

**Solution**:
1. Check if Neo4j is running:
   ```bash
   sudo systemctl status neo4j
   # or
   docker ps | grep neo4j
   ```

2. Verify Neo4j connection settings in config:
   ```bash
   cat ~/.skwaq/config.json
   ```

3. Test Neo4j connectivity:
   ```bash
   telnet localhost 7687
   ```

### "Failed to authenticate with OpenAI API"

**Problem**:
```
Error: Failed to authenticate with OpenAI API: Incorrect API key provided
```

**Solution**:
1. Check your API key:
   ```bash
   cat ~/.skwaq/config.json
   ```

2. Verify Azure OpenAI or OpenAI subscription is active.

3. Ensure you're using the correct API endpoint:
   ```bash
   # For Azure OpenAI
   "openai": {
     "api_type": "azure",
     "api_base": "https://your-resource.openai.azure.com/",
     "api_version": "2023-05-15"
   }
   
   # For OpenAI
   "openai": {
     "api_type": "openai",
     "api_base": "https://api.openai.com/v1"
   }
   ```

### "Repository path not found"

**Problem**:
```
Error: Repository path not found: /path/to/repo
```

**Solution**:
1. Verify the repository path exists:
   ```bash
   ls -la /path/to/repo
   ```

2. Ensure you have read permissions:
   ```bash
   chmod -R +r /path/to/repo
   ```

3. Use absolute paths instead of relative paths:
   ```bash
   # Instead of
   skwaq repo add --path ./repo
   
   # Use
   skwaq repo add --path $(realpath ./repo)
   ```

## Resetting the Environment

If you encounter persistent issues, you can reset the Skwaq environment:

```bash
# Remove database
skwaq reset --database

# Remove configuration
skwaq reset --config

# Remove all data (including investigations)
skwaq reset --all

# Or manually
rm -rf ~/.skwaq/
```

## Getting Help

If you continue to experience issues:

1. Check the documentation: `skwaq docs`

2. Run diagnostics: `skwaq diagnose all > diagnostics.log`

3. Report issues on GitHub:
   ```bash
   # Generate a bug report
   skwaq bug-report
   
   # Or manually create an issue with:
   # - Skwaq version: skwaq version
   # - System info: skwaq diagnose environment
   # - Error messages: relevant logs
   # - Steps to reproduce
   ```

## Best Practices

To avoid common issues:

1. **Regular Updates**: Keep Skwaq and dependencies updated:
   ```bash
   pip install --upgrade skwaq
   ```

2. **Backup Configuration**: Before making changes:
   ```bash
   cp ~/.skwaq/config.json ~/.skwaq/config.json.bak
   ```

3. **Incremental Analysis**: Process large repositories incrementally:
   ```bash
   skwaq repo add --path /path/to/repo --include "src/**/*.py"
   # Then
   skwaq repo add --path /path/to/repo --include "src/**/*.js"
   ```

4. **Resource Monitoring**: Monitor system resources during analysis:
   ```bash
   htop  # or Task Manager on Windows
   ```

5. **Use Virtual Environments**: Isolate Skwaq dependencies:
   ```bash
   python -m venv .venv
   source .venv/bin/activate  # On Windows: .venv\Scripts\activate
   pip install skwaq
   ```

These practices will help maintain a stable Skwaq environment and minimize issues during operation.
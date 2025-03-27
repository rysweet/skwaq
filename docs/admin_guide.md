# Skwaq Administrator Guide

This guide covers the administration of Skwaq vulnerability assessment copilot, including installation, configuration, maintenance, and troubleshooting.

## System Requirements

### Hardware Requirements

**Minimum Requirements:**
- CPU: 4 cores
- RAM: 8 GB
- Storage: 20 GB SSD

**Recommended Requirements:**
- CPU: 8+ cores
- RAM: 16+ GB
- Storage: 100+ GB SSD
- Network: 1 Gbps

### Software Requirements

- **Operating System**: Linux (Ubuntu 20.04+, CentOS 8+), macOS 12+, Windows 10/11
- **Python**: 3.10 or newer
- **Neo4j**: 5.0 or newer
- **Optional**: Docker and Docker Compose

## Installation

### Package Installation

Install Skwaq using pip:

```bash
pip install skwaq
```

### Development Installation

For a development setup:

```bash
git clone https://github.com/rysweet/skwaq
cd skwaq
poetry install
```

### Docker Installation

Using Docker:

```bash
git clone https://github.com/rysweet/skwaq
cd skwaq
docker-compose up -d
```

## Configuration

### Configuration File

The main configuration file is located at:
- Linux/macOS: `~/.skwaq/config.json`
- Windows: `%USERPROFILE%\.skwaq\config.json`

### Neo4j Configuration

Configure the Neo4j connection:

```json
{
  "neo4j": {
    "uri": "bolt://localhost:7687",
    "user": "neo4j",
    "password": "your-secure-password",
    "database": "neo4j"
  }
}
```

### OpenAI/Azure Configuration

Configure the AI service:

```json
{
  "openai": {
    "api_type": "azure",
    "api_version": "2023-05-15",
    "api_key": "your-api-key",
    "api_base": "https://your-resource.openai.azure.com/",
    "chat_model": "gpt4o",
    "embedding_model": "text-embedding-ada-002"
  }
}
```

### Telemetry Configuration

Configure telemetry settings:

```json
{
  "telemetry": {
    "enabled": true,
    "level": "basic",
    "endpoint": "https://your-telemetry-endpoint"
  }
}
```

### Environment Variables

Skwaq also supports configuration via environment variables:

```bash
export SKWAQ_NEO4J_URI="bolt://localhost:7687"
export SKWAQ_NEO4J_USER="neo4j"
export SKWAQ_NEO4J_PASSWORD="your-secure-password"
export SKWAQ_OPENAI_API_KEY="your-api-key"
export SKWAQ_OPENAI_API_BASE="https://your-resource.openai.azure.com/"
```

## System Management

### Initialization

Initialize the Skwaq environment:

```bash
skwaq init
```

This command:
1. Verifies the Neo4j connection
2. Checks the OpenAI API connection
3. Creates initial database schema
4. Loads default knowledge sources

### Service Management

#### Systemd Service (Linux)

Create a systemd service for Skwaq:

```ini
# /etc/systemd/system/skwaq.service
[Unit]
Description=Skwaq Vulnerability Assessment Copilot
After=network.target neo4j.service

[Service]
User=skwaq
WorkingDirectory=/opt/skwaq
ExecStart=/usr/local/bin/skwaq serve
Restart=on-failure
Environment=SKWAQ_CONFIG_FILE=/etc/skwaq/config.json

[Install]
WantedBy=multi-user.target
```

Enable and start the service:

```bash
sudo systemctl enable skwaq
sudo systemctl start skwaq
```

#### Docker Compose Service

For Docker Compose deployments:

```yaml
version: '3.8'

services:
  skwaq:
    image: skwaq:latest
    ports:
      - "8000:8000"
    environment:
      - SKWAQ_NEO4J_URI=bolt://neo4j:7687
      - SKWAQ_NEO4J_USER=neo4j
      - SKWAQ_NEO4J_PASSWORD=your-secure-password
    volumes:
      - ./config:/app/config
    depends_on:
      - neo4j
    restart: unless-stopped
    
  neo4j:
    image: neo4j:5.15.0
    environment:
      - NEO4J_AUTH=neo4j/your-secure-password
    ports:
      - "7474:7474"
      - "7687:7687"
    volumes:
      - neo4j_data:/data
      - neo4j_logs:/logs
    restart: unless-stopped

volumes:
  neo4j_data:
  neo4j_logs:
```

### User Management

Create a dedicated system user for running Skwaq:

```bash
# Create a system user
sudo useradd --system --create-home --shell /bin/bash skwaq

# Set appropriate permissions
sudo mkdir -p /opt/skwaq
sudo chown -R skwaq:skwaq /opt/skwaq
```

## Security Configuration

### Authentication

Skwaq supports multiple authentication methods:

#### API Key Authentication

```json
{
  "security": {
    "auth_type": "apikey",
    "api_keys": [
      {
        "key": "your-api-key",
        "name": "admin-key",
        "permissions": ["read", "write", "admin"]
      }
    ]
  }
}
```

#### OAuth2 Authentication

```json
{
  "security": {
    "auth_type": "oauth2",
    "oauth2": {
      "provider": "azure_ad",
      "tenant_id": "your-tenant-id",
      "client_id": "your-client-id",
      "client_secret": "your-client-secret",
      "allowed_groups": ["security-team"]
    }
  }
}
```

### Data Encryption

Configure data encryption:

```json
{
  "security": {
    "encryption": {
      "data_at_rest": true,
      "key_file": "/path/to/encryption/key",
      "algorithm": "AES-256-GCM"
    }
  }
}
```

### Network Security

Configure network security settings:

```json
{
  "security": {
    "network": {
      "allowed_hosts": ["127.0.0.1", "10.0.0.0/8"],
      "ssl": true,
      "ssl_cert": "/path/to/cert.pem",
      "ssl_key": "/path/to/key.pem"
    }
  }
}
```

## Monitoring and Logging

### Log Configuration

Configure logging in `~/.skwaq/config.json`:

```json
{
  "logging": {
    "level": "INFO",
    "file": "/var/log/skwaq/skwaq.log",
    "max_size_mb": 100,
    "backup_count": 10,
    "format": "{time} [{level}] {message}"
  }
}
```

### Health Checks

Monitor Skwaq health:

```bash
# Basic health check
curl http://localhost:8000/health

# Detailed health status
skwaq status
```

### Metrics Collection

Enable Prometheus metrics:

```json
{
  "monitoring": {
    "metrics": {
      "enabled": true,
      "endpoint": "/metrics",
      "push_gateway": "http://prometheus-pushgateway:9091"
    }
  }
}
```

### Alert Configuration

Configure alerts for important events:

```json
{
  "monitoring": {
    "alerts": {
      "enabled": true,
      "email": {
        "smtp_server": "smtp.example.com",
        "from": "alerts@example.com",
        "to": ["admin@example.com"],
        "username": "alerts@example.com",
        "password": "your-password"
      },
      "slack": {
        "webhook_url": "https://hooks.slack.com/services/xxx/yyy/zzz",
        "channel": "#skwaq-alerts"
      }
    }
  }
}
```

## Performance Tuning

### Neo4j Performance

Optimize Neo4j for Skwaq:

```conf
# neo4j.conf

# Memory settings
dbms.memory.heap.initial_size=4G
dbms.memory.heap.max_size=8G
dbms.memory.pagecache.size=4G

# Query performance
dbms.jvm.additional=-XX:+UseG1GC
dbms.jvm.additional=-XX:G1HeapRegionSize=4m

# Index settings
db.index.fulltext.eventually_consistent=true
```

### Application Performance

Optimize Skwaq application:

```json
{
  "performance": {
    "cache": {
      "enabled": true,
      "max_size_mb": 512,
      "ttl_seconds": 3600
    },
    "concurrency": {
      "max_workers": 8,
      "timeout_seconds": 300
    },
    "openai": {
      "batch_size": 5,
      "retry_limit": 3,
      "retry_delay_seconds": 2
    }
  }
}
```

## Maintenance

### Database Maintenance

Perform regular Neo4j maintenance:

```bash
# Backup Neo4j database
neo4j-admin backup --backup-dir=/path/to/backups --database=neo4j

# Check database consistency
neo4j-admin database check --database=neo4j

# Optimize database (consider scheduling during off-hours)
neo4j-admin db optimize --database=neo4j
```

### Version Updates

Update Skwaq to the latest version:

```bash
# Using pip
pip install --upgrade skwaq

# Using Docker
docker pull skwaq:latest
docker-compose down
docker-compose up -d
```

### Configuration Updates

When updating configuration:

1. Backup the current configuration:
   ```bash
   cp ~/.skwaq/config.json ~/.skwaq/config.json.bak
   ```

2. Update the configuration file

3. Validate the updated configuration:
   ```bash
   skwaq config --validate
   ```

4. Restart the service:
   ```bash
   systemctl restart skwaq
   # or
   docker-compose restart skwaq
   ```

## Troubleshooting

### Common Issues

#### Neo4j Connection Issues

Problem:
```
Error: Neo4j connection failed: Connection refused
```

Solutions:
- Check if Neo4j is running: `systemctl status neo4j` or `docker ps | grep neo4j`
- Verify connection information in configuration
- Check network connectivity: `telnet localhost 7687`
- Verify firewall rules: `sudo ufw status`

#### OpenAI API Issues

Problem:
```
Error: OpenAI API connection failed: Invalid API key
```

Solutions:
- Verify your API key is correct
- Check API endpoint URL
- Ensure your subscription has available quota
- Verify network connectivity to the API endpoint

#### Performance Issues

Problem:
```
Slow response times or timeouts
```

Solutions:
- Check system resource usage: `htop`
- Verify Neo4j has adequate memory: `grep dbms.memory /etc/neo4j/neo4j.conf`
- Check for slow queries: `CALL db.slowQueries()` in Neo4j browser
- Increase cache size and worker count in configuration
- Check disk I/O performance: `iostat -x 5`

### Diagnostic Tools

#### Log Analysis

Check logs for errors:

```bash
# View recent errors
grep -i error /var/log/skwaq/skwaq.log | tail -n 50

# Follow logs in real-time
tail -f /var/log/skwaq/skwaq.log | grep -i error
```

#### System Diagnostics

Run the built-in diagnostics:

```bash
skwaq diagnose
```

This tool:
1. Checks system resources
2. Verifies Neo4j connectivity
3. Tests OpenAI API access
4. Validates configuration
5. Checks for common issues

#### Database Diagnostics

Check Neo4j status:

```bash
# Check running queries
CALL dbms.listQueries()

# Check database size
CALL dbms.database.size()

# Check for long-running transactions
CALL dbms.listTransactions()
```

## Backup and Recovery

See [Backup and Recovery Guide](./deployment/backup_recovery.md) for comprehensive backup and recovery procedures.

### Quick Backup

Quick backup command:

```bash
skwaq backup --output=/path/to/backup/skwaq-$(date +%Y%m%d).tar.gz
```

### Quick Restore

Restore from backup:

```bash
skwaq restore --input=/path/to/backup/skwaq-20250101.tar.gz
```

## Advanced Administration

### Clustering

For high availability deployments, see [High Availability Guide](./deployment/high_availability.md).

### Customization

Add custom extensions:

```bash
# Install a custom extension
pip install skwaq-extension-example

# Configure the extension
cat >> ~/.skwaq/config.json << EOF
{
  "extensions": {
    "example": {
      "enabled": true,
      "config": {
        "option1": "value1"
      }
    }
  }
}
EOF

# Restart the service
systemctl restart skwaq
```

### Integration with External Systems

Configure external system integration:

```json
{
  "integrations": {
    "jira": {
      "enabled": true,
      "url": "https://jira.example.com",
      "username": "skwaq-integration",
      "api_token": "your-api-token",
      "project": "SEC",
      "issue_type": "Vulnerability"
    },
    "slack": {
      "enabled": true,
      "webhook_url": "https://hooks.slack.com/services/xxx/yyy/zzz",
      "channel": "#security-alerts"
    }
  }
}
```

## Reference

### Command Line Reference

```bash
# View all commands
skwaq --help

# View command-specific help
skwaq [command] --help
```

### Configuration Reference

See [Configuration Reference](./configuration_reference.md) for a complete list of configuration options.

### API Reference

See [API Reference](./api_reference.md) for the REST API documentation.
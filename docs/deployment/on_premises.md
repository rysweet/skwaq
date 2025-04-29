# On-Premises Deployment Guide

This guide covers deploying Skwaq in an on-premises environment.

## System Requirements

### Minimum Hardware Requirements

- **CPU**: 4 cores
- **RAM**: 8 GB
- **Storage**: 20 GB SSD
- **Network**: 1 Gbps Ethernet

### Recommended Hardware

- **CPU**: 8+ cores
- **RAM**: 16+ GB
- **Storage**: 100+ GB SSD
- **Network**: 10 Gbps Ethernet

### Software Requirements

- **Operating System**: Ubuntu 20.04 LTS or newer / CentOS 8+ / RHEL 8+
- **Python**: 3.10 or newer
- **Docker**: 20.10 or newer (if using containerized deployment)
- **Neo4j**: 5.0 or newer
- **NGINX**: 1.18 or newer (for reverse proxy)

## Deployment Options

### 1. Bare Metal Deployment

Installing directly on the host system:

```bash
# Clone the repository
git clone https://github.com/rysweet/skwaq
cd skwaq

# Install dependencies
./scripts/setup/setup_dev_environment.sh

# Configure the application
nano ~/.skwaq/config.json

# Start the application
skwaq check-config
```

### 2. Containerized Deployment

Using Docker and Docker Compose:

```bash
# Clone the repository
git clone https://github.com/rysweet/skwaq
cd skwaq

# Build and start containers
docker-compose up -d
```

## Configuration

The main configuration file is located at `~/.skwaq/config.json` for bare metal deployments or mounted at `/app/config/config.json` for containerized deployments.

### Key Configuration Parameters

```json
{
  "neo4j": {
    "uri": "bolt://neo4j:7687",
    "user": "neo4j",
    "password": "your-secure-password",
    "database": "neo4j"
  },
  "openai": {
    "api_type": "azure",
    "api_version": "2023-05-15",
    "api_key": "your-api-key",
    "api_base": "your-api-endpoint",
    "chat_model": "gpt4o",
    "embedding_model": "text-embedding-ada-002"
  }
}
```

## Network Configuration

### Ports

The following ports need to be accessible:

- **8000**: Skwaq API
- **7474**: Neo4j HTTP
- **7687**: Neo4j Bolt

### Firewall Configuration

For Ubuntu/Debian systems:

```bash
# Allow necessary ports
sudo ufw allow 8000/tcp
sudo ufw allow 7474/tcp
sudo ufw allow 7687/tcp

# Enable firewall
sudo ufw enable
```

For CentOS/RHEL systems:

```bash
# Allow necessary ports
sudo firewall-cmd --permanent --add-port=8000/tcp
sudo firewall-cmd --permanent --add-port=7474/tcp
sudo firewall-cmd --permanent --add-port=7687/tcp

# Reload firewall
sudo firewall-cmd --reload
```

## NGINX Configuration

For production deployments, it's recommended to use NGINX as a reverse proxy:

```nginx
server {
    listen 80;
    server_name skwaq.yourdomain.com;

    location / {
        proxy_pass http://localhost:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

## Systemd Service Configuration

For running Skwaq as a service:

```ini
[Unit]
Description=Skwaq Vulnerability Assessment Copilot
After=network.target

[Service]
User=skwaq
WorkingDirectory=/opt/skwaq
ExecStart=/opt/skwaq/.venv/bin/python -m skwaq
Restart=on-failure
Environment=PYTHONUNBUFFERED=1

[Install]
WantedBy=multi-user.target
```

Save this file as `/etc/systemd/system/skwaq.service` and enable it:

```bash
sudo systemctl enable skwaq
sudo systemctl start skwaq
```

## Security Considerations

1. **User Permissions**: Create a dedicated user for running Skwaq
   ```bash
   sudo useradd -m -s /bin/bash skwaq
   ```

2. **File Permissions**: Restrict access to configuration files
   ```bash
   sudo chown skwaq:skwaq -R /opt/skwaq
   sudo chmod 750 /opt/skwaq
   sudo chmod 600 /opt/skwaq/config/*.json
   ```

3. **Network Security**: Use TLS/SSL for all connections
   ```bash
   # Generate SSL certificates or use Let's Encrypt
   sudo certbot --nginx -d skwaq.yourdomain.com
   ```

4. **Database Security**: Configure Neo4j with authentication and encrypted connections

## Monitoring

### Log Files

Logs are stored in the following locations:

- **Application Logs**: `/var/log/skwaq/app.log`
- **Neo4j Logs**: `/var/log/neo4j/`

### Health Checks

Configure regular health checks:

```bash
# Create a simple health check script
cat > /opt/skwaq/health_check.sh << 'EOF'
#!/bin/bash
response=$(curl -s http://localhost:8000/health)
if [[ "$response" == *"healthy"* ]]; then
  echo "Skwaq is healthy"
  exit 0
else
  echo "Skwaq health check failed"
  exit 1
fi
EOF
chmod +x /opt/skwaq/health_check.sh

# Add to crontab
(crontab -l 2>/dev/null; echo "*/5 * * * * /opt/skwaq/health_check.sh") | crontab -
```

## Troubleshooting

Common issues and their solutions:

1. **Neo4j Connection Failed**
   - Check if Neo4j is running: `sudo systemctl status neo4j`
   - Verify credentials in config file
   - Check network connectivity: `telnet localhost 7687`

2. **API Not Responding**
   - Check service status: `sudo systemctl status skwaq`
   - Check logs: `sudo tail -f /var/log/skwaq/app.log`
   - Verify port is open: `sudo netstat -tuln | grep 8000`

3. **Performance Issues**
   - Check system resources: `top`, `htop`, or `glances`
   - Review Neo4j query performance: `CALL db.slowQueries()`
   - Check disk I/O: `iostat -x 5`
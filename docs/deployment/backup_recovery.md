# Backup and Recovery Guide

This guide covers backup and recovery procedures for Skwaq deployments, ensuring data protection and business continuity.

## Backup Strategy

A comprehensive backup strategy for Skwaq should cover:

1. **Neo4j Database**: The primary data store containing the knowledge graph
2. **Configuration Files**: All configuration needed to restore services
3. **User Investigation Data**: Active investigations and research
4. **Logs and Telemetry**: For post-incident analysis if needed

### Recommended Backup Schedule

| Component | Frequency | Retention | Type |
|-----------|-----------|-----------|------|
| Neo4j Database | Daily | 30 days | Full + Transaction logs |
| Neo4j Database | Weekly | 3 months | Full |
| Neo4j Database | Monthly | 1 year | Full |
| Configuration | After changes | 10 versions | Incremental |
| User Investigations | Daily | 90 days | Full |
| Logs | Daily | 90 days | Incremental |

## Backup Procedures

### 1. Neo4j Database Backup

#### Online Backup (Enterprise Edition)

The Neo4j Enterprise Edition supports online backups while the database is running:

```bash
# Full backup
neo4j-admin backup \
  --backup-dir=/backups \
  --name=skwaq-backup-$(date +%Y%m%d) \
  --database=neo4j

# Check backup status
ls -la /backups/skwaq-backup-$(date +%Y%m%d)
```

#### Offline Backup (Community Edition)

For Neo4j Community Edition, you'll need to stop the database before backing up:

```bash
# Stop Neo4j
systemctl stop neo4j

# Copy data files
tar -czf /backups/skwaq-backup-$(date +%Y%m%d).tar.gz /var/lib/neo4j/data/

# Restart Neo4j
systemctl start neo4j
```

#### Containerized Neo4j Backup

For Docker/Kubernetes deployments:

```bash
# For Docker
docker exec -it skwaq-neo4j neo4j-admin backup \
  --backup-dir=/backups \
  --name=skwaq-backup-$(date +%Y%m%d)

# For Kubernetes
kubectl exec -it neo4j-0 -n skwaq -- neo4j-admin backup \
  --backup-dir=/backups \
  --name=skwaq-backup-$(date +%Y%m%d)
```

### 2. Configuration Backup

```bash
# Backup Configuration Files
tar -czf /backups/skwaq-config-$(date +%Y%m%d).tar.gz \
  ~/.skwaq/config.json \
  /etc/skwaq/*.conf

# For Kubernetes
kubectl get configmap -n skwaq -o yaml > /backups/k8s-config-$(date +%Y%m%d).yaml
kubectl get secret -n skwaq -o yaml > /backups/k8s-secrets-$(date +%Y%m%d).yaml
```

### 3. User Investigation Backup

User investigations are stored in Neo4j but can be separately exported:

```bash
# Export all investigations as JSON
skwaq investigations export-all --format=json --output=/backups/investigations-$(date +%Y%m%d).json

# For specific investigations
skwaq investigations export --id=<investigation-id> --format=json --output=/backups/investigation-<id>-$(date +%Y%m%d).json
```

### 4. Logging and Telemetry Backup

Application logs should be collected and backed up:

```bash
# Compress log files
find /var/log/skwaq -type f -name "*.log" -mtime -1 | xargs tar -czf /backups/logs-$(date +%Y%m%d).tar.gz
```

## Automating Backups

### Systemd Timer Example

For regular backup scheduling on Linux systems:

1. Create a backup script at `/usr/local/bin/skwaq-backup.sh`:

```bash
#!/bin/bash
set -e

BACKUP_DIR="/backups/skwaq"
DATE=$(date +%Y%m%d)
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

# Ensure backup directory exists
mkdir -p $BACKUP_DIR

# Database backup
echo "Backing up Neo4j database..."
neo4j-admin backup --backup-dir=$BACKUP_DIR/db --name=skwaq-$DATE

# Configuration backup
echo "Backing up configuration..."
tar -czf $BACKUP_DIR/config/skwaq-config-$TIMESTAMP.tar.gz ~/.skwaq/config.json /etc/skwaq/

# Investigation export
echo "Backing up investigations..."
skwaq investigations export-all --format=json --output=$BACKUP_DIR/investigations/all-$TIMESTAMP.json

# Log files
echo "Backing up logs..."
find /var/log/skwaq -type f -name "*.log" -mtime -1 | xargs tar -czf $BACKUP_DIR/logs/logs-$TIMESTAMP.tar.gz

# Cleanup old backups (keep the last 30 days)
find $BACKUP_DIR -type d -name "skwaq-*" -mtime +30 -exec rm -rf {} \;
find $BACKUP_DIR/config -type f -name "skwaq-config-*.tar.gz" -mtime +30 -exec rm {} \;
find $BACKUP_DIR/investigations -type f -name "all-*.json" -mtime +30 -exec rm {} \;
find $BACKUP_DIR/logs -type f -name "logs-*.tar.gz" -mtime +30 -exec rm {} \;

echo "Backup completed successfully!"
```

2. Create a systemd service at `/etc/systemd/system/skwaq-backup.service`:

```ini
[Unit]
Description=Skwaq backup service
After=network.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/skwaq-backup.sh
User=skwaq
Group=skwaq
```

3. Create a systemd timer at `/etc/systemd/system/skwaq-backup.timer`:

```ini
[Unit]
Description=Run Skwaq backup daily

[Timer]
OnCalendar=*-*-* 02:00:00
Persistent=true

[Install]
WantedBy=timers.target
```

4. Enable and start the timer:

```bash
sudo systemctl enable skwaq-backup.timer
sudo systemctl start skwaq-backup.timer
```

### Kubernetes CronJob Example

For Kubernetes deployments:

```yaml
apiVersion: batch/v1
kind: CronJob
metadata:
  name: skwaq-backup
  namespace: skwaq
spec:
  schedule: "0 2 * * *"  # Run at 2 AM daily
  concurrencyPolicy: Forbid
  jobTemplate:
    spec:
      template:
        spec:
          containers:
          - name: backup
            image: skwaq:latest
            command:
            - /bin/bash
            - -c
            - |
              # Neo4j backup
              neo4j-admin backup --backup-dir=/backups/db --name=skwaq-$(date +%Y%m%d)
              
              # Config backup
              kubectl get configmap -n skwaq -o yaml > /backups/config/k8s-config-$(date +%Y%m%d).yaml
              kubectl get secret -n skwaq -o yaml > /backups/config/k8s-secrets-$(date +%Y%m%d).yaml
              
              # Export investigations
              skwaq investigations export-all --format=json \
                --output=/backups/investigations/all-$(date +%Y%m%d).json
              
              # Cleanup old backups
              find /backups -mtime +30 -delete
            volumeMounts:
            - name: backup-volume
              mountPath: /backups
          restartPolicy: OnFailure
          volumes:
          - name: backup-volume
            persistentVolumeClaim:
              claimName: skwaq-backup-pvc
```

## Off-site Backup Storage

For disaster recovery, backups should be stored off-site:

```bash
# Sync backups to a remote location
rsync -azP /backups/skwaq/ backup-server:/backups/skwaq/

# Alternatively, use cloud storage
aws s3 sync /backups/skwaq/ s3://skwaq-backups/
# or
gsutil -m rsync -r /backups/skwaq/ gs://skwaq-backups/
# or
az storage blob sync -c backups --account-name skwaqstorage -s /backups/skwaq/
```

## Backup Monitoring and Validation

### Backup Validation

Regularly validate backups to ensure they can be successfully restored:

```bash
# Create a test directory
mkdir -p /tmp/backup-test

# Restore Neo4j backup to a test location
neo4j-admin restore \
  --from=/backups/skwaq-backup-$(date +%Y%m%d) \
  --database=neo4j \
  --force \
  --verbose \
  --expand-commands

# Verify backup integrity
neo4j-admin database check --database=neo4j

# Clean up test files
rm -rf /tmp/backup-test
```

### Monitoring Backup Success

Set up monitoring to alert on backup failures:

```bash
# Add this to your backup script
if [ $? -ne 0 ]; then
  echo "Backup failed!" | mail -s "Skwaq Backup Failure" admin@example.com
  exit 1
else
  echo "Backup succeeded at $(date)" >> /var/log/skwaq/backup_success.log
fi
```

## Recovery Procedures

### 1. Database Recovery

#### Full Restore

To completely restore the Neo4j database:

```bash
# Stop Neo4j service
systemctl stop neo4j

# Restore from backup
neo4j-admin restore \
  --from=/backups/skwaq-backup-20250101 \
  --database=neo4j \
  --force

# Start Neo4j service
systemctl start neo4j
```

#### Containerized Database Restore

For Docker/Kubernetes environments:

```bash
# For Docker
docker stop skwaq-neo4j
docker run --rm -v neo4j_data:/data -v /backups:/backups neo4j:5.15.0 \
  neo4j-admin restore --from=/backups/skwaq-backup-20250101 --database=neo4j --force
docker start skwaq-neo4j

# For Kubernetes
kubectl scale statefulset neo4j --replicas=0 -n skwaq
kubectl run neo4j-restore --rm -it \
  --image=neo4j:5.15.0 \
  --volumes=data:/data,backup:/backups \
  --command -- neo4j-admin restore \
  --from=/backups/skwaq-backup-20250101 \
  --database=neo4j \
  --force
kubectl scale statefulset neo4j --replicas=1 -n skwaq
```

### 2. Configuration Recovery

Restore configuration files:

```bash
# Extract configuration files
tar -xzf /backups/skwaq-config-20250101.tar.gz -C /tmp/
cp -r /tmp/home/user/.skwaq/config.json ~/.skwaq/
cp -r /tmp/etc/skwaq/* /etc/skwaq/
```

For Kubernetes:

```bash
# Apply saved configurations
kubectl apply -f /backups/k8s-config-20250101.yaml
kubectl apply -f /backups/k8s-secrets-20250101.yaml
```

### 3. User Investigation Recovery

Restore user investigations:

```bash
# Import investigations from backup
skwaq investigations import --file=/backups/investigations/all-20250101.json

# Verify import
skwaq investigations list
```

## Disaster Recovery Plan

### 1. Identify the Disaster

Assess the type and extent of the disaster:
- Database corruption
- Hardware failure
- Data center outage
- Accidental data deletion
- Security breach

### 2. Activate Recovery Team

Assemble the team responsible for recovery operations:
- Database administrator
- System administrator
- Application owner
- Security team (if applicable)

### 3. Recovery Execution

Follow these steps for full system recovery:

1. **Infrastructure Restoration**:
   - Provision new servers/containers if needed
   - Restore network configurations
   - Ensure required services are available

2. **Database Recovery**:
   - Follow the database recovery procedures above
   - Verify the restore completed successfully
   - Confirm database connectivity

3. **Application Recovery**:
   - Redeploy application components
   - Restore configuration files
   - Verify application starts correctly

4. **Data Verification**:
   - Run integrity checks on restored data
   - Verify investigations are accessible
   - Check knowledge graph connectivity

### 4. Testing and Validation

After recovery, perform these validation tests:

```bash
# Verify Neo4j connection
skwaq init

# Check database content
skwaq query "MATCH (n) RETURN count(n) as nodeCount"

# Verify API functionality
curl http://localhost:8000/health

# Test a basic workflow
skwaq qa ask "What is a SQL injection vulnerability?"
```

### 5. Documentation and Review

After each recovery operation:

1. Document what happened
2. Record the recovery steps taken
3. Note any issues encountered
4. Update recovery procedures if needed
5. Review backup strategy to prevent similar incidents

## Recovery Time Objectives (RTO)

| Scenario | Target RTO | Recovery Steps |
|----------|------------|----------------|
| Database corruption | 1 hour | Restore from latest backup |
| Configuration error | 30 minutes | Restore configuration files |
| Complete system failure | 4 hours | Full infrastructure and data restore |
| Single node failure | 15 minutes | Auto-healing via orchestration |

## Recovery Point Objectives (RPO)

| Data Type | Target RPO | Backup Frequency |
|-----------|------------|------------------|
| Neo4j Database | 24 hours | Daily full backup + continuous transaction logs |
| Configuration | 1 hour | After every change |
| User Investigations | 24 hours | Daily export |

## Practical Recovery Examples

### Scenario 1: Corrupted Neo4j Database

```bash
# 1. Stop Neo4j service
systemctl stop neo4j

# 2. Check the latest valid backup
ls -lt /backups/ | grep skwaq-backup | head -1

# 3. Restore from that backup
neo4j-admin restore \
  --from=/backups/skwaq-backup-20250101 \
  --database=neo4j \
  --force

# 4. Start Neo4j service
systemctl start neo4j

# 5. Verify database functionality
skwaq init
skwaq repo list
```

### Scenario 2: Complete System Recovery

```bash
# 1. Provision new server/VM
# (platform-specific steps)

# 2. Install base OS and dependencies
apt-get update && apt-get install -y docker.io docker-compose

# 3. Restore configuration
mkdir -p ~/.skwaq
tar -xzf /backups/skwaq-config-20250101.tar.gz -C /tmp/
cp -r /tmp/home/user/.skwaq/config.json ~/.skwaq/

# 4. Start database
docker-compose up -d neo4j

# 5. Restore database
docker exec -it skwaq-neo4j neo4j-admin restore \
  --from=/backups/skwaq-backup-20250101 \
  --database=neo4j \
  --force

# 6. Start application
docker-compose up -d app

# 7. Import investigations
docker exec -it skwaq-app skwaq investigations import \
  --file=/backups/investigations/all-20250101.json

# 8. Verify functionality
curl http://localhost:8000/health
```
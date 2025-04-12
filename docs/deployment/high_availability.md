# High Availability Configuration Guide

This guide covers configuring Skwaq for high availability (HA) deployments to ensure reliability, fault tolerance, and optimal performance under load.

## Architecture Overview

A high availability Skwaq deployment should include:

1. **Redundant API Instances**: Multiple instances of the Skwaq API service
2. **Neo4j Clustering**: Distributed Neo4j database with fault tolerance
3. **Load Balancing**: Distributing traffic across API instances
4. **Health Monitoring**: Automated health checks and recovery
5. **Backup & Disaster Recovery**: Regular backups and recovery procedures

```
                          ┌─────────────────┐
                          │                 │
                          │  Load Balancer  │
                          │                 │
                          └────────┬────────┘
                                   │
                 ┌─────────────────┼─────────────────┐
                 │                 │                 │
        ┌────────▼───────┐ ┌───────▼────────┐ ┌──────▼─────────┐
        │                │ │                │ │                │
        │  Skwaq API #1  │ │  Skwaq API #2  │ │  Skwaq API #3  │
        │                │ │                │ │                │
        └────────┬───────┘ └───────┬────────┘ └──────┬─────────┘
                 │                 │                 │
                 └─────────────────┼─────────────────┘
                                   │
                          ┌────────▼────────┐
                          │                 │
                          │   Neo4j Cluster │
                          │                 │
                          └─────────────────┘
```

## Neo4j High Availability Setup

### Neo4j Causal Clustering

Neo4j offers a causal clustering architecture that provides:
- Read scalability
- Write performance
- Fault tolerance

#### Core Servers Configuration

Core servers participate in the Raft consensus protocol:

```yaml
# neo4j.conf for Core Server 1
dbms.mode=CORE
causal_clustering.minimum_core_cluster_size_at_formation=3
causal_clustering.minimum_core_cluster_size_at_runtime=2
causal_clustering.initial_discovery_members=core1:5000,core2:5000,core3:5000
causal_clustering.discovery_advertised_address=core1:5000
causal_clustering.transaction_advertised_address=core1:6000
causal_clustering.raft_advertised_address=core1:7000
```

Configure similar settings for core2 and core3, changing the advertised addresses.

#### Read Replicas Configuration

Read replicas provide horizontal read scaling:

```yaml
# neo4j.conf for Read Replica 1
dbms.mode=READ_REPLICA
causal_clustering.initial_discovery_members=core1:5000,core2:5000,core3:5000
causal_clustering.discovery_advertised_address=replica1:5000
causal_clustering.transaction_advertised_address=replica1:6000
```

### Deployment Example (Kubernetes)

```yaml
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: neo4j-core
spec:
  serviceName: neo4j-core
  replicas: 3
  selector:
    matchLabels:
      app: neo4j-core
  template:
    metadata:
      labels:
        app: neo4j-core
    spec:
      containers:
      - name: neo4j
        image: neo4j:5.15.0-enterprise
        env:
        - name: NEO4J_ACCEPT_LICENSE_AGREEMENT
          value: "yes"
        - name: NEO4J_dbms_mode
          value: "CORE"
        - name: NEO4J_causal__clustering_minimum__core__cluster__size__at__formation
          value: "3"
        # Additional env vars for clustering configuration
        volumeMounts:
        - name: data
          mountPath: /data
  volumeClaimTemplates:
  - metadata:
      name: data
    spec:
      accessModes: [ "ReadWriteOnce" ]
      resources:
        requests:
          storage: 20Gi
```

## API High Availability

### Horizontal Scaling

Deploy multiple instances of the Skwaq API service:

#### Kubernetes Deployment

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: skwaq-api
spec:
  replicas: 3
  selector:
    matchLabels:
      app: skwaq-api
  template:
    metadata:
      labels:
        app: skwaq-api
    spec:
      containers:
      - name: api
        image: your-registry/skwaq:latest
        readinessProbe:
          httpGet:
            path: /health
            port: 8000
          initialDelaySeconds: 10
          periodSeconds: 5
        livenessProbe:
          httpGet:
            path: /health
            port: 8000
          initialDelaySeconds: 30
          periodSeconds: 15
        resources:
          requests:
            cpu: 500m
            memory: 1Gi
          limits:
            cpu: 2
            memory: 4Gi
```

### Load Balancing

#### Kubernetes Service

```yaml
apiVersion: v1
kind: Service
metadata:
  name: skwaq-api
spec:
  selector:
    app: skwaq-api
  ports:
  - port: 80
    targetPort: 8000
  sessionAffinity: ClientIP
  sessionAffinityConfig:
    clientIP:
      timeoutSeconds: 600
```

#### NGINX Load Balancer (On-Premises)

```nginx
upstream skwaq_backend {
    least_conn;
    server skwaq1:8000 max_fails=3 fail_timeout=30s;
    server skwaq2:8000 max_fails=3 fail_timeout=30s;
    server skwaq3:8000 max_fails=3 fail_timeout=30s;
}

server {
    listen 80;
    server_name skwaq.yourdomain.com;

    location / {
        proxy_pass http://skwaq_backend;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        # Timeout settings
        proxy_connect_timeout 10s;
        proxy_send_timeout 30s;
        proxy_read_timeout 30s;
    }
}
```

## Session Management

For stateful user sessions, implement one of these strategies:

1. **Distributed Cache**:
   - Redis for session storage
   - Configuration example:

```yaml
# Skwaq API configuration
sessions:
  store: redis
  redis:
    host: redis-master.default.svc.cluster.local
    port: 6379
    db: 0
    password: your-redis-password
```

2. **Sticky Sessions**:
   - Keep user sessions on the same server
   - Already configured in the example load balancers above

## Health Monitoring and Auto-Recovery

### Health Checks

Implement comprehensive health checks:

```python
@app.route('/health')
def health_check():
    """Comprehensive health check."""
    status = {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "components": {
            "api": "healthy",
            "database": check_database_health(),
            "openai": check_openai_health()
        }
    }
    
    overall = all(v == "healthy" for v in status["components"].values())
    status["status"] = "healthy" if overall else "degraded"
    
    return jsonify(status), 200 if overall else 503
```

### Automatic Failover

#### Neo4j Failover

Neo4j Causal Clustering handles automatic failover:
- If a core instance fails, the cluster elects a new leader
- Transactions continue uninterrupted
- Read replicas automatically connect to the new leader

#### API Failover

Kubernetes or other orchestrators automatically restart failed containers:

```yaml
# Kubernetes example
spec:
  replicas: 3
  strategy:
    rollingUpdate:
      maxSurge: 1
      maxUnavailable: 0
    type: RollingUpdate
```

## Performance Optimization

### Connection Pooling

Configure connection pools for Neo4j:

```python
# Neo4j connection pooling
neo4j_driver = GraphDatabase.driver(
    uri, 
    auth=(user, password),
    max_connection_pool_size=50,
    max_transaction_retry_time=30
)
```

### Caching

Implement caching for frequently accessed data:

```yaml
# Redis cache configuration
cache:
  enabled: true
  provider: redis
  redis:
    host: redis-master
    port: 6379
    ttl: 3600  # seconds
```

### Resource Allocation

Optimize resource allocation based on workload:

```yaml
# Kubernetes example
resources:
  requests:
    cpu: 1
    memory: 2Gi
  limits:
    cpu: 4
    memory: 8Gi
```

## Advanced Configuration

### Geo-distributed Deployment

For global deployments, consider:

1. **Multiple Regions**:
   - Deploy Skwaq API instances in multiple regions
   - Use global load balancers (like AWS Global Accelerator)

2. **Neo4j Multi-datacenter**:
   - Configure Neo4j with multi-datacenter replication
   - Example configuration:

```
# Neo4j DC1 configuration
causal_clustering.middleware.routing.policies=multi_dc
causal_clustering.middleware.routing.multi_dc.router=route_by_label
causal_clustering.middleware.routing.multi_dc.label=dc1

# Neo4j DC2 configuration
causal_clustering.middleware.routing.policies=multi_dc
causal_clustering.middleware.routing.multi_dc.router=route_by_label
causal_clustering.middleware.routing.multi_dc.label=dc2
```

### Auto-scaling

Configure auto-scaling for dynamic workloads:

```yaml
# Kubernetes HorizontalPodAutoscaler
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: skwaq-api-hpa
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: skwaq-api
  minReplicas: 3
  maxReplicas: 10
  metrics:
  - type: Resource
    resource:
      name: cpu
      target:
        type: Utilization
        averageUtilization: 70
  - type: Resource
    resource:
      name: memory
      target:
        type: Utilization
        averageUtilization: 80
```

## Backup and Recovery

### Database Backups

Configure regular Neo4j backups:

```bash
# Backup script example
neo4j-admin backup --backup-dir=/backup --name=skwaq-backup-$(date +%Y%m%d)
```

Kubernetes CronJob:

```yaml
apiVersion: batch/v1
kind: CronJob
metadata:
  name: neo4j-backup
spec:
  schedule: "0 2 * * *"  # Daily at 2 AM
  jobTemplate:
    spec:
      template:
        spec:
          containers:
          - name: backup
            image: neo4j:5.15.0-enterprise
            command: ["/bin/sh", "-c"]
            args:
            - neo4j-admin backup --backup-dir=/backup --name=skwaq-backup-$(date +%Y%m%d)
            volumeMounts:
            - name: backup-volume
              mountPath: /backup
          restartPolicy: OnFailure
          volumes:
          - name: backup-volume
            persistentVolumeClaim:
              claimName: neo4j-backup-pvc
```

### Disaster Recovery Procedures

1. **Database Recovery**:
   ```bash
   neo4j-admin restore --from=/backup/skwaq-backup-20250101 --database=neo4j
   ```

2. **Complete System Recovery**:
   - Deploy infrastructure using IaC templates
   - Restore database from backup
   - Verify system functionality with health checks

## Monitoring and Alerts

Configure monitoring for high availability:

```yaml
# Prometheus monitoring example
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: skwaq-api-monitor
spec:
  selector:
    matchLabels:
      app: skwaq-api
  endpoints:
  - port: web
    path: /metrics
    interval: 15s
```

Alert configuration:

```yaml
apiVersion: monitoring.coreos.com/v1
kind: PrometheusRule
metadata:
  name: skwaq-alerts
spec:
  groups:
  - name: skwaq.rules
    rules:
    - alert: SkwaqApiHighErrorRate
      expr: sum(rate(http_requests_total{job="skwaq-api",code=~"5.."}[5m])) / sum(rate(http_requests_total{job="skwaq-api"}[5m])) > 0.05
      for: 5m
      labels:
        severity: critical
      annotations:
        summary: "High error rate in Skwaq API"
        description: "Error rate is {{ $value | humanizePercentage }} for the last 5 minutes"
```

## Configuration Management

Use a consistent approach to configuration across instances:

### ConfigMaps in Kubernetes

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: skwaq-config
data:
  config.json: |
    {
      "neo4j": {
        "uri": "bolt+routing://neo4j-core-headless:7687",
        "database": "neo4j"
      },
      "openai": {
        "api_type": "azure",
        "api_version": "2023-05-15",
        "chat_model": "gpt4o",
        "embedding_model": "text-embedding-ada-002"
      }
    }
```

### Environment-specific Configurations

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: skwaq-config-production
data:
  LOG_LEVEL: "INFO"
  CACHE_TTL: "3600"
  MAX_CONCURRENT_REQUESTS: "100"
```
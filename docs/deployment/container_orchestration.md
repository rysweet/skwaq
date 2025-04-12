# Container Orchestration Deployment Guide

This guide covers deploying Skwaq using container orchestration platforms like Kubernetes or Docker Swarm.

## Kubernetes Deployment

### Prerequisites

- Kubernetes cluster (v1.20+)
- `kubectl` command-line tool
- Helm (v3.0+)
- Container registry access

### Deployment Architecture

The Kubernetes deployment consists of the following components:

- **Skwaq API** - Deployment for the main application
- **Neo4j** - StatefulSet for the graph database
- **Services** - For network access to components
- **ConfigMaps/Secrets** - For configuration and sensitive data
- **Persistent Volumes** - For data persistence

```
┌──────────────────┐      ┌────────────────┐
│                  │      │                │
│  Ingress/Service │───►  │  Skwaq API     │
│                  │      │  (Deployment)  │
└──────────────────┘      └────────┬───────┘
                                   │
                                   ▼
                           ┌───────────────┐
                           │               │
                           │     Neo4j     │
                           │  (StatefulSet)│
                           └───────────────┘
                                   │
                                   ▼
                           ┌───────────────┐
                           │ Persistent    │
                           │ Volume        │
                           └───────────────┘
```

### Kubernetes Manifests

#### 1. Namespace

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: skwaq
```

#### 2. ConfigMap

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: skwaq-config
  namespace: skwaq
data:
  config.json: |
    {
      "neo4j": {
        "uri": "bolt://neo4j-0.neo4j.skwaq.svc.cluster.local:7687",
        "user": "neo4j",
        "database": "neo4j"
      },
      "openai": {
        "api_type": "azure",
        "api_version": "2023-05-15",
        "chat_model": "gpt4o",
        "embedding_model": "text-embedding-ada-002"
      },
      "telemetry": {
        "enabled": false
      }
    }
```

#### 3. Secrets

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: skwaq-secrets
  namespace: skwaq
type: Opaque
data:
  neo4j-password: <base64-encoded-password>
  openai-api-key: <base64-encoded-api-key>
  openai-endpoint: <base64-encoded-endpoint>
```

#### 4. Neo4j StatefulSet

```yaml
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: neo4j
  namespace: skwaq
spec:
  serviceName: neo4j
  replicas: 1
  selector:
    matchLabels:
      app: neo4j
  template:
    metadata:
      labels:
        app: neo4j
    spec:
      containers:
      - name: neo4j
        image: neo4j:5.15.0
        ports:
        - containerPort: 7474
          name: http
        - containerPort: 7687
          name: bolt
        env:
        - name: NEO4J_AUTH
          value: neo4j/$(NEO4J_PASSWORD)
        - name: NEO4J_PASSWORD
          valueFrom:
            secretKeyRef:
              name: skwaq-secrets
              key: neo4j-password
        - name: NEO4J_dbms_memory_pagecache_size
          value: 1G
        - name: NEO4J_dbms_memory_heap_initial__size
          value: 1G
        - name: NEO4J_dbms_memory_heap_max__size
          value: 2G
        volumeMounts:
        - name: neo4j-data
          mountPath: /data
  volumeClaimTemplates:
  - metadata:
      name: neo4j-data
    spec:
      accessModes: [ "ReadWriteOnce" ]
      resources:
        requests:
          storage: 10Gi
```

#### 5. Neo4j Service

```yaml
apiVersion: v1
kind: Service
metadata:
  name: neo4j
  namespace: skwaq
spec:
  selector:
    app: neo4j
  ports:
  - port: 7474
    name: http
  - port: 7687
    name: bolt
  clusterIP: None
```

#### 6. Skwaq Deployment

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: skwaq-api
  namespace: skwaq
spec:
  replicas: 2
  selector:
    matchLabels:
      app: skwaq-api
  template:
    metadata:
      labels:
        app: skwaq-api
    spec:
      containers:
      - name: skwaq
        image: <your-registry>/skwaq:latest
        ports:
        - containerPort: 8000
        env:
        - name: NEO4J_URI
          valueFrom:
            configMapKeyRef:
              name: skwaq-config
              key: neo4j.uri
        - name: NEO4J_USER
          valueFrom:
            configMapKeyRef:
              name: skwaq-config
              key: neo4j.user
        - name: NEO4J_PASSWORD
          valueFrom:
            secretKeyRef:
              name: skwaq-secrets
              key: neo4j-password
        - name: OPENAI_API_KEY
          valueFrom:
            secretKeyRef:
              name: skwaq-secrets
              key: openai-api-key
        - name: OPENAI_API_BASE
          valueFrom:
            secretKeyRef:
              name: skwaq-secrets
              key: openai-endpoint
        volumeMounts:
        - name: config-volume
          mountPath: /app/config
      volumes:
      - name: config-volume
        configMap:
          name: skwaq-config
```

#### 7. Skwaq Service

```yaml
apiVersion: v1
kind: Service
metadata:
  name: skwaq-api
  namespace: skwaq
spec:
  selector:
    app: skwaq-api
  ports:
  - port: 80
    targetPort: 8000
  type: ClusterIP
```

#### 8. Ingress

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: skwaq-ingress
  namespace: skwaq
  annotations:
    kubernetes.io/ingress.class: nginx
    # Add TLS annotations if needed
spec:
  rules:
  - host: skwaq.example.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: skwaq-api
            port:
              number: 80
```

### Deployment Commands

Apply the manifests in order:

```bash
# Create namespace
kubectl apply -f namespace.yaml

# Apply config and secrets
kubectl apply -f configmap.yaml
kubectl apply -f secrets.yaml

# Deploy Neo4j
kubectl apply -f neo4j-statefulset.yaml
kubectl apply -f neo4j-service.yaml

# Wait for Neo4j to be ready
kubectl wait --for=condition=Ready pod/neo4j-0 -n skwaq --timeout=300s

# Deploy Skwaq
kubectl apply -f skwaq-deployment.yaml
kubectl apply -f skwaq-service.yaml
kubectl apply -f skwaq-ingress.yaml
```

### Helm Chart Deployment (Alternative)

For a more maintainable approach, use Helm:

```bash
# Add Helm repository (if you have one)
helm repo add skwaq-repo https://helm.example.com/charts

# Install or upgrade the chart
helm upgrade --install skwaq skwaq-repo/skwaq \
  --namespace skwaq \
  --create-namespace \
  --values values.yaml
```

Example `values.yaml`:

```yaml
image:
  repository: <your-registry>/skwaq
  tag: latest
  pullPolicy: Always

replicaCount: 2

neo4j:
  enabled: true
  password: <password>
  persistentVolume:
    size: 10Gi

openai:
  apiKey: <api-key>
  endpoint: <endpoint>
  apiType: azure
  apiVersion: 2023-05-15
  chatModel: gpt4o
  embeddingModel: text-embedding-ada-002

ingress:
  enabled: true
  host: skwaq.example.com
  tls: true
```

## Docker Swarm Deployment

### Prerequisites

- Docker Swarm cluster
- Access to container registry
- Docker Compose for stack deployment

### Docker Compose File for Swarm

```yaml
version: '3.8'

services:
  skwaq-api:
    image: <your-registry>/skwaq:latest
    ports:
      - "8000:8000"
    environment:
      - NEO4J_URI=bolt://neo4j:7687
      - NEO4J_USER=neo4j
      - NEO4J_PASSWORD=<password>
      - OPENAI_API_KEY=<api-key>
      - OPENAI_API_BASE=<endpoint>
    configs:
      - source: skwaq_config
        target: /app/config/config.json
    networks:
      - skwaq-network
    deploy:
      replicas: 2
      update_config:
        parallelism: 1
        delay: 10s
      restart_policy:
        condition: on-failure
      resources:
        limits:
          cpus: '1'
          memory: 2G

  neo4j:
    image: neo4j:5.15.0
    ports:
      - "7474:7474"
      - "7687:7687"
    environment:
      - NEO4J_AUTH=neo4j/<password>
      - NEO4J_dbms_memory_pagecache_size=1G
      - NEO4J_dbms_memory_heap_initial__size=1G
      - NEO4J_dbms_memory_heap_max__size=2G
    volumes:
      - neo4j_data:/data
    networks:
      - skwaq-network
    deploy:
      placement:
        constraints:
          - node.role == manager
      restart_policy:
        condition: on-failure

networks:
  skwaq-network:
    driver: overlay

volumes:
  neo4j_data:
    driver: local

configs:
  skwaq_config:
    file: ./config/config.json
```

### Deployment Commands

```bash
# Deploy the stack
docker stack deploy -c docker-compose.yml skwaq

# Verify deployment
docker stack services skwaq

# Scale the API service
docker service scale skwaq_skwaq-api=3
```

## Performance Tuning

### Resource Allocation

Adjust resources based on workload:

```yaml
# Kubernetes example
resources:
  requests:
    cpu: 500m
    memory: 1Gi
  limits:
    cpu: 2
    memory: 4Gi
```

### Neo4j Performance

Optimize Neo4j for graph workloads:

```yaml
# Neo4j environment variables
NEO4J_dbms_memory_pagecache_size: 4G
NEO4J_dbms_memory_heap_initial__size: 4G
NEO4J_dbms_memory_heap_max__size: 8G
NEO4J_dbms_jvm_additional: "-XX:+UseG1GC -XX:G1HeapRegionSize=4m"
```

## High Availability Setup

For production environments, implement high availability:

1. **Neo4j Clustering**:
   - Configure Neo4j in a causal cluster with core and read replica servers

2. **API Redundancy**:
   - Deploy multiple replicas across availability zones/nodes
   - Implement proper health checks

3. **Load Balancing**:
   - Use Kubernetes Services or Ingress controllers
   - For Swarm, use built-in load balancing or an external load balancer

## Monitoring and Logging

### Prometheus Integration

```yaml
# Add to your deployment
annotations:
  prometheus.io/scrape: "true"
  prometheus.io/port: "8000"
  prometheus.io/path: "/metrics"
```

### ELK/EFK Stack

Configure centralized logging with Elasticsearch, Logstash/Fluentd, and Kibana:

```yaml
# Fluentd config example
<source>
  @type tail
  path /var/log/containers/skwaq-*.log
  pos_file /var/log/fluentd-skwaq.pos
  tag skwaq
  <parse>
    @type json
  </parse>
</source>
```

## Security Considerations

1. **Network Policies**:
   - Restrict traffic between services
   - Example: Only allow Skwaq API to connect to Neo4j

2. **Secrets Management**:
   - Use Kubernetes Secrets or Docker Secrets
   - Consider external secret management (HashiCorp Vault, AWS KMS)

3. **Container Security**:
   - Use non-root users in containers
   - Implement read-only file systems where possible
   - Regular security scanning

4. **TLS/SSL**:
   - Configure TLS for all inbound traffic
   - Enable encryption for Neo4j connections
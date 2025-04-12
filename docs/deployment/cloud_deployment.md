# Cloud Deployment Guide

This guide covers deploying Skwaq to cloud environments, with a focus on Azure.

## Prerequisites

- Azure subscription with Contributor or Owner role
- Azure CLI installed and configured (`az login`)
- Docker installed for building and pushing container images

## Deployment Architecture

The Skwaq cloud deployment consists of:

1. **Azure OpenAI Service** - For AI model inference
2. **Azure Container Registry** - For storing Docker images
3. **Azure App Service** - For hosting the Skwaq API
4. **Azure Database (Neo4j)** - For knowledge graph storage
5. **Azure KeyVault** - For secure credential storage

```
┌───────────────────┐           ┌───────────────────┐
│                   │           │                   │
│    Azure OpenAI   │◄─────────►│    Skwaq API      │
│                   │           │   (App Service)   │
└───────────────────┘           └─────────┬─────────┘
                                          │
                                          ▼
                                ┌───────────────────┐
                                │                   │
                                │      Neo4j        │
                                │                   │
                                └───────────────────┘
```

## Deployment Steps

### 1. Infrastructure Deployment

The recommended approach is to use Infrastructure as Code (Bicep or ARM templates) for consistent deployments:

```bash
# Deploy infrastructure using Bicep
az deployment sub create \
  --location <region> \
  --template-file ./scripts/infrastructure/main.bicep \
  --parameters environmentName=<env-name> location=<region>
```

### 2. Container Image Build and Push

```bash
# Build the Skwaq container image
docker build -t skwaq:latest .

# Tag and push to Azure Container Registry
az acr login --name <acr-name>
docker tag skwaq:latest <acr-name>.azurecr.io/skwaq:latest
docker push <acr-name>.azurecr.io/skwaq:latest
```

### 3. App Service Configuration

Configure the App Service with the necessary environment variables:

```bash
# Set environment variables for App Service
az webapp config appsettings set \
  --resource-group <resource-group> \
  --name <app-service-name> \
  --settings \
  NEO4J_URI="<neo4j-connection-string>" \
  NEO4J_USER="<username>" \
  NEO4J_PASSWORD="@Microsoft.KeyVault(SecretUri=<keyvault-secret-uri>)" \
  OPENAI_API_KEY="@Microsoft.KeyVault(SecretUri=<keyvault-secret-uri>)" \
  OPENAI_API_BASE="<openai-endpoint>"
```

### 4. Deployment Verification

After deployment, verify that the system is working properly:

```bash
# Check if the API is responding
curl https://<app-service-name>.azurewebsites.net/health

# Run a simple query through the API
curl -X POST \
  -H "Content-Type: application/json" \
  -d '{"query": "test"}' \
  https://<app-service-name>.azurewebsites.net/api/query
```

## Scaling Configuration

Skwaq can be configured to scale based on load:

```bash
# Configure autoscaling rules
az monitor autoscale create \
  --resource-group <resource-group> \
  --resource <app-service-name> \
  --resource-type "Microsoft.Web/sites" \
  --name "Skwaq Autoscale" \
  --min-count 1 \
  --max-count 3 \
  --count 1
```

## Monitoring

Enable Application Insights for comprehensive monitoring:

```bash
# Enable Application Insights
az webapp config appsettings set \
  --resource-group <resource-group> \
  --name <app-service-name> \
  --settings APPLICATIONINSIGHTS_CONNECTION_STRING="<connection-string>"
```

## Security Best Practices

1. **Network Security**: Use Private Endpoints for all services
2. **HTTPS Only**: Enforce HTTPS for all traffic
3. **Managed Identity**: Use managed identities for service-to-service authentication
4. **Key Rotation**: Regularly rotate all keys and credentials

## Troubleshooting

If you encounter issues with your cloud deployment:

1. Check App Service logs:
```bash
az webapp log tail --resource-group <resource-group> --name <app-service-name>
```

2. Verify connectivity between services:
```bash
az webapp ssh --resource-group <resource-group> --name <app-service-name>
# Then run tests from inside the container
```

3. Validate Neo4j connectivity:
```bash
# Test Neo4j connection from App Service
az webapp ssh --resource-group <resource-group> --name <app-service-name>
curl -v telnet://<neo4j-host>:7687
```

## Maintenance

Regular maintenance is essential:

1. **Updates**: Keep container images updated with latest security patches
2. **Backups**: Configure regular database backups
3. **Monitoring**: Set up alerts for abnormal usage patterns
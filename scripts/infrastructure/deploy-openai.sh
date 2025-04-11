#!/bin/bash
set -e

# Source authentication data
if [ -f "config/azure_auth.json" ]; then
    echo "Loading Azure authentication data..."
    SUBSCRIPTION_ID=$(jq -r '.subscription_id' config/azure_auth.json)
    TENANT_ID=$(jq -r '.tenant_id' config/azure_auth.json)
    
    # Verify we're using the correct subscription
    CURRENT_SUB=$(az account show --query id -o tsv)
    if [ "$CURRENT_SUB" != "$SUBSCRIPTION_ID" ]; then
        echo "Switching to subscription: $SUBSCRIPTION_ID"
        az account set --subscription "$SUBSCRIPTION_ID"
    fi
else
    echo "⚠️ No authentication data found. Running authentication setup first..."
    ./scripts/infrastructure/azure-auth.sh
    
    # Reload authentication data
    SUBSCRIPTION_ID=$(jq -r '.subscription_id' config/azure_auth.json)
    TENANT_ID=$(jq -r '.tenant_id' config/azure_auth.json)
fi

# Variables
RESOURCE_GROUP="skwaq-rg"
LOCATION="eastus"  # Choose a region where Azure OpenAI is available

# Verify selected region supports the required models
echo "Verifying $LOCATION supports required OpenAI models..."
SUPPORTED_MODELS=$(az cognitiveservices account list-models --location $LOCATION --query "[?contains(name, 'gpt-4') || contains(name, 'gpt-35-turbo')].name" -o tsv 2>/dev/null || echo "")

if [ -z "$SUPPORTED_MODELS" ]; then
    echo "⚠️ Warning: Unable to verify model availability in $LOCATION"
    echo "This might be due to permissions or the region not supporting the required models."
    echo "Available Azure OpenAI regions: East US, South Central US, West Europe, West US"
    read -p "Enter a different region or press Enter to continue with $LOCATION: " NEW_LOCATION
    if [ ! -z "$NEW_LOCATION" ]; then
        LOCATION=$NEW_LOCATION
        echo "Region updated to: $LOCATION"
    fi
else
    echo "✅ Region $LOCATION supports OpenAI models"
fi

# Check if resource group exists
if ! az group show --name "$RESOURCE_GROUP" &> /dev/null; then
    echo "Creating resource group $RESOURCE_GROUP in $LOCATION..."
    az group create --name "$RESOURCE_GROUP" --location "$LOCATION"
else
    echo "Using existing resource group: $RESOURCE_GROUP"
fi

# Deploy the Bicep template
echo "Deploying Azure OpenAI resources..."
DEPLOYMENT_OUTPUT=$(az deployment group create \
    --resource-group "$RESOURCE_GROUP" \
    --template-file "scripts/infrastructure/bicep/azure-openai.bicep" \
    --parameters location=$LOCATION \
    --output json)

# Extract endpoint and resource name
ENDPOINT=$(echo $DEPLOYMENT_OUTPUT | jq -r '.properties.outputs.endpoint.value')
RESOURCE_NAME=$(echo $DEPLOYMENT_OUTPUT | jq -r '.properties.outputs.name.value')

# Get the API key
API_KEY=$(az cognitiveservices account keys list \
    --resource-group "$RESOURCE_GROUP" \
    --name "$RESOURCE_NAME" \
    --query "key1" \
    --output tsv)

# Create credentials file
mkdir -p config
cat > config/azure_openai_credentials.json << EOF
{
    "api_key": "$API_KEY",
    "endpoint": "$ENDPOINT",
    "deployments": {
        "gpt4o": "gpt4o",
        "o1": "o1",
        "o3": "o3"
    },
    "subscription_id": "$SUBSCRIPTION_ID",
    "resource_group": "$RESOURCE_GROUP",
    "region": "$LOCATION"
}
EOF

echo "✅ Azure OpenAI resources deployed successfully!"
echo "Credentials saved to config/azure_openai_credentials.json"
echo "Resource Group: $RESOURCE_GROUP"
echo "OpenAI Service: $RESOURCE_NAME"
echo "Region: $LOCATION"
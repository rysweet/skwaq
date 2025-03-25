#!/bin/bash
set -e

# Source authentication data
if [ -f "config/azure_auth.json" ]; then
  echo "Loading Azure authentication data..."
  SUBSCRIPTION_ID=$(jq -r '.subscription_id' config/azure_auth.json)
  TENANT_ID=$(jq -r '.tenant_id' config/azure_auth.json)
else
  echo "⚠️ No authentication data found. Running authentication setup first..."
  ./scripts/infrastructure/azure-auth.sh
  SUBSCRIPTION_ID=$(jq -r '.subscription_id' config/azure_auth.json)
  TENANT_ID=$(jq -r '.tenant_id' config/azure_auth.json)
fi

# Variables
RESOURCE_GROUP="skwaq-rg"
LOCATION="eastus"  # Choose a region where Azure OpenAI is available

# Verify selected region supports the required models
echo "Verifying $LOCATION supports required OpenAI models..."
SUPPORTED_MODELS=$(az cognitiveservices account list-models --location $LOCATION --query "[?contains(name, 'gpt-4') || contains(name, 'o1') || contains(name, 'o3')].name" -o tsv 2>/dev/null || echo "")

if [ -z "$SUPPORTED_MODELS" ]; then
  echo "⚠️ Warning: Unable to verify model availability in $LOCATION"
  read -p "Do you want to continue anyway? (y/n): " CONTINUE
  if [[ "$CONTINUE" != "y" && "$CONTINUE" != "Y" ]]; then
    echo "Deployment aborted."
    exit 1
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
  --template-file scripts/infrastructure/openai-resources.bicep \
  --parameters location="$LOCATION" \
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
  "resource_group": "$RESOURCE_GROUP",
  "region": "$LOCATION"
}
EOF

echo "✅ Azure OpenAI resources deployed successfully!"
echo "Credentials saved to config/azure_openai_credentials.json"
echo "Resource Group: $RESOURCE_GROUP"
echo "OpenAI Service: $RESOURCE_NAME"
echo "Region: $LOCATION"
#!/bin/bash
set -e

echo "🔐 Setting up Azure authentication and subscription for Skwaq..."

# Check if Azure CLI is installed
if ! command -v az &> /dev/null; then
  echo "❌ Azure CLI is not installed. Please install it from https://docs.microsoft.com/en-us/cli/azure/install-azure-cli"
  exit 1
fi

# Authenticate with Azure
echo "Authenticating with Azure..."
az login

# List available subscriptions
echo "Available subscriptions:"
az account list --output table

# Prompt user to select subscription or use default
read -p "Enter subscription ID to use (leave blank for default): " SUBSCRIPTION_ID

if [ -z "$SUBSCRIPTION_ID" ]; then
  SUBSCRIPTION_ID=$(az account show --query id -o tsv)
  echo "Using default subscription: $SUBSCRIPTION_ID"
else
  # Set the subscription
  az account set --subscription "$SUBSCRIPTION_ID"
  echo "Subscription set to: $SUBSCRIPTION_ID"
fi

# Verify OpenAI resource provider is registered
PROVIDER_STATE=$(az provider show --namespace Microsoft.CognitiveServices --query "registrationState" -o tsv)

if [ "$PROVIDER_STATE" != "Registered" ]; then
  echo "Registering Microsoft.CognitiveServices resource provider..."
  az provider register --namespace Microsoft.CognitiveServices
  echo "Waiting for registration to complete (this may take a few minutes)..."
  
  # Wait for registration to complete
  while [ "$(az provider show --namespace Microsoft.CognitiveServices --query "registrationState" -o tsv)" != "Registered" ]; do
    echo "Still registering... waiting 10 seconds"
    sleep 10
  done
  
  echo "✅ Microsoft.CognitiveServices resource provider registered successfully"
else
  echo "✅ Microsoft.CognitiveServices resource provider already registered"
fi

# Verify OpenAI model availability in regions
echo "Checking OpenAI model availability in regions..."
AVAILABLE_REGIONS=$(az cognitiveservices account list-kinds -o json | \
                   jq -r '.[] | select(. == "OpenAI") | "OpenAI is available"')

if [ -z "$AVAILABLE_REGIONS" ]; then
  echo "⚠️  Warning: OpenAI service may not be available in your subscription."
  echo "Please verify that your subscription has access to Azure OpenAI and that you have appropriate permissions."
  echo "Visit https://azure.microsoft.com/en-us/products/cognitive-services/openai-service to request access if needed."
  read -p "Do you want to continue anyway? (y/n): " CONTINUE
  if [[ "$CONTINUE" != "y" && "$CONTINUE" != "Y" ]]; then
    echo "Setup aborted."
    exit 1
  fi
else
  echo "✅ OpenAI service is available in your subscription"
fi

# Check for required permissions
echo "Checking for required permissions..."
PERMISSIONS=$(az role assignment list --assignee "$(az account show --query user.name -o tsv)" --query "[?roleDefinitionName=='Contributor' || roleDefinitionName=='Owner'].roleDefinitionName" -o tsv)

if [ -z "$PERMISSIONS" ]; then
  echo "⚠️  Warning: You may not have Contributor or Owner permissions required to create resources."
  read -p "Do you want to continue anyway? (y/n): " CONTINUE
  if [[ "$CONTINUE" != "y" && "$CONTINUE" != "Y" ]]; then
    echo "Setup aborted."
    exit 1
  fi
else
  echo "✅ You have sufficient permissions to create resources"
fi

# Store authentication info for later scripts
mkdir -p config
cat > config/azure_auth.json << EOF
{
  "subscription_id": "$SUBSCRIPTION_ID",
  "tenant_id": "$(az account show --query tenantId -o tsv)"
}
EOF

echo "✅ Azure authentication and subscription setup completed successfully!"
echo "Subscription details saved to config/azure_auth.json"
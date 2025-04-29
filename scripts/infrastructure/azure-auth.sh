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
az login --tenant Microsoft

# Set specific subscription
SUBSCRIPTION_ID="be51a72b-4d76-4627-9a17-7dd26245da7b"  # adapt-appsci1
echo "Setting subscription to: adapt-appsci1 ($SUBSCRIPTION_ID)"
az account set --subscription "$SUBSCRIPTION_ID"

# Verify OpenAI resource provider is registered
PROVIDER_STATE=$(az provider show --namespace Microsoft.CognitiveServices --query "registrationState" -o tsv)

if [ "$PROVIDER_STATE" != "Registered" ]; then
    echo "Registering Microsoft.CognitiveServices resource provider..."
    az provider register --namespace Microsoft.CognitiveServices
    echo "Waiting for registration to complete (this may take a few minutes)..."
    
    while [ "$(az provider show --namespace Microsoft.CognitiveServices --query "registrationState" -o tsv)" != "Registered" ]; do
        echo "Still registering... waiting 10 seconds"
        sleep 10
    done
    
    echo "✅ Microsoft.CognitiveServices resource provider registered successfully"
else
    echo "✅ Microsoft.CognitiveServices resource provider already registered"
fi

# Check for required permissions
echo "Checking for required permissions..."
PERMISSIONS=$(az role assignment list --assignee "$(az account show --query user.name -o tsv)" --query "[?roleDefinitionName=='Contributor' || roleDefinitionName=='Owner'].roleDefinitionName" -o tsv)

if [ -z "$PERMISSIONS" ]; then
    echo "⚠️  Warning: You may not have Contributor or Owner permissions required to create resources."
    echo "The following steps may fail without proper permissions."
    read -p "Do you want to continue anyway? (y/n): " CONTINUE
    if [ "$CONTINUE" != "y" ]; then
        echo "Exiting setup."
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
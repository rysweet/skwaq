#!/bin/bash
set -e

echo "🔍 Verifying Azure OpenAI model deployments for Skwaq..."

# Load credentials
if [ ! -f "config/azure_openai_credentials.json" ]; then
  echo "❌ Azure OpenAI credentials not found. Please run deploy-openai.sh first."
  exit 1
fi

# Get resource name and group from credentials file
RESOURCE_GROUP=$(jq -r '.resource_group' config/azure_openai_credentials.json)
RESOURCE_NAME=$(az resource list --resource-group $RESOURCE_GROUP --resource-type "Microsoft.CognitiveServices/accounts" --query "[0].name" -o tsv)

if [ -z "$RESOURCE_NAME" ]; then
  echo "❌ Could not find OpenAI resource in resource group $RESOURCE_GROUP"
  exit 1
fi

echo "Checking model deployments in $RESOURCE_NAME..."

# Get current deployments
DEPLOYMENTS=$(az cognitiveservices account deployment list \
  --name "$RESOURCE_NAME" \
  --resource-group "$RESOURCE_GROUP" \
  --query "[].name" -o tsv)

# Check for required models
REQUIRED_MODELS=("gpt4o" "o1" "o3")
MISSING_MODELS=()

for MODEL in "${REQUIRED_MODELS[@]}"; do
  if ! echo "$DEPLOYMENTS" | grep -q "$MODEL"; then
    MISSING_MODELS+=("$MODEL")
  fi
done

if [ ${#MISSING_MODELS[@]} -eq 0 ]; then
  echo "✅ All required models are deployed and available"
else
  echo "⚠️ The following required models are not deployed: ${MISSING_MODELS[*]}"
  echo "You may need to adjust the deployment template or request access for these models."
  echo "For more information on model access, visit: https://aka.ms/oai/quotaincrease"
fi

# Test a simple completion to verify connectivity
echo "Testing API connectivity..."

# Use variables from credentials file
API_KEY=$(jq -r '.api_key' config/azure_openai_credentials.json)
ENDPOINT=$(jq -r '.endpoint' config/azure_openai_credentials.json)
MODEL=$(echo "$DEPLOYMENTS" | head -n 1)  # Use first available deployment

if [ -z "$MODEL" ]; then
  echo "❌ No model deployments found to test connectivity"
else
  # Simple API call to test connectivity
  echo "Testing connection to $MODEL deployment..."
  
  RESPONSE=$(curl -s $ENDPOINT/openai/deployments/$MODEL/chat/completions?api-version=2023-05-15 \
    -H "Content-Type: application/json" \
    -H "api-key: $API_KEY" \
    -d '{
      "messages": [
        {"role": "system", "content": "You are a helpful assistant."},
        {"role": "user", "content": "Say hello for testing connection"}
      ],
      "max_tokens": 10
    }')
  
  if echo "$RESPONSE" | grep -q "content"; then
    echo "✅ Successfully connected to Azure OpenAI API"
  else
    echo "❌ Failed to connect to Azure OpenAI API"
    echo "Response: $RESPONSE"
  fi
fi

echo "Model verification completed"
#!/bin/bash
set -e
echo "🔍 Verifying Azure OpenAI model deployments for Skwaq..."

# Load credentials
if [ ! -f "config/azure_openai_credentials.json" ]; then
    echo "❌ Azure OpenAI credentials not found. Please run deploy-openai.sh first."
    exit 1
fi

RESOURCE_NAME=$(az resource list --resource-group $(jq -r '.resource_group' config/azure_openai_credentials.json) --resource-type "Microsoft.CognitiveServices/accounts" --query "[0].name" -o tsv)

echo "Checking model deployments in $RESOURCE_NAME..."

# Get current deployments
DEPLOYMENTS=$(az cognitiveservices account deployment list \
    --name "$RESOURCE_NAME" \
    --resource-group $(jq -r '.resource_group' config/azure_openai_credentials.json) \
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
    echo "This could be due to quota limitations or deployment delays."
    echo "The Azure OpenAI deployments may take up to 15 minutes to complete."
    echo "You can check deployment status in the Azure Portal or run this script again later."
    
    # Suggest quota increase if needed
    echo "If you need to request quota increases, visit:"
    echo "https://aka.ms/oai/quotaincrease"
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
    RESPONSE=$(curl -s -X POST "$ENDPOINT/openai/deployments/$MODEL/chat/completions?api-version=2023-05-15" \
        -H "Content-Type: application/json" \
        -H "api-key: $API_KEY" \
        -d '{
            "messages": [{"role": "user", "content": "Say hello"}],
            "max_tokens": 10
        }')
    
    if echo "$RESPONSE" | jq -e '.choices[0].message.content' > /dev/null; then
        echo "✅ Successfully connected to Azure OpenAI API"
    else
        echo "❌ Failed to connect to Azure OpenAI API"
        echo "Response: $RESPONSE"
        echo "Please verify your credentials and network connectivity"
    fi
fi

echo "Model verification completed"
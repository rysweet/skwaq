// deploy-model.bicep
// Deploys any model (OpenAI or Anthropic MaaS) to an Azure AI Services resource.
// Idempotent — safe to run multiple times.
//
// Usage (GPT-5.4):
//   az deployment group create \
//     --resource-group <your-rg> \
//     --template-file infra/azure/deploy-model.bicep \
//     --parameters accountName=<your-account> \
//                  deploymentName=gpt-54 \
//                  modelName=gpt-5.4 \
//                  modelVersion=2026-03-05 \
//                  modelFormat=OpenAI
//
// Usage (Claude Opus 4.6 — requires quota):
//   az deployment group create \
//     --resource-group <your-rg> \
//     --template-file infra/azure/deploy-model.bicep \
//     --parameters accountName=<your-account> \
//                  deploymentName=claude-opus-46 \
//                  modelName=claude-opus-4-6 \
//                  modelVersion=1 \
//                  modelFormat=Anthropic

@description('Name of the existing Azure AI Services account')
param accountName string

@description('Name for the model deployment')
param deploymentName string

@description('Model name (e.g. gpt-5.4, claude-opus-4-6)')
param modelName string

@description('Model version')
param modelVersion string

@description('Model format: OpenAI for GPT models, Anthropic for Claude models')
@allowed([
  'OpenAI'
  'Anthropic'
])
param modelFormat string = 'OpenAI'

@description('SKU name for the deployment')
@allowed([
  'Standard'
  'GlobalStandard'
  'DataZoneStandard'
])
param skuName string = 'GlobalStandard'

@description('Capacity in thousands of tokens per minute')
param skuCapacity int = 10

// Reference the existing AI Services account
resource account 'Microsoft.CognitiveServices/accounts@2024-10-01' existing = {
  name: accountName
}

// Deploy the model
resource deployment 'Microsoft.CognitiveServices/accounts/deployments@2024-10-01' = {
  parent: account
  name: deploymentName
  sku: {
    name: skuName
    capacity: skuCapacity
  }
  properties: {
    model: {
      format: modelFormat
      name: modelName
      version: modelVersion
    }
  }
}

output deploymentName string = deployment.name
output endpoint string = account.properties.endpoint
output modelName string = modelName
output modelFormat string = modelFormat

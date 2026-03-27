// deploy-model.bicep
// Deploys an OpenAI model to an existing Azure AI Services resource.
// Usage:
//   az deployment group create \
//     --resource-group <your-rg> \
//     --template-file infra/azure/deploy-model.bicep \
//     --parameters accountName=<your-account> \
//                  deploymentName=gpt-51 \
//                  modelName=gpt-5.1 \
//                  modelVersion=2025-11-13

@description('Name of the existing Azure AI Services / Cognitive Services account')
param accountName string

@description('Name for the model deployment')
param deploymentName string

@description('Model name (e.g. gpt-5.1, gpt-5.4)')
param modelName string

@description('Model version')
param modelVersion string

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
      format: 'OpenAI'
      name: modelName
      version: modelVersion
    }
  }
}

output deploymentName string = deployment.name
output endpoint string = account.properties.endpoint
output modelName string = modelName
output modelVersion string = modelVersion

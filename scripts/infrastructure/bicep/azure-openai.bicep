@description('The name of the OpenAI resource')
param name string = 'skwaq-openai-${uniqueString(resourceGroup().id)}'

@description('The location to deploy the OpenAI resource')
param location string = resourceGroup().location

@description('SKU name for the OpenAI resource')
param sku string = 'S0'

@description('Array of model deployments to create')
param modelDeployments array = [
  {
    name: 'gpt4o'
    model: {
      format: 'OpenAI'
      name: 'gpt-4'
      version: '0125-preview'
    }
    sku: {
      name: 'Standard'
      capacity: 1
    }
  }
  {
    name: 'o1'
    model: {
      format: 'OpenAI'
      name: 'gpt-35-turbo'
      version: '0125'
    }
    sku: {
      name: 'Standard'
      capacity: 1
    }
  }
  {
    name: 'o3'
    model: {
      format: 'OpenAI'
      name: 'gpt-35-turbo-16k'
      version: '0125'
    }
    sku: {
      name: 'Standard'
      capacity: 1
    }
  }
]

// Azure OpenAI Service resource
resource openai 'Microsoft.CognitiveServices/accounts@2023-05-01' = {
  name: name
  location: location
  sku: {
    name: sku
  }
  kind: 'OpenAI'
  properties: {
    customSubDomainName: toLower(name)
    networkAcls: {
      defaultAction: 'Allow'
      virtualNetworkRules: []
      ipRules: []
    }
    publicNetworkAccess: 'Enabled'
  }
}

// Model deployments
@batchSize(1)
resource modelDeployment 'Microsoft.CognitiveServices/accounts/deployments@2023-05-01' = [for deployment in modelDeployments: {
  name: '${openai.name}/${deployment.name}'
  properties: {
    model: deployment.model
    raiPolicyName: 'Microsoft.Default'
  }
  sku: deployment.sku
}]

// Outputs
output endpoint string = openai.properties.endpoint
output name string = openai.name
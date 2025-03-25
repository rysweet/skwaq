@description('Specifies the location for resources.')
param location string = resourceGroup().location

@description('Suffix for resource names to ensure uniqueness')
param nameSuffix string = uniqueString(resourceGroup().id)

@description('Tags for resources')
param tags object = {
  project: 'skwaq'
  environment: 'development'
}

@description('Cognitive Services SKU')
param cognitiveServicesSku string = 'S0'

resource openAI 'Microsoft.CognitiveServices/accounts@2023-05-01' = {
  name: 'skwaq-openai-${nameSuffix}'
  location: location
  tags: tags
  sku: {
    name: cognitiveServicesSku
  }
  kind: 'OpenAI'
  properties: {
    publicNetworkAccess: 'Enabled'
    customSubDomainName: 'skwaq-openai-${nameSuffix}'
  }
}

resource gpt4oDeployment 'Microsoft.CognitiveServices/accounts/deployments@2023-05-01' = {
  parent: openAI
  name: 'gpt4o'
  properties: {
    model: {
      format: 'OpenAI'
      name: 'gpt-4o'
      version: '0613'
    }
    raiPolicyName: 'Microsoft.Default'
  }
  sku: {
    name: 'Standard'
    capacity: 10
  }
}

resource o1Deployment 'Microsoft.CognitiveServices/accounts/deployments@2023-05-01' = {
  parent: openAI
  name: 'o1'
  properties: {
    model: {
      format: 'OpenAI'
      name: 'o1'
      version: '2024-05-01'
    }
    raiPolicyName: 'Microsoft.Default'
  }
  sku: {
    name: 'Standard'
    capacity: 10
  }
}

resource o3Deployment 'Microsoft.CognitiveServices/accounts/deployments@2023-05-01' = {
  parent: openAI
  name: 'o3'
  properties: {
    model: {
      format: 'OpenAI'
      name: 'o3'
      version: '2024-05-01'
    }
    raiPolicyName: 'Microsoft.Default'
  }
  sku: {
    name: 'Standard'
    capacity: 10
  }
}

output endpoint string = openAI.properties.endpoint
output name string = openAI.name

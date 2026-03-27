// setup-rbac.bicep
// Assigns Cognitive Services OpenAI User role to a principal on an AI Services resource.
// Usage:
//   az deployment group create \
//     --resource-group rysweet-ballistae \
//     --template-file infra/azure/setup-rbac.bicep \
//     --parameters accountName=rysweetballist5347662217 \
//                  principalId=<user-or-managed-identity-object-id>

@description('Name of the existing Azure AI Services account')
param accountName string

@description('Object ID of the principal (user, service principal, or managed identity)')
param principalId string

@description('Principal type')
@allowed(['User', 'ServicePrincipal', 'Group'])
param principalType string = 'User'

// Cognitive Services OpenAI User built-in role
var cognitiveServicesOpenAIUserRoleId = '5e0bd9bd-7b93-4f28-af87-19fc36ad61bd'

resource account 'Microsoft.CognitiveServices/accounts@2024-10-01' existing = {
  name: accountName
}

resource roleAssignment 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(account.id, principalId, cognitiveServicesOpenAIUserRoleId)
  scope: account
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', cognitiveServicesOpenAIUserRoleId)
    principalId: principalId
    principalType: principalType
  }
}

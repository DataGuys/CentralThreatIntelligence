// Core Infrastructure for Central Threat Intelligence
// Updated: 2025‑04‑19 – replaced map() with array comprehensions and formatted

param location string
param ctiWorkspaceName string
param ctiWorkspaceRetentionInDays int
param ctiWorkspaceDailyQuotaGb int
param ctiWorkspaceSku string
param keyVaultName string
param clientSecretName string
@secure()
param initialClientSecret string
param tenantId string
param managedIdentityName string
param allowedIpAddresses array
param allowedSubnetIds array
param logicAppServicePlanName string
param logicAppSku string
param maxElasticWorkerCount int
param tags object

// Variables for Key Vault network ACLs
var ipRulesConfig = [for ipAddress in allowedIpAddresses: { value: ipAddress }]
var vnetRulesConfig = [for subnetId in allowedSubnetIds: { id: subnetId }]

// User‑assigned managed identity for Logic Apps
resource managedIdentity 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' = {
  name: managedIdentityName
  location: location
  tags: tags
}

// Log Analytics workspace
resource ctiWorkspace 'Microsoft.OperationalInsights/workspaces@2022-10-01' = {
  name: ctiWorkspaceName
  location: location
  tags: tags
  properties: {
    sku: {
      name: ctiWorkspaceSku
    }
    retentionInDays: ctiWorkspaceRetentionInDays
    workspaceCapping: {
      dailyQuotaGb: ctiWorkspaceDailyQuotaGb
    }
    features: {
      enableLogAccessUsingOnlyResourcePermissions: true
      searchVersion: 2
    }
    publicNetworkAccessForIngestion: 'Enabled'
    publicNetworkAccessForQuery: 'Enabled'
  }
}

// Key Vault with IP & VNet ACLs
resource keyVault 'Microsoft.KeyVault/vaults@2023-02-01' = {
  name: keyVaultName
  location: location
  tags: tags
  properties: {
    enabledForDeployment: true
    enabledForTemplateDeployment: true
    enabledForDiskEncryption: true
    enableRbacAuthorization: true
    tenantId: tenantId
    sku: {
      name: 'standard'
      family: 'A'
    }
    networkAcls: {
      defaultAction: 'Deny'
      bypass: 'AzureServices'
      ipRules: ipRulesConfig
      virtualNetworkRules: vnetRulesConfig
    }
  }
}

resource clientSecretValue 'Microsoft.KeyVault/vaults/secrets@2023-02-01' = {
  parent: keyVault
  name: clientSecretName
  properties: {
    value: !empty(initialClientSecret) ? initialClientSecret : 'PlaceholderValue-ReplaceAfterDeployment'
  }
}

resource keyVaultRoleAssignment 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(keyVault.id, managedIdentity.id, 'KeyVaultSecretsUser')
  scope: keyVault
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', '4633458b-17de-408a-b874-0445c86b69e6')
    principalId: managedIdentity.properties.principalId
    principalType: 'ServicePrincipal'
  }
}

resource logicAppServicePlan 'Microsoft.Web/serverfarms@2022-09-01' = {
  name: logicAppServicePlanName
  location: location
  tags: tags
  sku: {
    name: logicAppSku
    tier: contains(logicAppSku, 'P') ? 'Premium' : 'WorkflowStandard'
  }
  properties: {
    maximumElasticWorkerCount: maxElasticWorkerCount
  }
}

output ctiWorkspaceId string = ctiWorkspace.id
output managedIdentityId string = managedIdentity.id
output managedIdentityPrincipalId string = managedIdentity.properties.principalId
output keyVaultId string = keyVault.id
output logicAppServicePlanId string = logicAppServicePlan.id

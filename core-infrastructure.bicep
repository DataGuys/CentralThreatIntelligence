param location string
param ctiWorkspaceName string
param ctiWorkspaceRetentionInDays int
param ctiWorkspaceDailyQuotaGb int
param ctiWorkspaceSku string
param keyVaultName string
param clientSecretName string
param initialClientSecret string
param tenantId string
param managedIdentityName string
param allowedIpAddresses array
param allowedSubnetIds array
param logicAppServicePlanName string
param logicAppSku string
param maxElasticWorkerCount int
param tags object

// User-assigned managed identity for Logic Apps
resource managedIdentity 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' = {
  name: managedIdentityName
  location: location
  tags: tags
}

// Define Log Analytics workspace for CTI
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

// Key Vault for storing secrets with enhanced security
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
      ipRules: empty(allowedIpAddresses) ? [] : map(allowedIpAddresses, ip => {
        value: ip
      })
      virtualNetworkRules: empty(allowedSubnetIds) ? [] : map(allowedSubnetIds, subnetId => {
        id: subnetId
      })
    }
  }
}

// Add client secret to Key Vault
resource clientSecretValue 'Microsoft.KeyVault/vaults/secrets@2023-02-01' = {
  parent: keyVault
  name: clientSecretName
  properties: {
    value: !empty(initialClientSecret) ? initialClientSecret : 'PlaceholderValue-ReplaceAfterDeployment'
  }
}

// RBAC role assignment for managed identity to access Key Vault
resource keyVaultRoleAssignment 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(keyVault.id, managedIdentity.id, 'Key Vault Secrets User')
  scope: keyVault
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', '4633458b-17de-408a-b874-0445c86b69e6') // Key Vault Secrets User
    principalId: managedIdentity.properties.principalId
    principalType: 'ServicePrincipal'
  }
}

// Logic App Service Plan with enhanced scalability
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

// Output the resource IDs
output ctiWorkspaceId string = ctiWorkspace.id
output managedIdentityId string = managedIdentity.id
output managedIdentityPrincipalId string = managedIdentity.properties.principalId
output keyVaultId string = keyVault.id
output logicAppServicePlanId string = logicAppServicePlan.id

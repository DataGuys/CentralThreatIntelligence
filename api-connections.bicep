param location string
param ctiWorkspaceName string
param keyVaultName string
param clientSecretName string
param tenantId string
param appClientId string
param tags object
param logAnalyticsDataCollectorConnectionName string
param logAnalyticsQueryConnectionName string
param microsoftGraphConnectionName string

// Reference to existing resources
resource ctiWorkspace 'Microsoft.OperationalInsights/workspaces@2022-10-01' existing = {
  name: ctiWorkspaceName
}

// Logic App API Connections
resource logAnalyticsConnection 'Microsoft.Web/connections@2016-06-01' = {
  name: logAnalyticsDataCollectorConnectionName
  location: location
  tags: tags
  properties: {
    displayName: 'Log Analytics Data Collector'
    api: {
      id: subscriptionResourceId('Microsoft.Web/locations/managedApis', location, 'azureloganalyticsdatacollector')
    }
    parameterValues: {
      workspace: ctiWorkspace.properties.customerId
      workspaceKey: ctiWorkspace.listKeys().primarySharedKey
    }
  }
}

resource logAnalyticsQueryConnection 'Microsoft.Web/connections@2016-06-01' = {
  name: logAnalyticsQueryConnectionName
  location: location
  tags: tags
  properties: {
    displayName: 'Azure Monitor Logs'
    api: {
      id: subscriptionResourceId('Microsoft.Web/locations/managedApis', location, 'azuremonitorlogs')
    }
    parameterValues: {
      'token:TenantId': tenantId
      'token:clientId': appClientId
      'token:clientSecret': listSecrets(resourceId('Microsoft.KeyVault/vaults/secrets', keyVaultName, clientSecretName), '2023-02-01').value
      'token:grantType': 'client_credentials'
    }
  }
}

// Microsoft Graph connection for modern API access
resource microsoftGraphConnection 'Microsoft.Web/connections@2016-06-01' = {
  name: microsoftGraphConnectionName
  location: location
  tags: tags
  properties: {
    displayName: 'Microsoft Graph'
    api: {
      id: subscriptionResourceId('Microsoft.Web/locations/managedApis', location, 'microsoftgraph')
    }
    parameterValues: {
      'token:TenantId': tenantId
      'token:clientId': appClientId
      'token:clientSecret': listSecrets(resourceId('Microsoft.KeyVault/vaults/secrets', keyVaultName, clientSecretName), '2023-02-01').value
      'token:grantType': 'client_credentials'
    }
  }
}

// Output the connection IDs
output logAnalyticsConnectionId string = logAnalyticsConnection.id
output logAnalyticsQueryConnectionId string = logAnalyticsQueryConnection.id
output microsoftGraphConnectionId string = microsoftGraphConnection.id

param location string
param mdtiConnectorName string = 'CTI-MDTI-Connector'
param managedIdentityId string
param logAnalyticsConnectionId string
param logAnalyticsQueryConnectionId string
param ctiWorkspaceName string
param diagnosticSettingsRetentionDays int
param ctiWorkspaceId string
param keyVaultName string
param clientSecretName string
param appClientId string
param tenantId string
param enableMDTI bool
param tags object

resource mdtiConnectorLogicApp 'Microsoft.Logic/workflows@2019-05-01' = if (enableMDTI) {
  name: mdtiConnectorName
  location: location
  tags: tags
  identity: {
    type: 'UserAssigned'
    userAssignedIdentities: {
      '${managedIdentityId}': {}
    }
  }
  properties: {
    state: 'Enabled'
    definition: {
      '$schema': 'https://schema.management.azure.com/providers/Microsoft.Logic/schemas/2016-06-01/workflowdefinition.json#'
      contentVersion: '1.0.0.0'
      parameters: {
        '$connections': {
          defaultValue: {}
          type: 'Object'
        }
        'workspaceName': {
          defaultValue: ctiWorkspaceName
          type: 'String'
        }
        'tenantId': {
          defaultValue: tenantId
          type: 'String'
        }
        'clientId': {
          defaultValue: appClientId
          type: 'String'
        }
      }
      triggers: {
        Recurrence: {
          recurrence: {
            frequency: 'Hour'
            interval: 6
          }
          type: 'Recurrence'
        }
      }
      actions: {
        Get_Authentication_Token: {
          runAfter: {}
          type: 'Http'
          inputs: {
            method: 'POST'
            uri: '${environment().authentication.loginEndpoint}${tenantId}/oauth2/token'
            headers: {
              'Content-Type': 'application/x-www-form-urlencoded'
            }
            body: 'grant_type=client_credentials&client_id=${appClientId}&client_secret=${listSecrets(resourceId('Microsoft.KeyVault/vaults/secrets', keyVaultName, clientSecretName), '2023-02-01').value}&resource=https://api.securitycenter.microsoft.com/'
          }
        }
        Get_MDTI_Indicators: {
          runAfter: {
            Get_Authentication_Token: ['Succeeded']
          }
          type: 'Http'
          inputs: {
            method: 'GET'
            uri: 'https://api.securitycenter.microsoft.com/api/indicators?$filter=sourceseverity eq \'High\' and expirationDateTime gt @{utcNow()}'
            headers: {
              Authorization: 'Bearer @{body(\'Get_Authentication_Token\').access_token}'
              'Content-Type': 'application/json'
            }
          }
        }
        // Additional actions for processing indicators would be here
      }
    }
    parameters: {
      '$connections': {
        value: {
          azureloganalyticsdatacollector: {
            connectionId: logAnalyticsConnectionId
            connectionName: 'azureloganalyticsdatacollector'
            id: subscriptionResourceId('Microsoft.Web/locations/managedApis', location, 'azureloganalyticsdatacollector')
          }
          azuremonitorlogs: {
            connectionId: logAnalyticsQueryConnectionId
            connectionName: 'azuremonitorlogs'
            id: subscriptionResourceId('Microsoft.Web/locations/managedApis', location, 'azuremonitorlogs')
          }
        }
      }
    }
  }
}

resource mdtiConnectorDiagnostics 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = if (enableMDTI) {
  scope: mdtiConnectorLogicApp
  name: 'diagnostics'
  properties: {
    workspaceId: ctiWorkspaceId
    logs: [
      {
        category: 'WorkflowRuntime'
        enabled: true
        retentionPolicy: {
          days: diagnosticSettingsRetentionDays
          enabled: true
        }
      }
    ]
    metrics: [
      {
        category: 'AllMetrics'
        enabled: true
        retentionPolicy: {
          days: diagnosticSettingsRetentionDays
          enabled: true
        }
      }
    ]
  }
}

output mdtiConnectorResourceId string = enableMDTI ? mdtiConnectorLogicApp.id : ''
output mdtiConnectorName string = enableMDTI ? mdtiConnectorName : ''

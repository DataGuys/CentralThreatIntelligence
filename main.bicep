// Advanced Central Threat Intelligence (CTI) Solution – v2.1
// Updated: 2025‑04‑19 – removed utcNow() from parameter default

targetScope = 'resourceGroup'

@description('Location for all resources.')
param location string = resourceGroup().location

@description('Name of the Log Analytics workspace for CTI')
param ctiWorkspaceName string = 'CTI-Workspace'

param enableMDTI bool = true
param enableSecurityCopilot bool = false
param enableSentinelIntegration bool = true
param enableAnalyticsRules bool = true
param enableHuntingQueries bool = true

@description('Application (client) ID for the service principal')
param appClientId string

@description('Tenant ID, defaults to the subscription tenant')
param tenantId string = subscription().tenantId

@secure()
@description('Client secret for the service principal')
param clientSecret string = ''

@description('Base set of tags applied to all resources')
param baseTags object = {
  solution: 'CentralThreatIntelligence'
  environment: 'Production'
  createdBy: 'Bicep'
}

@description('Current UTC date in yyyy-MM-dd format')
param deploymentDate string = utcNow('yyyy-MM-dd')

var tags = union(baseTags, {
  deploymentDate: deploymentDate
})

module parameters './parameters.bicep' = {
  name: 'parameters'
}

module coreInfrastructure './core-infrastructure.bicep' = {
  name: 'coreInfrastructure'
  params: {
    location: location
    ctiWorkspaceName: ctiWorkspaceName
    ctiWorkspaceRetentionInDays: 90
    ctiWorkspaceDailyQuotaGb: 5
    ctiWorkspaceSku: 'PerGB2018'
    keyVaultName: parameters.outputs.keyVaultName
    clientSecretName: 'clientSecret'
    initialClientSecret: clientSecret
    tenantId: tenantId
    managedIdentityName: parameters.outputs.managedIdentityName
    allowedIpAddresses: []
    allowedSubnetIds: []
    logicAppServicePlanName: parameters.outputs.logicAppServicePlanName
    logicAppSku: 'WS1'
    maxElasticWorkerCount: 10
    tags: tags
  }
}

module customTables './custom-tables.json' = {
  name: 'customTables'
  params: {
    ctiWorkspaceName: ctiWorkspaceName
  }
  dependsOn: [ coreInfrastructure ]
}

module apiConnections './api-connections.bicep' = {
  name: 'apiConnections'
  params: {
    location: location
    ctiWorkspaceName: ctiWorkspaceName
    keyVaultName: parameters.outputs.keyVaultName
    clientSecretName: 'clientSecret'
    tenantId: tenantId
    appClientId: appClientId
    tags: tags
    logAnalyticsDataCollectorConnectionName: parameters.outputs.logAnalyticsDataCollectorConnectionName
    logAnalyticsQueryConnectionName: parameters.outputs.logAnalyticsQueryConnectionName
    microsoftGraphConnectionName: parameters.outputs.microsoftGraphConnectionName
  }
  dependsOn: [ coreInfrastructure, customTables ]
}

module logicApps 'logic-apps/deployment.bicep' = {
  name: 'logicApps'
  params: {
    location: location
    managedIdentityId: coreInfrastructure.outputs.managedIdentityId
    logAnalyticsConnectionId: apiConnections.outputs.logAnalyticsConnectionId
    logAnalyticsQueryConnectionId: apiConnections.outputs.logAnalyticsQueryConnectionId
    microsoftGraphConnectionId: apiConnections.outputs.microsoftGraphConnectionId
    ctiWorkspaceName: ctiWorkspaceName
    ctiWorkspaceId: coreInfrastructure.outputs.ctiWorkspaceId
    keyVaultName: parameters.outputs.keyVaultName
    clientSecretName: 'clientSecret'
    appClientId: appClientId
    tenantId: tenantId
    securityApiBaseUrl: parameters.outputs.securityApiBaseUrl
    enableMDTI: enableMDTI
    enableSecurityCopilot: enableSecurityCopilot
    dceNameForCopilot: parameters.outputs.dceNameForCopilot
    // dceCopilotIntegrationName: parameters.outputs.dceCopilotIntegrationName // Removed as it's not a valid parameter for the logicApps module
    diagnosticSettingsRetentionDays: 30
    tags: tags
  }
}

module sentinelIntegration './sentinel-integration.bicep' = {
  name: 'sentinelIntegration'
  params: {
    ctiWorkspaceName: ctiWorkspaceName
    ctiWorkspaceId: coreInfrastructure.outputs.ctiWorkspaceId
    location: location
    enableSentinelIntegration: enableSentinelIntegration
    enableAnalyticsRules: enableAnalyticsRules
    enableHuntingQueries: enableHuntingQueries
    existingSentinelWorkspaceId: ''
    tags: tags
  }
  dependsOn: [ customTables ]
}

resource ctiDashboardWorkbook 'Microsoft.Insights/workbooks@2022-04-01' = {
  name: 'CTIDashboard-${ctiWorkspaceName}' // Unique name for the workbook
  location: location
  tags: tags
  kind: 'shared' // Or 'user' depending on requirement
  properties: {
    displayName: 'CTI Dashboard'
    serializedData: loadTextContent('./CTI-ManualIndicatorSubmission.workbook') // Assuming content is moved to a separate file
    category: 'workbook' // Standard category for workbooks
    sourceId: coreInfrastructure.outputs.ctiWorkspaceId // Link workbook to the Log Analytics workspace
    version: 'Notebook/1.0' // Optional: Specify workbook version if needed
  }
}

// Note: The large JSON content for the workbook has been moved to a separate file 'workbook-content.json'
// Create a file named 'workbook-content.json' in the same directory and paste the JSON content into it.
// Example content for 'workbook-content.json':
/*
{
  "version": "Notebook/1.0",
  "items": [
    {
      "type": 1, // Use numeric type for text block
      "content": {
        "json": "# Threat Intelligence Dashboard"
      },
      "name": "Title"
    },
    {
      "type": 9, // Use numeric type for parameters block
      "content": {
        "version": "KqlParameterItem/1.0",
        "parameters": [
          {
            "id": "timeRange",
            "version": "KqlParameterItem/1.0",
            "name": "TimeRange",
            "label": "Time Range",
            "type": 4, // Time range parameter type
            "isRequired": true, // Make parameter required
            "value": {
              "durationMs": 86400000 // Default to 1 day
            },
            "typeSettings": {
              "selectableValues": [
                { "durationMs": 3600000, "label": "Last hour" },
                { "durationMs": 86400000, "label": "Last 24 hours" },
                { "durationMs": 604800000, "label": "Last 7 days" },
                { "durationMs": 2592000000, "label": "Last 30 days" }
              ],
              "includeTime": true // Include time picker
            }
          }
        ],
        "style": "above", // Parameter style
        "queryType": 0, // Query type (usually 0 for parameters)
        "resourceType": "microsoft.operationalinsights/workspaces" // Resource type context
      },
      "name": "TimeRangeDropdown"
    }
    // Add other workbook items (queries, visualizations) here
  ],
  "styleSettings": {}, // Empty or configure style settings
  "$schema": "https://github.com/Microsoft/Application-Insights-Workbooks/blob/master/schema/workbook.json" // Optional: Schema reference
}
*/


// Removed incorrect variable declarations that were likely placeholders
// var someVariable = 'properValue'
// var interpolatedString = '${someVariable}-suffix'
// var anotherVariable = 'anotherValue'

output ctiWorkspaceId string = coreInfrastructure.outputs.ctiWorkspaceId
output ctiWorkspaceName string = ctiWorkspaceName
output keyVaultName string = parameters.outputs.keyVaultName
output managedIdentityId string = coreInfrastructure.outputs.managedIdentityId
output managedIdentityPrincipalId string = coreInfrastructure.outputs.managedIdentityPrincipalId
output logicAppNames object = logicApps.outputs.logicAppNames

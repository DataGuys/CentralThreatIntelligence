// Advanced Central Threat Intelligence (CTI) Solution
// This template deploys a comprehensive threat intelligence platform
// Version: 2.0
// Last Updated: April 2025

targetScope = 'resourceGroup'

// Import parameters from parameters.bicep
module parameters './parameters.bicep' = {
  name: 'parameters'
}

// Core Infrastructure
module coreInfrastructure './core-infrastructure.bicep' = {
  name: 'coreInfrastructure'
  params: {
    location: parameters.outputs.location
    ctiWorkspaceName: parameters.outputs.ctiWorkspaceName
    ctiWorkspaceRetentionInDays: 90
    ctiWorkspaceDailyQuotaGb: 5
    ctiWorkspaceSku: 'PerGB2018'
    keyVaultName: parameters.outputs.keyVaultName
    clientSecretName: 'clientSecret'
    initialClientSecret: ''
    tenantId: subscription().tenantId
    managedIdentityName: parameters.outputs.managedIdentityName
    allowedIpAddresses: []
    allowedSubnetIds: []
    logicAppServicePlanName: parameters.outputs.logicAppServicePlanName
    logicAppSku: 'WS1'
    maxElasticWorkerCount: 10
    tags: {
      solution: 'CentralThreatIntelligence'
      environment: 'Production'
      createdBy: 'Bicep'
      deploymentDate: utcNow('yyyy-MM-dd')
    }
  }
}

// Custom Tables
module customTables './custom-tables.bicep' = {
  name: 'customTables'
  params: {
    ctiWorkspaceName: parameters.outputs.ctiWorkspaceName
  }
  dependsOn: [
    coreInfrastructure
  ]
}

// API Connections
module apiConnections './api-connections.bicep' = {
  name: 'apiConnections'
  params: {
    location: parameters.outputs.location
    ctiWorkspaceName: parameters.outputs.ctiWorkspaceName
    keyVaultName: parameters.outputs.keyVaultName
    clientSecretName: 'clientSecret'
    tenantId: subscription().tenantId
    appClientId: 'REPLACE_WITH_APP_CLIENT_ID' // Replace with actual client ID
    tags: {
      solution: 'CentralThreatIntelligence'
      environment: 'Production'
      createdBy: 'Bicep'
      deploymentDate: utcNow('yyyy-MM-dd')
    }
    logAnalyticsDataCollectorConnectionName: parameters.outputs.logAnalyticsDataCollectorConnectionName
    logAnalyticsQueryConnectionName: parameters.outputs.logAnalyticsQueryConnectionName
    microsoftGraphConnectionName: parameters.outputs.microsoftGraphConnectionName
  }
  dependsOn: [
    coreInfrastructure
    customTables
  ]
}

// TAXII Connector
module taxiiConnector 'logic-apps/taxii-connector.bicep' = {
  name: 'taxiiConnector'
  params: {
    location: parameters.outputs.location
    taxiiConnectorLogicAppName: 'CTI-TAXII2-Connector'
    managedIdentityId: coreInfrastructure.outputs.managedIdentityId
    logAnalyticsConnectionId: apiConnections.outputs.logAnalyticsConnectionId
    logAnalyticsQueryConnectionId: apiConnections.outputs.logAnalyticsQueryConnectionId
    ctiWorkspaceName: parameters.outputs.ctiWorkspaceName
    diagnosticSettingsRetentionDays: 30
    ctiWorkspaceId: coreInfrastructure.outputs.ctiWorkspaceId
    tags: {
      solution: 'CentralThreatIntelligence'
      environment: 'Production'
      createdBy: 'Bicep'
      deploymentDate: utcNow('yyyy-MM-dd')
    }
  }
  dependsOn: [
    apiConnections
  ]
}

// Additional Logic App modules would be referenced here following the same pattern
// module defenderConnector 'logic-apps/defender-connector.bicep' = {...}
// module mdtiConnector 'logic-apps/mdti-connector.bicep' = {...}
// module entraConnector 'logic-apps/entra-connector.bicep' = {...}
// module exoConnector 'logic-apps/exo-connector.bicep' = {...}
// module securityCopilotConnector 'logic-apps/copilot-connector.bicep' = {...}
// module housekeeping 'logic-apps/housekeeping.bicep' = {...}
// module threatFeedSync 'logic-apps/threatfeed-sync.bicep' = {...}

// Sentinel Integration - Conditional based on the enableSentinelIntegration parameter
module sentinelIntegration './sentinel-integration.bicep' = {
  name: 'sentinelIntegration'
  params: {
    ctiWorkspaceName: parameters.outputs.ctiWorkspaceName
    ctiWorkspaceId: coreInfrastructure.outputs.ctiWorkspaceId
    location: parameters.outputs.location
    enableSentinelIntegration: true
    enableAnalyticsRules: true
    enableHuntingQueries: true
    existingSentinelWorkspaceId: ''
    tags: {
      solution: 'CentralThreatIntelligence'
      environment: 'Production'
      createdBy: 'Bicep'
      deploymentDate: utcNow('yyyy-MM-dd')
    }
  }
  dependsOn: [
    customTables
  ]
}

// Main outputs
output ctiWorkspaceId string = coreInfrastructure.outputs.ctiWorkspaceId
output ctiWorkspaceName string = parameters.outputs.ctiWorkspaceName
output keyVaultName string = parameters.outputs.keyVaultName
output managedIdentityId string = coreInfrastructure.outputs.managedIdentityId
output managedIdentityPrincipalId string = coreInfrastructure.outputs.managedIdentityPrincipalId
output taxiiConnectorName string = taxiiConnector.outputs.taxiiConnectorName
// Additional connector outputs would be added here

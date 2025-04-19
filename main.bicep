// Advanced Central Threat Intelligence (CTI) Solution
// This template deploys a comprehensive threat intelligence platform
// Version: 2.0
// Last Updated: April 2025

targetScope = 'resourceGroup'

// Parameters
@description('Location for all resources.')
param location string = resourceGroup().location

@description('Name of the Log Analytics workspace for CTI')
param ctiWorkspaceName string = 'CTI-Workspace'

@description('Enable Microsoft Defender Threat Intelligence integration')
param enableMDTI bool = true

@description('Enable Microsoft Security Copilot integration')
param enableSecurityCopilot bool = false

@description('Enable Microsoft Sentinel integration with the CTI workspace')
param enableSentinelIntegration bool = true

@description('Enable Sentinel Analytics Rules for threat intelligence')
param enableAnalyticsRules bool = true

@description('Enable Sentinel Hunting Queries for threat intelligence')
param enableHuntingQueries bool = true

@description('Microsoft Entra App ID for API authentication')
param appClientId string

@description('Microsoft Entra Tenant ID')
param tenantId string = subscription().tenantId

@description('Initial value for client secret (should be replaced post-deployment for production)')
@secure()
param clientSecret string = ''

@description('Tag values for resources')
param tags object = {
  solution: 'CentralThreatIntelligence'
  environment: 'Production'
  createdBy: 'Bicep'
  deploymentDate: utcNow('yyyy-MM-dd')
}

// Import parameters module
module parameters './parameters.bicep' = {
  name: 'parameters'
}

// Core Infrastructure
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

// Custom Tables
module customTables './custom-tables.bicep' = {
  name: 'customTables'
  params: {
    ctiWorkspaceName: ctiWorkspaceName
  }
  dependsOn: [
    coreInfrastructure
  ]
}

// API Connections
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
  dependsOn: [
    coreInfrastructure
    customTables
  ]
}

// Logic Apps
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
    dceCopilotIntegrationName: parameters.outputs.dceCopilotIntegrationName
    diagnosticSettingsRetentionDays: 30
    tags: tags
  }
  dependsOn: [
    apiConnections
  ]
}

// Sentinel Integration
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
  dependsOn: [
    customTables
  ]
}

// Main outputs
output ctiWorkspaceId string = coreInfrastructure.outputs.ctiWorkspaceId
output ctiWorkspaceName string = ctiWorkspaceName
output keyVaultName string = parameters.outputs.keyVaultName
output managedIdentityId string = coreInfrastructure.outputs.managedIdentityId
output managedIdentityPrincipalId string = coreInfrastructure.outputs.managedIdentityPrincipalId
output logicAppNames object = logicApps.outputs.logicAppNames

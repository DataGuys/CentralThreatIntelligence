// Advanced Central Threat Intelligence (CTI) Solution – v2.1
// Updated: 2025‑04‑19 – removed utcNow() from parameter default

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

param appClientId string
param tenantId string = subscription().tenantId

@secure()
param clientSecret string = ''

@description('Base set of tags applied to all resources')
param baseTags object = {
  solution: 'CentralThreatIntelligence'
  environment: 'Production'
  createdBy: 'Bicep'
}

var deploymentDate = utcNow('yyyy-MM-dd')
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

module customTables './custom-tables.bicep' = {
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
    dceCopilotIntegrationName: parameters.outputs.dceCopilotIntegrationName
    diagnosticSettingsRetentionDays: 30
    tags: tags
  }
  dependsOn: [ apiConnections ]
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

output ctiWorkspaceId string = coreInfrastructure.outputs.ctiWorkspaceId
output ctiWorkspaceName string = ctiWorkspaceName
output keyVaultName string = parameters.outputs.keyVaultName
output managedIdentityId string = coreInfrastructure.outputs.managedIdentityId
output managedIdentityPrincipalId string = coreInfrastructure.outputs.managedIdentityPrincipalId
output logicAppNames object = logicApps.outputs.logicAppNames

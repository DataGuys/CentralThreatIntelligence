// Advanced Central Threat Intelligence (CTI) Solution – v2.1

targetScope = 'resourceGroup'

@description('Location for all resources.')
param location string = resourceGroup().location

@description('Name of the Log Analytics workspace for CTI')
param ctiWorkspaceName string = 'CTI-Workspace'

param enableMDTI bool = false
param enableSecurityCopilot bool = false
param enableSentinelIntegration bool = false
param enableAnalyticsRules bool = false
param enableHuntingQueries bool = false

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
  dependsOn: [ coreInfrastructure ]
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

output ctiWorkspaceId string = coreInfrastructure.outputs.ctiWorkspaceId
output ctiWorkspaceName string = ctiWorkspaceName
output keyVaultName string = parameters.outputs.keyVaultName
output managedIdentityId string = coreInfrastructure.outputs.managedIdentityId
output managedIdentityPrincipalId string = coreInfrastructure.outputs.managedIdentityPrincipalId
output logicAppNames object = logicApps.outputs.logicAppNames

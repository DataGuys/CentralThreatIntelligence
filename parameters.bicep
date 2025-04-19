@description('Location for all resources.')
param location string = resourceGroup().location

@description('Name of the Log Analytics workspace for CTI')
@minLength(4)
@maxLength(63)
param ctiWorkspaceName string = 'CTI-Workspace'

@description('Retention period in days for the CTI workspace')
@minValue(30)
@maxValue(730)
param ctiWorkspaceRetentionInDays int = 90

@description('Daily quota for Log Analytics workspace in GB')
@minValue(1)
param ctiWorkspaceDailyQuotaGb int = 5

@description('SKU for Log Analytics workspace')
@allowed([
  'PerGB2018'
  'Standard'
  'Premium'
])
param ctiWorkspaceSku string = 'PerGB2018'

@description('SKU for Logic App service plan')
@allowed([
  'WS1'  // WorkflowStandard
  'WS2'  // WorkflowStandard
  'WS3'  // WorkflowStandard
  'P1v2' // Premium
  'P2v2' // Premium
  'P3v2' // Premium
])
param logicAppSku string = 'WS1' // Default to WorkflowStandard

@description('Maximum elastic worker count for Logic App service plan')
@minValue(1)
@maxValue(20)
param maxElasticWorkerCount int = contains(logicAppSku, 'P') ? 20 : 10

@description('Enable Microsoft Sentinel integration with the CTI workspace')
param enableSentinelIntegration bool = true

@description('Resource ID of the existing Sentinel workspace (if you want to integrate with an existing Sentinel)')
param existingSentinelWorkspaceId string = ''

@description('Enable Microsoft Defender Threat Intelligence integration')
param enableMDTI bool = true

@description('Enable Microsoft Security Copilot integration')
param enableSecurityCopilot bool = false

@description('Enable Sentinel Analytics Rules for threat intelligence')
param enableAnalyticsRules bool = true

@description('Enable Sentinel Hunting Queries for threat intelligence')
param enableHuntingQueries bool = true

@description('Microsoft Entra App ID for API authentication')
param appClientId string = ''

@description('Microsoft Entra Tenant ID')
param tenantId string = subscription().tenantId

@description('URI for Microsoft Graph API')
param graphApiUrl string = 'https://graph.microsoft.com'

@description('Key Vault name for storing secrets')
@minLength(3)
@maxLength(24)
param keyVaultName string = 'kv-cti-${uniqueString(resourceGroup().id)}'

@description('Secret name for storing client secret')
param clientSecretName string = 'clientSecret'

@description('Initial value for client secret (should be replaced post-deployment for production)')
@secure()
param initialClientSecret string = ''

@description('User assigned managed identity name')
param managedIdentityName string = 'id-cti-automation'

@description('Diagnostic settings retention period in days')
@minValue(7)
@maxValue(365)
param diagnosticSettingsRetentionDays int = 30

@description('List of allowed IP addresses for Key Vault firewall')
param allowedIpAddresses array = []

@description('List of allowed subnet IDs for Key Vault firewall')
param allowedSubnetIds array = []

@description('Tag values for resources')
param tags object = {
  solution: 'CentralThreatIntelligence'
  environment: 'Production'
  createdBy: 'Bicep'
  deploymentDate: utcNow('yyyy-MM-dd')
}

// Shared variables
var securityApiBaseUrl = 'https://api.security.microsoft.com'
var logicAppServicePlanName = 'CTI-LogicApp-ServicePlan'
var logAnalyticsDataCollectorConnectionName = 'azureloganalyticsdatacollector'
var logAnalyticsQueryConnectionName = 'azuremonitorlogs'
var microsoftGraphConnectionName = 'microsoftgraph'
var dceCopilotIntegrationName = enableSecurityCopilot ? 'DCE-CTI-SecurityCopilot' : ''
var dceNameForCopilot = enableSecurityCopilot ? 'dce-${ctiWorkspaceName}-copilot' : ''

// Output the parameters and variables
output location string = location
output ctiWorkspaceName string = ctiWorkspaceName
output logicAppServicePlanName string = logicAppServicePlanName
output keyVaultName string = keyVaultName
output managedIdentityName string = managedIdentityName
output securityApiBaseUrl string = securityApiBaseUrl
output logAnalyticsDataCollectorConnectionName string = logAnalyticsDataCollectorConnectionName
output logAnalyticsQueryConnectionName string = logAnalyticsQueryConnectionName
output microsoftGraphConnectionName string = microsoftGraphConnectionName
output dceCopilotIntegrationName string = dceCopilotIntegrationName
output dceNameForCopilot string = dceNameForCopilot

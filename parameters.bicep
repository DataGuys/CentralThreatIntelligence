@description('Location for all resources.')
param location string = resourceGroup().location

@description('Name of the Log Analytics workspace for CTI')
@minLength(4)
@maxLength(63)
param ctiWorkspaceName string = 'CTI-Workspace'

@description('SKU for Log Analytics workspace')
@allowed([
  'PerGB2018'
  'Standard'
  'Premium'
])
param ctiWorkspaceSku string = 'PerGB2018'

@description('Enable Microsoft Security Copilot integration')
param enableSecurityCopilot bool = false

@description('Key Vault name for storing secrets')
@minLength(3)
@maxLength(24)
param keyVaultName string = 'kv-cti-${uniqueString(resourceGroup().id)}'

@description('User assigned managed identity name')
param managedIdentityName string = 'id-cti-automation'

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
output ctiWorkspaceSku string = ctiWorkspaceSku
output logicAppServicePlanName string = logicAppServicePlanName
output keyVaultName string = keyVaultName
output managedIdentityName string = managedIdentityName
output securityApiBaseUrl string = securityApiBaseUrl
output logAnalyticsDataCollectorConnectionName string = logAnalyticsDataCollectorConnectionName
output logAnalyticsQueryConnectionName string = logAnalyticsQueryConnectionName
output microsoftGraphConnectionName string = microsoftGraphConnectionName
output dceCopilotIntegrationName string = dceCopilotIntegrationName
output dceNameForCopilot string = dceNameForCopilot

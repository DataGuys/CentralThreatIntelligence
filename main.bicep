// Advanced Central Threat Intelligence (CTI) Solution
// This template deploys a comprehensive threat intelligence platform that integrates with Microsoft Security products
// Version: 2.0
// Last Updated: April 2025

targetScope = 'resourceGroup'

// ============================================
// PARAMETERS
// ============================================

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

// ============================================
// VARIABLES
// ============================================

var logicAppServicePlanName = 'CTI-LogicApp-ServicePlan'
var taxiiConnectorLogicAppName = 'CTI-TAXII2-Connector'
var defenderEndpointConnectorName = 'CTI-DefenderXDR-Connector'
var mdtiConnectorLogicAppName = 'CTI-MDTI-Connector'
var entraIDConnectorLogicAppName = 'CTI-EntraID-Connector'
var exoConnectorLogicAppName = 'CTI-ExchangeOnline-Connector'
var securityCopilotConnectorName = 'CTI-SecurityCopilot-Connector'
var housekeepingLogicAppName = 'CTI-Housekeeping'
var threatFeedSyncLogicAppName = 'CTI-ThreatFeedSync'
var logAnalyticsDataCollectorConnectionName = 'azureloganalyticsdatacollector'
var logAnalyticsQueryConnectionName = 'azuremonitorlogs'
var microsoftGraphConnectionName = 'microsoftgraph'
var securityApiBaseUrl = 'https://api.security.microsoft.com'
var dceCopilotIntegrationName = enableSecurityCopilot ? 'DCE-CTI-SecurityCopilot' : ''

// Table schemas with modern structure aligned with STIX 2.1
var tables = [
  {
    name: 'CTI_IPIndicators_CL'
    columns: [
      { name: 'IPAddress_s', type: 'string' }
      { name: 'ConfidenceScore_d', type: 'double' }
      { name: 'SourceFeed_s', type: 'string' }
      { name: 'FirstSeen_t', type: 'datetime' }
      { name: 'LastSeen_t', type: 'datetime' }
      { name: 'ExpirationDateTime_t', type: 'datetime' }
      { name: 'ThreatType_s', type: 'string' }
      { name: 'ThreatCategory_s', type: 'string' }
      { name: 'TLP_s', type: 'string' }
      { name: 'GeoLocation_s', type: 'string' }
      { name: 'ASN_s', type: 'string' }
      { name: 'Tags_s', type: 'string' }
      { name: 'Description_s', type: 'string' }
      { name: 'Action_s', type: 'string' }
      { name: 'ReportedBy_s', type: 'string' }
      { name: 'DistributionTargets_s', type: 'string' }
      { name: 'ThreatActorName_s', type: 'string' }
      { name: 'CampaignName_s', type: 'string' }
      { name: 'Active_b', type: 'bool' }
      { name: 'IndicatorId_g', type: 'guid' }
    ]
  }
  {
    name: 'CTI_FileHashIndicators_CL'
    columns: [
      { name: 'SHA256_s', type: 'string' }
      { name: 'MD5_s', type: 'string' }
      { name: 'SHA1_s', type: 'string' }
      { name: 'ConfidenceScore_d', type: 'double' }
      { name: 'SourceFeed_s', type: 'string' }
      { name: 'FirstSeen_t', type: 'datetime' }
      { name: 'LastSeen_t', type: 'datetime' }
      { name: 'ExpirationDateTime_t', type: 'datetime' }
      { name: 'MalwareFamily_s', type: 'string' }
      { name: 'ThreatType_s', type: 'string' }
      { name: 'ThreatCategory_s', type: 'string' }
      { name: 'TLP_s', type: 'string' }
      { name: 'Tags_s', type: 'string' }
      { name: 'Description_s', type: 'string' }
      { name: 'Action_s', type: 'string' }
      { name: 'DistributionTargets_s', type: 'string' }
      { name: 'ReportedBy_s', type: 'string' }
      { name: 'ThreatActorName_s', type: 'string' }
      { name: 'CampaignName_s', type: 'string' }
      { name: 'Active_b', type: 'bool' }
      { name: 'IndicatorId_g', type: 'guid' }
    ]
  }
  {
    name: 'CTI_DomainIndicators_CL'
    columns: [
      { name: 'Domain_s', type: 'string' }
      { name: 'ConfidenceScore_d', type: 'double' }
      { name: 'SourceFeed_s', type: 'string' }
      { name: 'FirstSeen_t', type: 'datetime' }
      { name: 'LastSeen_t', type: 'datetime' }
      { name: 'ExpirationDateTime_t', type: 'datetime' }
      { name: 'ThreatType_s', type: 'string' }
      { name: 'ThreatCategory_s', type: 'string' }
      { name: 'TLP_s', type: 'string' }
      { name: 'Tags_s', type: 'string' }
      { name: 'Description_s', type: 'string' }
      { name: 'Action_s', type: 'string' }
      { name: 'DistributionTargets_s', type: 'string' }
      { name: 'ReportedBy_s', type: 'string' }
      { name: 'ThreatActorName_s', type: 'string' }
      { name: 'CampaignName_s', type: 'string' }
      { name: 'Active_b', type: 'bool' }
      { name: 'IndicatorId_g', type: 'guid' }
    ]
  }
  {
    name: 'CTI_MutexIndicators_CL'
    columns: [
      { name: 'MutexName_s', type: 'string' }
      { name: 'ConfidenceScore_d', type: 'double' }
      { name: 'SourceFeed_s', type: 'string' }
      { name: 'FirstSeen_t', type: 'datetime' }
      { name: 'LastSeen_t', type: 'datetime' }
      { name: 'ExpirationDateTime_t', type: 'datetime' }
      { name: 'MalwareFamily_s', type: 'string' }
      { name: 'ThreatType_s', type: 'string' }
      { name: 'ThreatCategory_s', type: 'string' }
      { name: 'TLP_s', type: 'string' }
      { name: 'Tags_s', type: 'string' }
      { name: 'Description_s', type: 'string' }
      { name: 'Action_s', type: 'string' }
      { name: 'DistributionTargets_s', type: 'string' }
      { name: 'ReportedBy_s', type: 'string' }
      { name: 'ThreatActorName_s', type: 'string' }
      { name: 'CampaignName_s', type: 'string' }
      { name: 'Active_b', type: 'bool' }
      { name: 'IndicatorId_g', type: 'guid' }
    ]
  }
  {
    name: 'CTI_RegistryIndicators_CL'
    columns: [
      { name: 'RegistryPath_s', type: 'string' }
      { name: 'RegistryKey_s', type: 'string' }
      { name: 'RegistryValue_s', type: 'string' }
      { name: 'ConfidenceScore_d', type: 'double' }
      { name: 'SourceFeed_s', type: 'string' }
      { name: 'FirstSeen_t', type: 'datetime' }
      { name: 'LastSeen_t', type: 'datetime' }
      { name: 'ExpirationDateTime_t', type: 'datetime' }
      { name: 'MalwareFamily_s', type: 'string' }
      { name: 'ThreatType_s', type: 'string' }
      { name: 'ThreatCategory_s', type: 'string' }
      { name: 'TLP_s', type: 'string' }
      { name: 'Tags_s', type: 'string' }
      { name: 'Description_s', type: 'string' }
      { name: 'Action_s', type: 'string' }
      { name: 'DistributionTargets_s', type: 'string' }
      { name: 'ReportedBy_s', type: 'string' }
      { name: 'ThreatActorName_s', type: 'string' }
      { name: 'CampaignName_s', type: 'string' }
      { name: 'Active_b', type: 'bool' }
      { name: 'IndicatorId_g', type: 'guid' }
    ]
  }
  {
    name: 'CTI_URLIndicators_CL'
    columns: [
      { name: 'URL_s', type: 'string' }
      { name: 'ConfidenceScore_d', type: 'double' }
      { name: 'SourceFeed_s', type: 'string' }
      { name: 'FirstSeen_t', type: 'datetime' }
      { name: 'LastSeen_t', type: 'datetime' }
      { name: 'ExpirationDateTime_t', type: 'datetime' }
      { name: 'ThreatType_s', type: 'string' }
      { name: 'ThreatCategory_s', type: 'string' }
      { name: 'TLP_s', type: 'string' }
      { name: 'Tags_s', type: 'string' }
      { name: 'Description_s', type: 'string' }
      { name: 'Action_s', type: 'string' }
      { name: 'DistributionTargets_s', type: 'string' }
      { name: 'ReportedBy_s', type: 'string' }
      { name: 'ThreatActorName_s', type: 'string' }
      { name: 'CampaignName_s', type: 'string' }
      { name: 'Active_b', type: 'bool' }
      { name: 'IndicatorId_g', type: 'guid' }
    ]
  }
  {
    name: 'CTI_EmailIndicators_CL'
    columns: [
      { name: 'EmailAddress_s', type: 'string' }
      { name: 'ConfidenceScore_d', type: 'double' }
      { name: 'SourceFeed_s', type: 'string' }
      { name: 'FirstSeen_t', type: 'datetime' }
      { name: 'LastSeen_t', type: 'datetime' }
      { name: 'ExpirationDateTime_t', type: 'datetime' }
      { name: 'ThreatType_s', type: 'string' }
      { name: 'ThreatCategory_s', type: 'string' }
      { name: 'TLP_s', type: 'string' }
      { name: 'Tags_s', type: 'string' }
      { name: 'Description_s', type: 'string' }
      { name: 'Action_s', type: 'string' }
      { name: 'DistributionTargets_s', type: 'string' }
      { name: 'ReportedBy_s', type: 'string' }
      { name: 'ThreatActorName_s', type: 'string' }
      { name: 'CampaignName_s', type: 'string' }
      { name: 'Active_b', type: 'bool' }
      { name: 'IndicatorId_g', type: 'guid' }
    ]
  }
  {
    name: 'CTI_ThreatIntelIndicator_CL'
    columns: [
      { name: 'Type_s', type: 'string' }
      { name: 'Value_s', type: 'string' }
      { name: 'Pattern_s', type: 'string' }
      { name: 'PatternType_s', type: 'string' }
      { name: 'Name_s', type: 'string' }
      { name: 'Description_s', type: 'string' }
      { name: 'Action_s', type: 'string' }
      { name: 'Confidence_d', type: 'double' }
      { name: 'ValidFrom_t', type: 'datetime' }
      { name: 'ValidUntil_t', type: 'datetime' }
      { name: 'CreatedTimeUtc_t', type: 'datetime' }
      { name: 'UpdatedTimeUtc_t', type: 'datetime' }
      { name: 'Source_s', type: 'string' }
      { name: 'SourceRef_s', type: 'string' }
      { name: 'KillChainPhases_s', type: 'string' }
      { name: 'Labels_s', type: 'string' }
      { name: 'ThreatType_s', type: 'string' }
      { name: 'TLP_s', type: 'string' }
      { name: 'DistributionTargets_s', type: 'string' }
      { name: 'ThreatActorName_s', type: 'string' }
      { name: 'CampaignName_s', type: 'string' }
      { name: 'Active_b', type: 'bool' }
      { name: 'ObjectId_g', type: 'guid' }
      { name: 'IndicatorId_g', type: 'guid' }
    ]
  }
  {
    name: 'CTI_ThreatIntelObjects_CL'
    columns: [
      { name: 'ObjectId_g', type: 'guid' }
      { name: 'Type_s', type: 'string' }
      { name: 'CreatedTimeUtc_t', type: 'datetime' }
      { name: 'UpdatedTimeUtc_t', type: 'datetime' }
      { name: 'SourceId_s', type: 'string' }
      { name: 'Source_s', type: 'string' }
      { name: 'Name_s', type: 'string' }
      { name: 'Description_s', type: 'string' }
      { name: 'JsonData_s', type: 'string' }
      { name: 'Relations_s', type: 'string' }
      { name: 'TLP_s', type: 'string' }
      { name: 'MitreAttackId_s', type: 'string' }
      { name: 'ThreatActorType_s', type: 'string' }
      { name: 'TargetedCountries_s', type: 'string' }
      { name: 'TargetedIndustries_s', type: 'string' }
      { name: 'MotivationContext_s', type: 'string' }
      { name: 'Active_b', type: 'bool' }
    ]
  }
  {
    name: 'CTI_TransactionLog_CL'
    columns: [
      { name: 'IndicatorType_s', type: 'string' }
      { name: 'IndicatorValue_s', type: 'string' }
      { name: 'Action_s', type: 'string' }
      { name: 'TargetSystem_s', type: 'string' }
      { name: 'Status_s', type: 'string' }
      { name: 'ErrorMessage_s', type: 'string' }
      { name: 'ErrorCode_s', type: 'string' }
      { name: 'ErrorDetails_s', type: 'string' }
      { name: 'Timestamp_t', type: 'datetime' }
      { name: 'ActionId_g', type: 'guid' }
      { name: 'CorrelationId_g', type: 'guid' }
      { name: 'IndicatorId_g', type: 'guid' }
      { name: 'RunbookName_s', type: 'string' }
      { name: 'TriggerSource_s', type: 'string' }
      { name: 'UserId_s', type: 'string' }
      { name: 'UserName_s', type: 'string' }
    ]
  }
  {
    name: 'CTI_IntelligenceFeeds_CL'
    columns: [
      { name: 'FeedId_g', type: 'guid' }
      { name: 'FeedName_s', type: 'string' }
      { name: 'FeedType_s', type: 'string' }
      { name: 'FeedURL_s', type: 'string' }
      { name: 'CollectionId_s', type: 'string' }
      { name: 'EncodedCredentials_s', type: 'string' }
      { name: 'Description_s', type: 'string' }
      { name: 'Category_s', type: 'string' }
      { name: 'TLP_s', type: 'string' }
      { name: 'ConfidenceScore_d', type: 'double' }
      { name: 'LastUpdated_t', type: 'datetime' }
      { name: 'UpdateFrequency_s', type: 'string' }
      { name: 'Status_s', type: 'string' }
      { name: 'IndicatorCount_d', type: 'double' }
      { name: 'ConfigData_s', type: 'string' }
      { name: 'ContentMapping_s', type: 'string' }
      { name: 'Active_b', type: 'bool' }
    ]
  }
  {
    name: 'CTI_AnalyticsFeedback_CL'
    columns: [
      { name: 'FeedbackId_g', type: 'guid' }
      { name: 'IndicatorId_g', type: 'guid' }
      { name: 'IndicatorValue_s', type: 'string' }
      { name: 'IndicatorType_s', type: 'string' }
      { name: 'MatchType_s', type: 'string' }
      { name: 'MatchedValue_s', type: 'string' }
      { name: 'IncidentId_s', type: 'string' }
      { name: 'AlertId_s', type: 'string' }
      { name: 'SourceSystem_s', type: 'string' }
      { name: 'Timestamp_t', type: 'datetime' }
      { name: 'FeedbackType_s', type: 'string' }
      { name: 'Comments_s', type: 'string' }
      { name: 'SubmittedBy_s', type: 'string' }
      { name: 'ConfidenceAdjustment_d', type: 'double' }
    ]
  }
  {
    name: 'CTI_TacticsTechniques_CL'
    columns: [
      { name: 'IndicatorId_g', type: 'guid' }
      { name: 'IndicatorValue_s', type: 'string' }
      { name: 'TacticId_s', type: 'string' }
      { name: 'TacticName_s', type: 'string' }
      { name: 'TechniqueId_s', type: 'string' }
      { name: 'TechniqueName_s', type: 'string' }
      { name: 'SubTechniqueId_s', type: 'string' }
      { name: 'SubTechniqueName_s', type: 'string' }
      { name: 'TacticURL_s', type: 'string' }
      { name: 'TechniqueURL_s', type: 'string' }
      { name: 'MitreVersion_s', type: 'string' }
      { name: 'Timestamp_t', type: 'datetime' }
    ]
  }
  {
    name: 'CTI_ThreatActors_CL'
    columns: [
      { name: 'ActorId_g', type: 'guid' }
      { name: 'Name_s', type: 'string' }
      { name: 'Aliases_s', type: 'string' }
      { name: 'Description_s', type: 'string' }
      { name: 'FirstSeen_t', type: 'datetime' }
      { name: 'LastSeen_t', type: 'datetime' }
      { name: 'Motivations_s', type: 'string' }
      { name: 'ThreatTypes_s', type: 'string' }
      { name: 'TargetedCountries_s', type: 'string' }
      { name: 'TargetedIndustries_s', type: 'string' }
      { name: 'SourceFeed_s', type: 'string' }
      { name: 'TLP_s', type: 'string' }
      { name: 'Confidence_d', type: 'double' }
      { name: 'TechniquesUsed_s', type: 'string' }
      { name: 'RelatedActors_s', type: 'string' }
      { name: 'Active_b', type: 'bool' }
    ]
  }
  {
    name: 'CTI_Campaigns_CL'
    columns: [
      { name: 'CampaignId_g', type: 'guid' }
      { name: 'Name_s', type: 'string' }
      { name: 'Description_s', type: 'string' }
      { name: 'StartDate_t', type: 'datetime' }
      { name: 'EndDate_t', type: 'datetime' }
      { name: 'ThreatActorIds_s', type: 'string' }
      { name: 'TargetedCountries_s', type: 'string' }
      { name: 'TargetedIndustries_s', type: 'string' }
      { name: 'TargetedTechnologies_s', type: 'string' }
      { name: 'TTP_s', type: 'string' }
      { name: 'IndicatorIds_s', type: 'string' }
      { name: 'SourceFeed_s', type: 'string' }
      { name: 'TLP_s', type: 'string' }
      { name: 'Confidence_d', type: 'double' }
      { name: 'RelatedCampaigns_s', type: 'string' }
      { name: 'Active_b', type: 'bool' }
    ]
  }
]

// Data Collection Endpoint name for Security Copilot integration
var dceNameForCopilot = enableSecurityCopilot ? 'dce-${ctiWorkspaceName}-copilot' : ''

// ============================================
// RESOURCES
// ============================================

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

// Create custom tables
resource customTables 'Microsoft.OperationalInsights/workspaces/tables@2022-10-01' = [for table in tables: {
  parent: ctiWorkspace
  name: table.name
  properties: {
    schema: {
      name: table.name
      columns: table.columns
    }
  }
}]

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

// Diagnostic settings for Logic App Service Plan
resource logicAppServicePlanDiagnostics 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = {
  scope: logicAppServicePlan
  name: 'diagnostics'
  properties: {
    workspaceId: ctiWorkspace.id
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
  dependsOn: [
    customTables
  ]
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
      token:TenantId: tenantId
      token:clientId: appClientId
      token:clientSecret: clientSecretValue.properties.value
      token:grantType: 'client_credentials'
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
      token:TenantId: tenantId
      token:clientId: appClientId
      token:clientSecret: clientSecretValue.properties.value
      token:grantType: 'client_credentials'
    }
  }
  dependsOn: [
    clientSecretValue
    keyVaultRoleAssignment
  ]
}

// Logic App for TAXII feed ingestion
resource taxiiConnectorLogicApp 'Microsoft.Logic/workflows@2019-05-01' = {
  name: taxiiConnectorLogicAppName
  location: location
  tags: tags
  identity: {
    type: 'UserAssigned'
    userAssignedIdentities: {
      '${managedIdentity.id}': {}
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
        For_each_TAXII_feed: {
          foreach: '@body(\'Get_TAXII_feeds\')'
          actions: {
            Get_TAXII_objects: {
              runAfter: {}
              type: 'Http'
              inputs: {
                method: 'GET'
                uri: '@{items(\'For_each_TAXII_feed\').FeedURL_s}/collections/@{items(\'For_each_TAXII_feed\').CollectionId_s}/objects'
                headers: {
                  Accept: 'application/vnd.oasis.stix+json; version=2.1'
                  'Content-Type': 'application/json'
                  Authorization: 'Basic @{items(\'For_each_TAXII_feed\').EncodedCredentials_s}'
                }
                retryPolicy: {
                  type: 'fixed'
                  count: 3
                  interval: 'PT30S'
                }
              }
            }
            Parse_STIX_response: {
              runAfter: {
                Get_TAXII_objects: [
                  'Succeeded'
                ]
              }
              type: 'ParseJson'
              inputs: {
                content: '@body(\'Get_TAXII_objects\')'
                schema: {
                  type: 'object'
                  properties: {
                    more: {
                      type: 'boolean'
                    }
                    objects: {
                      type: 'array'
                      items: {
                        type: 'object'
                        properties: {}
                      }
                    }
                  }
                }
              }
            }
            Process_STIX_objects: {
              foreach: '@body(\'Parse_STIX_response\').objects'
              actions: {
                Condition_Check_Object_Type: {
                  actions: {
                    Process_Indicator_IP: {
                      actions: {
                        Parse_IP_Indicator: {
                          runAfter: {}
                          type: 'Compose'
                          inputs: '@items(\'Process_STIX_objects\').pattern'
                        }
                        Send_IP_to_Log_Analytics: {
                          runAfter: {
                            Parse_IP_Indicator: [
                              'Succeeded'
                            ]
                          }
                          type: 'ApiConnection'
                          inputs: {
                            body: {
                              IPAddress_s: '@replace(replace(outputs(\'Parse_IP_Indicator\'),\'ipv4-addr:value = \\\'\',\'\'),\'\\\'\',\'\')'
                              ObjectId_g: '@{items(\'Process_STIX_objects\').id}'
                              IndicatorId_g: '@{guid()}'
                              ConfidenceScore_d: '@if(equals(items(\'Process_STIX_objects\')?[\'confidence\'], null), 50, items(\'Process_STIX_objects\').confidence)'
                              SourceFeed_s: '@{items(\'For_each_TAXII_feed\').FeedName_s}'
                              FirstSeen_t: '@{items(\'Process_STIX_objects\').created}'
                              LastSeen_t: '@{items(\'Process_STIX_objects\').modified}'
                              ExpirationDateTime_t: '@{items(\'Process_STIX_objects\').valid_until}'
                              ThreatType_s: '@{if(contains(items(\'Process_STIX_objects\'), \'labels\'), join(items(\'Process_STIX_objects\').labels, \', \'), \'Unknown\')}'
                              Description_s: '@{items(\'Process_STIX_objects\').description}'
                              TLP_s: '@{if(contains(items(\'Process_STIX_objects\').object_marking_refs[0], \'tlp\'), last(split(items(\'Process_STIX_objects\').object_marking_refs[0], \':\' )), \'TLP:AMBER\')}'
                              Action_s: 'Alert'
                              DistributionTargets_s: 'Microsoft Sentinel'
                              Active_b: '@{if(equals(items(\'Process_STIX_objects\')?[\'revoked\'], true), false, true)}'
                            }
                            host: {
                              connection: {
                                name: '@parameters(\'$connections\')[\'azureloganalyticsdatacollector\'][\'connectionId\']'
                              }
                            }
                            method: 'post'
                            path: '/api/logs'
                            queries: {
                              logType: 'CTI_IPIndicators_CL'
                            }
                          }
                        }
                        Send_to_ThreatIntelIndicator: {
                          runAfter: {
                            Parse_IP_Indicator: [
                              'Succeeded'
                            ]
                          }
                          type: 'ApiConnection'
                          inputs: {
                            body: {
                              Type_s: 'ipv4-addr'
                              Value_s: '@replace(replace(outputs(\'Parse_IP_Indicator\'),\'ipv4-addr:value = \\\'\',\'\'),\'\\\'\',\'\')'
                              Pattern_s: '@{items(\'Process_STIX_objects\').pattern}'
                              PatternType_s: '@{items(\'Process_STIX_objects\').pattern_type}'
                              Name_s: '@{if(contains(items(\'Process_STIX_objects\'), \'name\'), items(\'Process_STIX_objects\').name, \'IP Indicator\')}'
                              Description_s: '@{items(\'Process_STIX_objects\').description}'
                              Action_s: 'alert'
                              Confidence_d: '@if(equals(items(\'Process_STIX_objects\')?[\'confidence\'], null), 50, items(\'Process_STIX_objects\').confidence)'
                              ValidFrom_t: '@{items(\'Process_STIX_objects\').valid_from}'
                              ValidUntil_t: '@{items(\'Process_STIX_objects\').valid_until}'
                              CreatedTimeUtc_t: '@{items(\'Process_STIX_objects\').created}'
                              UpdatedTimeUtc_t: '@{items(\'Process_STIX_objects\').modified}'
                              Source_s: '@{items(\'For_each_TAXII_feed\').FeedName_s}'
                              SourceRef_s: '@{items(\'For_each_TAXII_feed\').FeedURL_s}'
                              KillChainPhases_s: '@{if(contains(items(\'Process_STIX_objects\'), \'kill_chain_phases\'), string(items(\'Process_STIX_objects\').kill_chain_phases), \'\')}'
                              Labels_s: '@{if(contains(items(\'Process_STIX_objects\'), \'labels\'), join(items(\'Process_STIX_objects\').labels, \', \'), \'\')}'
                              ThreatType_s: '@{if(contains(items(\'Process_STIX_objects\'), \'labels\'), join(items(\'Process_STIX_objects\').labels, \', \'), \'Unknown\')}'
                              TLP_s: '@{if(contains(items(\'Process_STIX_objects\').object_marking_refs[0], \'tlp\'), last(split(items(\'Process_STIX_objects\').object_marking_refs[0], \':\' )), \'TLP:AMBER\')}'
                              DistributionTargets_s: 'Microsoft Sentinel'
                              Active_b: '@{if(equals(items(\'Process_STIX_objects\')?[\'revoked\'], true), false, true)}'
                              ObjectId_g: '@{items(\'Process_STIX_objects\').id}'
                              IndicatorId_g: '@{guid()}'
                            }
                            host: {
                              connection: {
                                name: '@parameters(\'$connections\')[\'azureloganalyticsdatacollector\'][\'connectionId\']'
                              }
                            }
                            method: 'post'
                            path: '/api/logs'
                            queries: {
                              logType: 'CTI_ThreatIntelIndicator_CL'
                            }
                          }
                        }
                      }
                      runAfter: {}
                      expression: {
                        and: [
                          {
                            equals: [
                              '@items(\'Process_STIX_objects\').type'
                              'indicator'
                            ]
                          }
                          {
                            contains: [
                              '@items(\'Process_STIX_objects\').pattern'
                              'ipv4-addr'
                            ]
                          }
                        ]
                      }
                      type: 'If'
                    }
                    Process_Indicator_Domain: {
                      actions: {
                        Parse_Domain_Indicator: {
                          runAfter: {}
                          type: 'Compose'
                          inputs: '@items(\'Process_STIX_objects\').pattern'
                        }
                        Send_Domain_to_Log_Analytics: {
                          runAfter: {
                            Parse_Domain_Indicator: [
                              'Succeeded'
                            ]
                          }
                          type: 'ApiConnection'
                          inputs: {
                            body: {
                              Domain_s: '@replace(replace(outputs(\'Parse_Domain_Indicator\'),\'domain-name:value = \\\'\',\'\'),\'\\\'\',\'\')'
                              ObjectId_g: '@{items(\'Process_STIX_objects\').id}'
                              IndicatorId_g: '@{guid()}'
                              ConfidenceScore_d: '@if(equals(items(\'Process_STIX_objects\')?[\'confidence\'], null), 50, items(\'Process_STIX_objects\').confidence)'
                              SourceFeed_s: '@{items(\'For_each_TAXII_feed\').FeedName_s}'
                              FirstSeen_t: '@{items(\'Process_STIX_objects\').created}'
                              LastSeen_t: '@{items(\'Process_STIX_objects\').modified}'
                              ExpirationDateTime_t: '@{items(\'Process_STIX_objects\').valid_until}'
                              ThreatType_s: '@{if(contains(items(\'Process_STIX_objects\'), \'labels\'), join(items(\'Process_STIX_objects\').labels, \', \'), \'Unknown\')}'
                              Description_s: '@{items(\'Process_STIX_objects\').description}'
                              TLP_s: '@{if(contains(items(\'Process_STIX_objects\').object_marking_refs[0], \'tlp\'), last(split(items(\'Process_STIX_objects\').object_marking_refs[0], \':\' )), \'TLP:AMBER\')}'
                              Action_s: 'Alert'
                              DistributionTargets_s: 'Microsoft Sentinel'
                              Active_b: '@{if(equals(items(\'Process_STIX_objects\')?[\'revoked\'], true), false, true)}'
                            }
                            host: {
                              connection: {
                                name: '@parameters(\'$connections\')[\'azureloganalyticsdatacollector\'][\'connectionId\']'
                              }
                            }
                            method: 'post'
                            path: '/api/logs'
                            queries: {
                              logType: 'CTI_DomainIndicators_CL'
                            }
                          }
                        }
                        Send_to_ThreatIntelIndicator_Domain: {
                          runAfter: {
                            Parse_Domain_Indicator: [
                              'Succeeded'
                            ]
                          }
                          type: 'ApiConnection'
                          inputs: {
                            body: {
                              Type_s: 'domain-name'
                              Value_s: '@replace(replace(outputs(\'Parse_Domain_Indicator\'),\'domain-name:value = \\\'\',\'\'),\'\\\'\',\'\')'
                              Pattern_s: '@{items(\'Process_STIX_objects\').pattern}'
                              PatternType_s: '@{items(\'Process_STIX_objects\').pattern_type}'
                              Name_s: '@{if(contains(items(\'Process_STIX_objects\'), \'name\'), items(\'Process_STIX_objects\').name, \'Domain Indicator\')}'
                              Description_s: '@{items(\'Process_STIX_objects\').description}'
                              Action_s: 'alert'
                              Confidence_d: '@if(equals(items(\'Process_STIX_objects\')?[\'confidence\'], null), 50, items(\'Process_STIX_objects\').confidence)'
                              ValidFrom_t: '@{items(\'Process_STIX_objects\').valid_from}'
                              ValidUntil_t: '@{items(\'Process_STIX_objects\').valid_until}'
                              CreatedTimeUtc_t: '@{items(\'Process_STIX_objects\').created}'
                              UpdatedTimeUtc_t: '@{items(\'Process_STIX_objects\').modified}'
                              Source_s: '@{items(\'For_each_TAXII_feed\').FeedName_s}'
                              SourceRef_s: '@{items(\'For_each_TAXII_feed\').FeedURL_s}'
                              KillChainPhases_s: '@{if(contains(items(\'Process_STIX_objects\'), \'kill_chain_phases\'), string(items(\'Process_STIX_objects\').kill_chain_phases), \'\')}'
                              Labels_s: '@{if(contains(items(\'Process_STIX_objects\'), \'labels\'), join(items(\'Process_STIX_objects\').labels, \', \'), \'\')}'
                              ThreatType_s: '@{if(contains(items(\'Process_STIX_objects\'), \'labels\'), join(items(\'Process_STIX_objects\').labels, \', \'), \'Unknown\')}'
                              TLP_s: '@{if(contains(items(\'Process_STIX_objects\').object_marking_refs[0], \'tlp\'), last(split(items(\'Process_STIX_objects\').object_marking_refs[0], \':\' )), \'TLP:AMBER\')}'
                              DistributionTargets_s: 'Microsoft Sentinel'
                              Active_b: '@{if(equals(items(\'Process_STIX_objects\')?[\'revoked\'], true), false, true)}'
                              ObjectId_g: '@{items(\'Process_STIX_objects\').id}'
                              IndicatorId_g: '@{guid()}'
                            }
                            host: {
                              connection: {
                                name: '@parameters(\'$connections\')[\'azureloganalyticsdatacollector\'][\'connectionId\']'
                              }
                            }
                            method: 'post'
                            path: '/api/logs'
                            queries: {
                              logType: 'CTI_ThreatIntelIndicator_CL'
                            }
                          }
                        }
                      }
                      runAfter: {
                        Process_Indicator_IP: [
                          'Succeeded'
                        ]
                      }
                      expression: {
                        and: [
                          {
                            equals: [
                              '@items(\'Process_STIX_objects\').type'
                              'indicator'
                            ]
                          }
                          {
                            contains: [
                              '@items(\'Process_STIX_objects\').pattern'
                              'domain-name'
                            ]
                          }
                        ]
                      }
                      type: 'If'
                    }
                    Process_Indicator_URL: {
                      actions: {
                        Parse_URL_Indicator: {
                          runAfter: {}
                          type: 'Compose'
                          inputs: '@items(\'Process_STIX_objects\').pattern'
                        }
                        Send_URL_to_Log_Analytics: {
                          runAfter: {
                            Parse_URL_Indicator: [
                              'Succeeded'
                            ]
                          }
                          type: 'ApiConnection'
                          inputs: {
                            body: {
                              URL_s: '@replace(replace(outputs(\'Parse_URL_Indicator\'),\'url:value = \\\'\',\'\'),\'\\\'\',\'\')'
                              ObjectId_g: '@{items(\'Process_STIX_objects\').id}'
                              IndicatorId_g: '@{guid()}'
                              ConfidenceScore_d: '@if(equals(items(\'Process_STIX_objects\')?[\'confidence\'], null), 50, items(\'Process_STIX_objects\').confidence)'
                              SourceFeed_s: '@{items(\'For_each_TAXII_feed\').FeedName_s}'
                              FirstSeen_t: '@{items(\'Process_STIX_objects\').created}'
                              LastSeen_t: '@{items(\'Process_STIX_objects\').modified}'
                              ExpirationDateTime_t: '@{items(\'Process_STIX_objects\').valid_until}'
                              ThreatType_s: '@{if(contains(items(\'Process_STIX_objects\'), \'labels\'), join(items(\'Process_STIX_objects\').labels, \', \'), \'Unknown\')}'
                              Description_s: '@{items(\'Process_STIX_objects\').description}'
                              TLP_s: '@{if(contains(items(\'Process_STIX_objects\').object_marking_refs[0], \'tlp\'), last(split(items(\'Process_STIX_objects\').object_marking_refs[0], \':\' )), \'TLP:AMBER\')}'
                              Action_s: 'Alert'
                              DistributionTargets_s: 'Microsoft Sentinel'
                              Active_b: '@{if(equals(items(\'Process_STIX_objects\')?[\'revoked\'], true), false, true)}'
                            }
                            host: {
                              connection: {
                                name: '@parameters(\'$connections\')[\'azureloganalyticsdatacollector\'][\'connectionId\']'
                              }
                            }
                            method: 'post'
                            path: '/api/logs'
                            queries: {
                              logType: 'CTI_URLIndicators_CL'
                            }
                          }
                        }
                        Send_to_ThreatIntelIndicator_URL: {
                          runAfter: {
                            Parse_URL_Indicator: [
                              'Succeeded'
                            ]
                          }
                          type: 'ApiConnection'
                          inputs: {
                            body: {
                              Type_s: 'url'
                              Value_s: '@replace(replace(outputs(\'Parse_URL_Indicator\'),\'url:value = \\\'\',\'\'),\'\\\'\',\'\')'
                              Pattern_s: '@{items(\'Process_STIX_objects\').pattern}'
                              PatternType_s: '@{items(\'Process_STIX_objects\').pattern_type}'
                              Name_s: '@{if(contains(items(\'Process_STIX_objects\'), \'name\'), items(\'Process_STIX_objects\').name, \'URL Indicator\')}'
                              Description_s: '@{items(\'Process_STIX_objects\').description}'
                              Action_s: 'alert'
                              Confidence_d: '@if(equals(items(\'Process_STIX_objects\')?[\'confidence\'], null), 50, items(\'Process_STIX_objects\').confidence)'
                              ValidFrom_t: '@{items(\'Process_STIX_objects\').valid_from}'
                              ValidUntil_t: '@{items(\'Process_STIX_objects\').valid_until}'
                              CreatedTimeUtc_t: '@{items(\'Process_STIX_objects\').created}'
                              UpdatedTimeUtc_t: '@{items(\'Process_STIX_objects\').modified}'
                              Source_s: '@{items(\'For_each_TAXII_feed\').FeedName_s}'
                              SourceRef_s: '@{items(\'For_each_TAXII_feed\').FeedURL_s}'
                              KillChainPhases_s: '@{if(contains(items(\'Process_STIX_objects\'), \'kill_chain_phases\'), string(items(\'Process_STIX_objects\').kill_chain_phases), \'\')}'
                              Labels_s: '@{if(contains(items(\'Process_STIX_objects\'), \'labels\'), join(items(\'Process_STIX_objects\').labels, \', \'), \'\')}'
                              ThreatType_s: '@{if(contains(items(\'Process_STIX_objects\'), \'labels\'), join(items(\'Process_STIX_objects\').labels, \', \'), \'Unknown\')}'
                              TLP_s: '@{if(contains(items(\'Process_STIX_objects\').object_marking_refs[0], \'tlp\'), last(split(items(\'Process_STIX_objects\').object_marking_refs[0], \':\' )), \'TLP:AMBER\')}'
                              DistributionTargets_s: 'Microsoft Sentinel'
                              Active_b: '@{if(equals(items(\'Process_STIX_objects\')?[\'revoked\'], true), false, true)}'
                              ObjectId_g: '@{items(\'Process_STIX_objects\').id}'
                              IndicatorId_g: '@{guid()}'
                            }
                            host: {
                              connection: {
                                name: '@parameters(\'$connections\')[\'azureloganalyticsdatacollector\'][\'connectionId\']'
                              }
                            }
                            method: 'post'
                            path: '/api/logs'
                            queries: {
                              logType: 'CTI_ThreatIntelIndicator_CL'
                            }
                          }
                        }
                      }
                      runAfter: {
                        Process_Indicator_Domain: [
                          'Succeeded'
                        ]
                      }
                      expression: {
                        and: [
                          {
                            equals: [
                              '@items(\'Process_STIX_objects\').type'
                              'indicator'
                            ]
                          }
                          {
                            contains: [
                              '@items(\'Process_STIX_objects\').pattern'
                              'url'
                            ]
                          }
                        ]
                      }
                      type: 'If'
                    }
                    Process_Indicator_File_Hash: {
                      actions: {
                        Parse_File_Hash_Indicator: {
                          runAfter: {}
                          type: 'Compose'
                          inputs: '@items(\'Process_STIX_objects\').pattern'
                        }
                        Condition_for_Hash_Type: {
                          actions: {
                            Parse_SHA256: {
                              runAfter: {}
                              type: 'Compose'
                              inputs: '@replace(replace(outputs(\'Parse_File_Hash_Indicator\'),\'file:hashes.sha256 = \\\'\',\'\'),\'\\\'\',\'\')'
                            }
                            Send_FileHash_to_Log_Analytics: {
                              runAfter: {
                                Parse_SHA256: [
                                  'Succeeded'
                                ]
                              }
                              type: 'ApiConnection'
                              inputs: {
                                body: {
                                  SHA256_s: '@{outputs(\'Parse_SHA256\')}'
                                  ObjectId_g: '@{items(\'Process_STIX_objects\').id}'
                                  IndicatorId_g: '@{guid()}'
                                  ConfidenceScore_d: '@if(equals(items(\'Process_STIX_objects\')?[\'confidence\'], null), 50, items(\'Process_STIX_objects\').confidence)'
                                  SourceFeed_s: '@{items(\'For_each_TAXII_feed\').FeedName_s}'
                                  FirstSeen_t: '@{items(\'Process_STIX_objects\').created}'
                                  LastSeen_t: '@{items(\'Process_STIX_objects\').modified}'
                                  ExpirationDateTime_t: '@{items(\'Process_STIX_objects\').valid_until}'
                                  ThreatType_s: '@{if(contains(items(\'Process_STIX_objects\'), \'labels\'), join(items(\'Process_STIX_objects\').labels, \', \'), \'Unknown\')}'
                                  MalwareFamily_s: '@{if(contains(items(\'Process_STIX_objects\'), \'labels\'), first(items(\'Process_STIX_objects\').labels), \'Unknown\')}'
                                  Description_s: '@{items(\'Process_STIX_objects\').description}'
                                  TLP_s: '@{if(contains(items(\'Process_STIX_objects\').object_marking_refs[0], \'tlp\'), last(split(items(\'Process_STIX_objects\').object_marking_refs[0], \':\' )), \'TLP:AMBER\')}'
                                  Action_s: 'Alert'
                                  DistributionTargets_s: 'Microsoft Sentinel'
                                  Active_b: '@{if(equals(items(\'Process_STIX_objects\')?[\'revoked\'], true), false, true)}'
                                }
                                host: {
                                  connection: {
                                    name: '@parameters(\'$connections\')[\'azureloganalyticsdatacollector\'][\'connectionId\']'
                                  }
                                }
                                method: 'post'
                                path: '/api/logs'
                                queries: {
                                  logType: 'CTI_FileHashIndicators_CL'
                                }
                              }
                            }
                            Send_to_ThreatIntelIndicator_Hash: {
                              runAfter: {
                                Parse_SHA256: [
                                  'Succeeded'
                                ]
                              }
                              type: 'ApiConnection'
                              inputs: {
                                body: {
                                  Type_s: 'file-hash-sha256'
                                  Value_s: '@{outputs(\'Parse_SHA256\')}'
                                  Pattern_s: '@{items(\'Process_STIX_objects\').pattern}'
                                  PatternType_s: '@{items(\'Process_STIX_objects\').pattern_type}'
                                  Name_s: '@{if(contains(items(\'Process_STIX_objects\'), \'name\'), items(\'Process_STIX_objects\').name, \'File Hash Indicator\')}'
                                  Description_s: '@{items(\'Process_STIX_objects\').description}'
                                  Action_s: 'alert'
                                  Confidence_d: '@if(equals(items(\'Process_STIX_objects\')?[\'confidence\'], null), 50, items(\'Process_STIX_objects\').confidence)'
                                  ValidFrom_t: '@{items(\'Process_STIX_objects\').valid_from}'
                                  ValidUntil_t: '@{items(\'Process_STIX_objects\').valid_until}'
                                  CreatedTimeUtc_t: '@{items(\'Process_STIX_objects\').created}'
                                  UpdatedTimeUtc_t: '@{items(\'Process_STIX_objects\').modified}'
                                  Source_s: '@{items(\'For_each_TAXII_feed\').FeedName_s}'
                                  SourceRef_s: '@{items(\'For_each_TAXII_feed\').FeedURL_s}'
                                  KillChainPhases_s: '@{if(contains(items(\'Process_STIX_objects\'), \'kill_chain_phases\'), string(items(\'Process_STIX_objects\').kill_chain_phases), \'\')}'
                                  Labels_s: '@{if(contains(items(\'Process_STIX_objects\'), \'labels\'), join(items(\'Process_STIX_objects\').labels, \', \'), \'\')}'
                                  ThreatType_s: '@{if(contains(items(\'Process_STIX_objects\'), \'labels\'), join(items(\'Process_STIX_objects\').labels, \', \'), \'Unknown\')}'
                                  TLP_s: '@{if(contains(items(\'Process_STIX_objects\').object_marking_refs[0], \'tlp\'), last(split(items(\'Process_STIX_objects\').object_marking_refs[0], \':\' )), \'TLP:AMBER\')}'
                                  DistributionTargets_s: 'Microsoft Sentinel'
                                  Active_b: '@{if(equals(items(\'Process_STIX_objects\')?[\'revoked\'], true), false, true)}'
                                  ObjectId_g: '@{items(\'Process_STIX_objects\').id}'
                                  IndicatorId_g: '@{guid()}'
                                }
                                host: {
                                  connection: {
                                    name: '@parameters(\'$connections\')[\'azureloganalyticsdatacollector\'][\'connectionId\']'
                                  }
                                }
                                method: 'post'
                                path: '/api/logs'
                                queries: {
                                  logType: 'CTI_ThreatIntelIndicator_CL'
                                }
                              }
                            }
                          }
                          runAfter: {
                            Parse_File_Hash_Indicator: [
                              'Succeeded'
                            ]
                          }
                          expression: {
                            contains: [
                              '@outputs(\'Parse_File_Hash_Indicator\')'
                              'sha256'
                            ]
                          }
                          type: 'If'
                        }
                      }
                      runAfter: {
                        Process_Indicator_URL: [
                          'Succeeded'
                        ]
                      }
                      expression: {
                        and: [
                          {
                            equals: [
                              '@items(\'Process_STIX_objects\').type'
                              'indicator'
                            ]
                          }
                          {
                            contains: [
                              '@items(\'Process_STIX_objects\').pattern'
                              'file:hashes'
                            ]
                          }
                        ]
                      }
                      type: 'If'
                    }
                    Process_Indicator_Email: {
                      actions: {
                        Parse_Email_Indicator: {
                          runAfter: {}
                          type: 'Compose'
                          inputs: '@items(\'Process_STIX_objects\').pattern'
                        }
                        Send_Email_to_Log_Analytics: {
                          runAfter: {
                            Parse_Email_Indicator: [
                              'Succeeded'
                            ]
                          }
                          type: 'ApiConnection'
                          inputs: {
                            body: {
                              EmailAddress_s: '@replace(replace(outputs(\'Parse_Email_Indicator\'),\'email-addr:value = \\\'\',\'\'),\'\\\'\',\'\')'
                              ObjectId_g: '@{items(\'Process_STIX_objects\').id}'
                              IndicatorId_g: '@{guid()}'
                              ConfidenceScore_d: '@if(equals(items(\'Process_STIX_objects\')?[\'confidence\'], null), 50, items(\'Process_STIX_objects\').confidence)'
                              SourceFeed_s: '@{items(\'For_each_TAXII_feed\').FeedName_s}'
                              FirstSeen_t: '@{items(\'Process_STIX_objects\').created}'
                              LastSeen_t: '@{items(\'Process_STIX_objects\').modified}'
                              ExpirationDateTime_t: '@{items(\'Process_STIX_objects\').valid_until}'
                              ThreatType_s: '@{if(contains(items(\'Process_STIX_objects\'), \'labels\'), join(items(\'Process_STIX_objects\').labels, \', \'), \'Unknown\')}'
                              Description_s: '@{items(\'Process_STIX_objects\').description}'
                              TLP_s: '@{if(contains(items(\'Process_STIX_objects\').object_marking_refs[0], \'tlp\'), last(split(items(\'Process_STIX_objects\').object_marking_refs[0], \':\' )), \'TLP:AMBER\')}'
                              Action_s: 'Alert'
                              DistributionTargets_s: 'Microsoft Sentinel'
                              Active_b: '@{if(equals(items(\'Process_STIX_objects\')?[\'revoked\'], true), false, true)}'
                            }
                            host: {
                              connection: {
                                name: '@parameters(\'$connections\')[\'azureloganalyticsdatacollector\'][\'connectionId\']'
                              }
                            }
                            method: 'post'
                            path: '/api/logs'
                            queries: {
                              logType: 'CTI_EmailIndicators_CL'
                            }
                          }
                        }
                        Send_to_ThreatIntelIndicator_Email: {
                          runAfter: {
                            Parse_Email_Indicator: [
                              'Succeeded'
                            ]
                          }
                          type: 'ApiConnection'
                          inputs: {
                            body: {
                              Type_s: 'email-addr'
                              Value_s: '@replace(replace(outputs(\'Parse_Email_Indicator\'),\'email-addr:value = \\\'\',\'\'),\'\\\'\',\'\')'
                              Pattern_s: '@{items(\'Process_STIX_objects\').pattern}'
                              PatternType_s: '@{items(\'Process_STIX_objects\').pattern_type}'
                              Name_s: '@{if(contains(items(\'Process_STIX_objects\'), \'name\'), items(\'Process_STIX_objects\').name, \'Email Indicator\')}'
                              Description_s: '@{items(\'Process_STIX_objects\').description}'
                              Action_s: 'alert'
                              Confidence_d: '@if(equals(items(\'Process_STIX_objects\')?[\'confidence\'], null), 50, items(\'Process_STIX_objects\').confidence)'
                              ValidFrom_t: '@{items(\'Process_STIX_objects\').valid_from}'
                              ValidUntil_t: '@{items(\'Process_STIX_objects\').valid_until}'
                              CreatedTimeUtc_t: '@{items(\'Process_STIX_objects\').created}'
                              UpdatedTimeUtc_t: '@{items(\'Process_STIX_objects\').modified}'
                              Source_s: '@{items(\'For_each_TAXII_feed\').FeedName_s}'
                              SourceRef_s: '@{items(\'For_each_TAXII_feed\').FeedURL_s}'
                              KillChainPhases_s: '@{if(contains(items(\'Process_STIX_objects\'), \'kill_chain_phases\'), string(items(\'Process_STIX_objects\').kill_chain_phases), \'\')}'
                              Labels_s: '@{if(contains(items(\'Process_STIX_objects\'), \'labels\'), join(items(\'Process_STIX_objects\').labels, \', \'), \'\')}'
                              ThreatType_s: '@{if(contains(items(\'Process_STIX_objects\'), \'labels\'), join(items(\'Process_STIX_objects\').labels, \', \'), \'Unknown\')}'
                              TLP_s: '@{if(contains(items(\'Process_STIX_objects\').object_marking_refs[0], \'tlp\'), last(split(items(\'Process_STIX_objects\').object_marking_refs[0], \':\' )), \'TLP:AMBER\')}'
                              DistributionTargets_s: 'Microsoft Sentinel'
                              Active_b: '@{if(equals(items(\'Process_STIX_objects\')?[\'revoked\'], true), false, true)}'
                              ObjectId_g: '@{items(\'Process_STIX_objects\').id}'
                              IndicatorId_g: '@{guid()}'
                            }
                            host: {
                              connection: {
                                name: '@parameters(\'$connections\')[\'azureloganalyticsdatacollector\'][\'connectionId\']'
                              }
                            }
                            method: 'post'
                            path: '/api/logs'
                            queries: {
                              logType: 'CTI_ThreatIntelIndicator_CL'
                            }
                          }
                        }
                      }
                      runAfter: {
                        Process_Indicator_File_Hash: [
                          'Succeeded'
                        ]
                      }
                      expression: {
                        and: [
                          {
                            equals: [
                              '@items(\'Process_STIX_objects\').type'
                              'indicator'
                            ]
                          }
                          {
                            contains: [
                              '@items(\'Process_STIX_objects\').pattern'
                              'email-addr'
                            ]
                          }
                        ]
                      }
                      type: 'If'
                    }
                    Process_Threat_Actor: {
                      actions: {
                        Store_Threat_Actor: {
                          runAfter: {}
                          type: 'ApiConnection'
                          inputs: {
                            body: {
                              ActorId_g: '@{items(\'Process_STIX_objects\').id}'
                              Name_s: '@{items(\'Process_STIX_objects\').name}'
                              Aliases_s: '@{if(contains(items(\'Process_STIX_objects\'), \'aliases\'), join(items(\'Process_STIX_objects\').aliases, \', \'), \'\')}'
                              Description_s: '@{items(\'Process_STIX_objects\').description}'
                              FirstSeen_t: '@{items(\'Process_STIX_objects\').created}'
                              LastSeen_t: '@{items(\'Process_STIX_objects\').modified}'
                              Motivations_s: '@{if(contains(items(\'Process_STIX_objects\'), \'motivations\'), join(items(\'Process_STIX_objects\').motivations, \', \'), \'\')}'
                              ThreatTypes_s: '@{if(contains(items(\'Process_STIX_objects\'), \'labels\'), join(items(\'Process_STIX_objects\').labels, \', \'), \'Unknown\')}'
                              SourceFeed_s: '@{items(\'For_each_TAXII_feed\').FeedName_s}'
                              TLP_s: '@{if(contains(items(\'Process_STIX_objects\').object_marking_refs[0], \'tlp\'), last(split(items(\'Process_STIX_objects\').object_marking_refs[0], \':\' )), \'TLP:AMBER\')}'
                              Confidence_d: '@if(equals(items(\'Process_STIX_objects\')?[\'confidence\'], null), 50, items(\'Process_STIX_objects\').confidence)'
                              Active_b: true
                            }
                            host: {
                              connection: {
                                name: '@parameters(\'$connections\')[\'azureloganalyticsdatacollector\'][\'connectionId\']'
                              }
                            }
                            method: 'post'
                            path: '/api/logs'
                            queries: {
                              logType: 'CTI_ThreatActors_CL'
                            }
                          }
                        }
                        Store_STIX_Object_Actor: {
                          runAfter: {
                            Store_Threat_Actor: [
                              'Succeeded'
                            ]
                          }
                          type: 'ApiConnection'
                          inputs: {
                            body: {
                              ObjectId_g: '@{items(\'Process_STIX_objects\').id}'
                              Type_s: '@{items(\'Process_STIX_objects\').type}'
                              CreatedTimeUtc_t: '@{items(\'Process_STIX_objects\').created}'
                              UpdatedTimeUtc_t: '@{items(\'Process_STIX_objects\').modified}'
                              SourceId_s: '@{items(\'For_each_TAXII_feed\').FeedId_g}'
                              Source_s: '@{items(\'For_each_TAXII_feed\').FeedName_s}'
                              Name_s: '@{items(\'Process_STIX_objects\').name}'
                              Description_s: '@{items(\'Process_STIX_objects\').description}'
                              JsonData_s: '@{string(items(\'Process_STIX_objects\'))}'
                              Relations_s: '@{if(contains(items(\'Process_STIX_objects\'), \'object_refs\'), string(items(\'Process_STIX_objects\').object_refs), \'\')}'
                              TLP_s: '@{if(contains(items(\'Process_STIX_objects\'), \'object_marking_refs\') && contains(first(items(\'Process_STIX_objects\').object_marking_refs), \'tlp\'), last(split(first(items(\'Process_STIX_objects\').object_marking_refs), \':\' )), \'TLP:AMBER\')}'
                              ThreatActorType_s: '@{if(contains(items(\'Process_STIX_objects\'), \'threat_actor_types\'), join(items(\'Process_STIX_objects\').threat_actor_types, \', \'), \'\')}'
                              Active_b: true
                            }
                            host: {
                              connection: {
                                name: '@parameters(\'$connections\')[\'azureloganalyticsdatacollector\'][\'connectionId\']'
                              }
                            }
                            method: 'post'
                            path: '/api/logs'
                            queries: {
                              logType: 'CTI_ThreatIntelObjects_CL'
                            }
                          }
                        }
                      }
                      runAfter: {
                        Process_Indicator_Email: [
                          'Succeeded'
                        ]
                      }
                      expression: {
                        equals: [
                          '@items(\'Process_STIX_objects\').type'
                          'threat-actor'
                        ]
                      }
                      type: 'If'
                    }
                    Store_STIX_Object: {
                      runAfter: {
                        Process_Threat_Actor: [
                          'Succeeded'
                        ]
                      }
                      type: 'ApiConnection'
                      inputs: {
                        body: {
                          ObjectId_g: '@{items(\'Process_STIX_objects\').id}'
                          Type_s: '@{items(\'Process_STIX_objects\').type}'
                          CreatedTimeUtc_t: '@{items(\'Process_STIX_objects\').created}'
                          UpdatedTimeUtc_t: '@{items(\'Process_STIX_objects\').modified}'
                          SourceId_s: '@{items(\'For_each_TAXII_feed\').FeedId_g}'
                          Source_s: '@{items(\'For_each_TAXII_feed\').FeedName_s}'
                          Name_s: '@{if(contains(items(\'Process_STIX_objects\'), \'name\'), items(\'Process_STIX_objects\').name, items(\'Process_STIX_objects\').type)}'
                          Description_s: '@{items(\'Process_STIX_objects\').description}'
                          JsonData_s: '@{string(items(\'Process_STIX_objects\'))}'
                          Relations_s: '@{if(contains(items(\'Process_STIX_objects\'), \'object_refs\'), string(items(\'Process_STIX_objects\').object_refs), \'\')}'
                          TLP_s: '@{if(contains(items(\'Process_STIX_objects\'), \'object_marking_refs\') && contains(first(items(\'Process_STIX_objects\').object_marking_refs), \'tlp\'), last(split(first(items(\'Process_STIX_objects\').object_marking_refs), \':\' )), \'TLP:AMBER\')}'
                          Active_b: '@{if(equals(items(\'Process_STIX_objects\')?[\'revoked\'], true), false, true)}'
                        }
                        host: {
                          connection: {
                            name: '@parameters(\'$connections\')[\'azureloganalyticsdatacollector\'][\'connectionId\']'
                          }
                        }
                        method: 'post'
                        path: '/api/logs'
                        queries: {
                          logType: 'CTI_ThreatIntelObjects_CL'
                        }
                      }
                    }
                  }
                  runAfter: {
                    Parse_STIX_response: [
                      'Succeeded'
                    ]
                  }
                  type: 'Foreach'
                  runtimeConfiguration: {
                    concurrency: {
                      repetitions: 20  // Increased from 10 for faster processing
                    }
                    staticResult: {
                      staticResultOptions: 'Disabled'  // Added for performance
                    }
                  }
                }
                Log_feed_update: {
                  runAfter: {
                    Process_STIX_objects: [
                      'Succeeded'
                    ]
                  }
                  type: 'ApiConnection'
                  inputs: {
                    body: {
                      FeedId_g: '@{items(\'For_each_TAXII_feed\').FeedId_g}'
                      FeedName_s: '@{items(\'For_each_TAXII_feed\').FeedName_s}'
                      FeedType_s: 'TAXII'
                      FeedURL_s: '@{items(\'For_each_TAXII_feed\').FeedURL_s}'
                      Status_s: 'Active'
                      LastUpdated_t: '@{utcNow()}'
                      UpdateFrequency_s: '6 hours'
                      IndicatorCount_d: '@{length(body(\'Parse_STIX_response\').objects)}'
                      Description_s: '@{items(\'For_each_TAXII_feed\').Description_s}'
                      Category_s: '@{items(\'For_each_TAXII_feed\').Category_s}'
                      TLP_s: '@{items(\'For_each_TAXII_feed\').TLP_s}'
                      ConfidenceScore_d: '@{items(\'For_each_TAXII_feed\').ConfidenceScore_d}'
                      Active_b: true
                    }
                    host: {
                      connection: {
                        name: '@parameters(\'$connections\')[\'azureloganalyticsdatacollector\'][\'connectionId\']'
                      }
                    }
                    method: 'post'
                    path: '/api/logs'
                    queries: {
                      logType: 'CTI_IntelligenceFeeds_CL'
                    }
                  }
                }
              }
              runAfter: {
                Get_TAXII_feeds: [
                  'Succeeded'
                ]
              }
              type: 'Foreach'
              runtimeConfiguration: {
                concurrency: {
                  repetitions: 1
                }
              }
            }
            Get_TAXII_feeds: {
              runAfter: {}
              type: 'ApiConnection'
              inputs: {
                body: 'CTI_IntelligenceFeeds_CL | where FeedType_s == "TAXII" and Active_b == true'
                host: {
                  connection: {
                    name: '@parameters(\'$connections\')[\'azuremonitorlogs\'][\'connectionId\']'
                  }
                }
                method: 'post'
                path: '/queryData'
                queries: {
                  resourcegroups: '@resourceGroup().name'
                  resourcename: '@{parameters(\'workspaceName\')}'
                  resourcetype: 'Log Analytics Workspace'
                  subscriptions: '@{subscription().subscriptionId}'
                  timerange: 'Last 7 days'
                }
              }
            }
            Handle_Error: {
              actions: {
                Log_Error: {
                  runAfter: {}
                  type: 'ApiConnection'
                  inputs: {
                    body: {
                      ErrorSource_s: 'TAXII-Connector'
                      ErrorMessage_s: 'Failed to process TAXII feeds. Error: @{result(\'Get_TAXII_feeds\')}'
                      ErrorCode_s: '@{outputs(\'Get_TAXII_feeds\')?[\'statusCode\']}'
                      ErrorDetails_s: '@{outputs(\'Get_TAXII_feeds\')?[\'body\']}'
                      Timestamp_t: '@{utcNow()}'
                      ActionId_g: '@{guid()}'
                      CorrelationId_g: '@{workflow()[\'run\'][\'name\']}'
                      RunbookName_s: 'CTI-TAXII2-Connector'
                      TriggerSource_s: 'Scheduled'
                    }
                    host: {
                      connection: {
                        name: '@parameters(\'$connections\')[\'azureloganalyticsdatacollector\'][\'connectionId\']'
                      }
                    }
                    method: 'post'
                    path: '/api/logs'
                    queries: {
                      logType: 'CTI_TransactionLog_CL'
                    }
                  }
                }
              }
              runAfter: {
                Get_TAXII_feeds: [
                  'Failed'
                ]
              }
              type: 'Scope'
            }
          }
        }
      }
    }
    parameters: {
      '$connections': {
        value: {
          azureloganalyticsdatacollector: {
            connectionId: logAnalyticsConnection.id
            connectionName: logAnalyticsConnection.name
            id: subscriptionResourceId('Microsoft.Web/locations/managedApis', location, 'azureloganalyticsdatacollector')
          }
          azuremonitorlogs: {
            connectionId: logAnalyticsQueryConnection.id
            connectionName: logAnalyticsQueryConnection.name
            id: subscriptionResourceId('Microsoft.Web/locations/managedApis', location, 'azuremonitorlogs')
          }
        }
      }
    }
  }
  dependsOn: [
    logAnalyticsQueryConnection
    logAnalyticsConnection
  ]
}

// Add diagnostic settings for taxiiConnectorLogicApp
resource taxiiConnectorDiagnostics 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = {
  scope: taxiiConnectorLogicApp
  name: 'diagnostics'
  properties: {
    workspaceId: ctiWorkspace.id
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

// Microsoft Defender XDR Connector
resource defenderEndpointConnector 'Microsoft.Logic/workflows@2019-05-01' = {
  name: defenderEndpointConnectorName
  location: location
  tags: tags
  identity: {
    type: 'UserAssigned'
    userAssignedIdentities: {
      '${managedIdentity.id}': {}
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
        'tenantId': {
          defaultValue: tenantId
          type: 'String'
        }
        'clientId': {
          defaultValue: appClientId
          type: 'String'
        }
        'workspaceName': {
          defaultValue: ctiWorkspaceName
          type: 'String'
        }
        'securityApiUrl': {
          defaultValue: securityApiBaseUrl
          type: 'String'
        }
      }
      triggers: {
        Recurrence: {
          recurrence: {
            frequency: 'Hour'
            interval: 1
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
            uri: '${environment().authentication.loginEndpoint}${parameters(\'tenantId\')}/oauth2/token'
            headers: {
              'Content-Type': 'application/x-www-form-urlencoded'
            }
            body: 'grant_type=client_credentials&client_id=@{parameters(\'clientId\')}&client_secret=@{listSecrets(resourceId(\'Microsoft.KeyVault/vaults/secrets\', \'${keyVaultName}\', \'${clientSecretName}\'), \'2023-02-01\').value}&resource=https://api.securitycenter.windows.com/'
            retryPolicy: {
              type: 'fixed'
              count: 3
              interval: 'PT30S'
            }
          }
        }
        Process_High_Confidence_IPs: {
          runAfter: {
            Get_Authentication_Token: [
              'Succeeded'
            ]
          }
          type: 'ApiConnection'
          inputs: {
            body: 'CTI_IPIndicators_CL \n| where ConfidenceScore_d >= 80 and TimeGenerated > ago(1h) and isnotempty(IPAddress_s) \n| where not(IPAddress_s matches regex "^10\\\\.|^172\\\\.(1[6-9]|2[0-9]|3[0-1])\\\\.|^192\\\\.168\\\\.")\n| where "Microsoft Defender XDR" in (split(DistributionTargets_s, ", "))\n| project IPAddress_s, ConfidenceScore_d, ThreatType_s, Description_s, IndicatorId_g, Action_s\n| limit 500'
            host: {
              connection: {
                name: '@parameters(\'$connections\')[\'azuremonitorlogs\'][\'connectionId\']'
              }
            }
            method: 'post'
            path: '/queryData'
            queries: {
              resourcegroups: '@resourceGroup().name'
              resourcename: '@{parameters(\'workspaceName\')}'
              resourcetype: 'Log Analytics Workspace'
              subscriptions: '@{subscription().subscriptionId}'
              timerange: 'Last hour'
            }
          }
        }
        For_Each_IP_Indicator: {
          foreach: '@body(\'Process_High_Confidence_IPs\').tables[0].rows'
          actions: {
            Submit_IP_Indicator: {
              runAfter: {}
              type: 'Http'
              inputs: {
                method: 'POST'
                uri: '@{parameters(\'securityApiUrl\')}/api/indicators'
                headers: {
                  'Content-Type': 'application/json'
                  Authorization: 'Bearer @{body(\'Get_Authentication_Token\').access_token}'
                }
                body: {
                  indicatorValue: '@{item()[0]}' // IPAddress_s
                  indicatorType: 'IpAddress'
                  action: '@{if(equals(item()[5], \'Alert\'), \'Alert\', if(equals(item()[5], \'AlertAndBlock\'), \'AlertAndBlock\', \'Block\'))}'
                  title: 'CTI Auto-Block: @{item()[2]}' // ThreatType_s
                  description: '@{if(equals(item()[3], \'\'), concat(\'High confidence malicious IP from threat feed. Confidence: \', item()[1]), item()[3])}'
                  severity: '@{if(less(item()[1], 70), \'Low\', if(less(item()[1], 90), \'Medium\', \'High\'))}'
                  recommendedActions: 'Block this IP address'
                  rbacGroupNames: []
                  generateAlert: true
                }
                retryPolicy: {
                  type: 'fixed'
                  count: 3
                  interval: 'PT30S'
                }
              }
            }
            Log_Transaction: {
              runAfter: {
                Submit_IP_Indicator: [
                  'Succeeded'
                ]
              }
              type: 'ApiConnection'
              inputs: {
                body: {
                  IndicatorType_s: 'IP'
                  IndicatorValue_s: '@{item()[0]}'
                  Action_s: '@{if(equals(item()[5], \'Alert\'), \'Alert\', if(equals(item()[5], \'AlertAndBlock\'), \'AlertAndBlock\', \'Block\'))}'
                  TargetSystem_s: 'Microsoft Defender XDR'
                  Status_s: 'Success'
                  Timestamp_t: '@{utcNow()}'
                  ActionId_g: '@{guid()}'
                  CorrelationId_g: '@{workflow()[\'run\'][\'name\']}'
                  IndicatorId_g: '@{item()[4]}'
                  RunbookName_s: 'CTI-DefenderXDR-Connector'
                  TriggerSource_s: 'Scheduled'
                }
                host: {
                  connection: {
                    name: '@parameters(\'$connections\')[\'azureloganalyticsdatacollector\'][\'connectionId\']'
                  }
                }
                method: 'post'
                path: '/api/logs'
                queries: {
                  logType: 'CTI_TransactionLog_CL'
                }
              }
            }
            Handle_Error: {
              actions: {
                Log_Error: {
                  runAfter: {}
                  type: 'ApiConnection'
                  inputs: {
                    body: {
                      IndicatorType_s: 'IP'
                      IndicatorValue_s: '@{item()[0]}'
                      Action_s: '@{if(equals(item()[5], \'Alert\'), \'Alert\', if(equals(item()[5], \'AlertAndBlock\'), \'AlertAndBlock\', \'Block\'))}'
                      TargetSystem_s: 'Microsoft Defender XDR'
                      Status_s: 'Failed'
                      ErrorMessage_s: '@{outputs(\'Submit_IP_Indicator\')[\'body\']}'
                      ErrorCode_s: '@{outputs(\'Submit_IP_Indicator\')?[\'statusCode\']}'
                      ErrorDetails_s: '@{string(outputs(\'Submit_IP_Indicator\'))}'
                      Timestamp_t: '@{utcNow()}'
                      ActionId_g: '@{guid()}'
                      CorrelationId_g: '@{workflow()[\'run\'][\'name\']}'
                      IndicatorId_g: '@{item()[4]}'
                      RunbookName_s: 'CTI-DefenderXDR-Connector'
                      TriggerSource_s: 'Scheduled'
                    }
                    host: {
                      connection: {
                        name: '@parameters(\'$connections\')[\'azureloganalyticsdatacollector\'][\'connectionId\']'
                      }
                    }
                    method: 'post'
                    path: '/api/logs'
                    queries: {
                      logType: 'CTI_TransactionLog_CL'
                    }
                  }
                }
              }
              runAfter: {
                Submit_IP_Indicator: [
                  'Failed'
                ]
              }
              type: 'Scope'
            }
          }
          runAfter: {
            Process_High_Confidence_IPs: [
              'Succeeded'
            ]
          }
          type: 'Foreach'
          runtimeConfiguration: {
            concurrency: {
              repetitions: 20  // Increased from 10 for faster processing
            }
            staticResult: {
              staticResultOptions: 'Disabled'  // Added for performance
            }
          }
        }
        Process_High_Confidence_FileHashes: {
          runAfter: {
            For_Each_IP_Indicator: [
              'Succeeded'
            ]
          }
          type: 'ApiConnection'
          inputs: {
            body: 'CTI_FileHashIndicators_CL \n| where ConfidenceScore_d >= 80 and TimeGenerated > ago(1h) and isnotempty(SHA256_s)\n| where "Microsoft Defender XDR" in (split(DistributionTargets_s, ", "))\n| project SHA256_s, ConfidenceScore_d, ThreatType_s, MalwareFamily_s, Description_s, IndicatorId_g, Action_s\n| limit 500'
            host: {
              connection: {
                name: '@parameters(\'$connections\')[\'azuremonitorlogs\'][\'connectionId\']'
              }
            }
            method: 'post'
            path: '/queryData'
            queries: {
              resourcegroups: '@resourceGroup().name'
              resourcename: '@{parameters(\'workspaceName\')}'
              resourcetype: 'Log Analytics Workspace'
              subscriptions: '@{subscription().subscriptionId}'
              timerange: 'Last hour'
            }
          }
        }
        For_Each_FileHash_Indicator: {
          foreach: '@body(\'Process_High_Confidence_FileHashes\').tables[0].rows'
          actions: {
            Submit_FileHash_Indicator: {
              runAfter: {}
              type: 'Http'
              inputs: {
                method: 'POST'
                uri: '@{parameters(\'securityApiUrl\')}/api/indicators'
                headers: {
                  'Content-Type': 'application/json'
                  Authorization: 'Bearer @{body(\'Get_Authentication_Token\').access_token}'
                }
                body: {
                  indicatorValue: '@{item()[0]}' // SHA256_s
                  indicatorType: 'FileSha256'
                  action: '@{if(equals(item()[6], \'Alert\'), \'Alert\', if(equals(item()[6], \'AlertAndBlock\'), \'AlertAndBlock\', \'Block\'))}'
                  title: 'CTI Auto-Block: @{if(not(empty(item()[3])), concat(item()[3], \' malware\'), concat(item()[2], \' threat\'))}'
                  description: '@{if(equals(item()[4], \'\'), concat(\'High confidence malicious file hash from threat feed. Confidence: \', item()[1]), item()[4])}'
                  severity: '@{if(less(item()[1], 70), \'Low\', if(less(item()[1], 90), \'Medium\', \'High\'))}'
                  recommendedActions: 'Block this file hash'
                  rbacGroupNames: []
                  generateAlert: true
                }
                retryPolicy: {
                  type: 'fixed'
                  count: 3
                  interval: 'PT30S'
                }
              }
            }
            Log_Transaction_FileHash: {
              runAfter: {
                Submit_FileHash_Indicator: [
                  'Succeeded'
                ]
              }
              type: 'ApiConnection'
              inputs: {
                body: {
                  IndicatorType_s: 'FileHash'
                  IndicatorValue_s: '@{item()[0]}'
                  Action_s: '@{if(equals(item()[6], \'Alert\'), \'Alert\', if(equals(item()[6], \'AlertAndBlock\'), \'AlertAndBlock\', \'Block\'))}'
                  TargetSystem_s: 'Microsoft Defender XDR'
                  Status_s: 'Success'
                  Timestamp_t: '@{utcNow()}'
                  ActionId_g: '@{guid()}'
                  CorrelationId_g: '@{workflow()[\'run\'][\'name\']}'
                  IndicatorId_g: '@{item()[5]}'
                  RunbookName_s: 'CTI-DefenderXDR-Connector'
                  TriggerSource_s: 'Scheduled'
                }
                host: {
                  connection: {
                    name: '@parameters(\'$connections\')[\'azureloganalyticsdatacollector\'][\'connectionId\']'
                  }
                }
                method: 'post'
                path: '/api/logs'
                queries: {
                  logType: 'CTI_TransactionLog_CL'
                }
              }
            }
            Handle_FileHash_Error: {
              actions: {
                Log_Error_FileHash: {
                  runAfter: {}
                  type: 'ApiConnection'
                  inputs: {
                    body: {
                      IndicatorType_s: 'FileHash'
                      IndicatorValue_s: '@{item()[0]}'
                      Action_s: '@{if(equals(item()[6], \'Alert\'), \'Alert\', if(equals(item()[6], \'AlertAndBlock\'), \'AlertAndBlock\', \'Block\'))}'
                      TargetSystem_s: 'Microsoft Defender XDR'
                      Status_s: 'Failed'
                      ErrorMessage_s: '@{outputs(\'Submit_FileHash_Indicator\')[\'body\']}'
                      ErrorCode_s: '@{outputs(\'Submit_FileHash_Indicator\')?[\'statusCode\']}'
                      ErrorDetails_s: '@{string(outputs(\'Submit_FileHash_Indicator\'))}'
                      Timestamp_t: '@{utcNow()}'
                      ActionId_g: '@{guid()}'
                      CorrelationId_g: '@{workflow()[\'run\'][\'name\']}'
                      IndicatorId_g: '@{item()[5]}'
                      RunbookName_s: 'CTI-DefenderXDR-Connector'
                      TriggerSource_s: 'Scheduled'
                    }
                    host: {
                      connection: {
                        name: '@parameters(\'$connections\')[\'azureloganalyticsdatacollector\'][\'connectionId\']'
                      }
                    }
                    method: 'post'
                    path: '/api/logs'
                    queries: {
                      logType: 'CTI_TransactionLog_CL'
                    }
                  }
                }
              }
              runAfter: {
                Submit_FileHash_Indicator: [
                  'Failed'
                ]
              }
              type: 'Scope'
            }
          }
          runAfter: {
            Process_High_Confidence_FileHashes: [
              'Succeeded'
            ]
          }
          type: 'Foreach'
          runtimeConfiguration: {
            concurrency: {
              repetitions: 20  // Increased from 10 for faster processing
            }
            staticResult: {
              staticResultOptions: 'Disabled'  // Added for performance
            }
          }
        }
        Process_High_Confidence_URLs: {
          runAfter: {
            For_Each_FileHash_Indicator: [
              'Succeeded'
            ]
          }
          type: 'ApiConnection'
          inputs: {
            body: 'CTI_URLIndicators_CL \n| where ConfidenceScore_d >= 90 and TimeGenerated > ago(1h) and isnotempty(URL_s)\n| where "Microsoft Defender XDR" in (split(DistributionTargets_s, ", "))\n| project URL_s, ConfidenceScore_d, ThreatType_s, Description_s, IndicatorId_g, Action_s\n| limit 500'
            host: {
              connection: {
                name: '@parameters(\'$connections\')[\'azuremonitorlogs\'][\'connectionId\']'
              }
            }
            method: 'post'
            path: '/queryData'
            queries: {
              resourcegroups: '@resourceGroup().name'
              resourcename: '@{parameters(\'workspaceName\')}'
              resourcetype: 'Log Analytics Workspace'
              subscriptions: '@{subscription().subscriptionId}'
              timerange: 'Last hour'
            }
          }
        }
        For_Each_URL_Indicator: {
          foreach: '@body(\'Process_High_Confidence_URLs\').tables[0].rows'
          actions: {
            Submit_URL_Indicator: {
              runAfter: {}
              type: 'Http'
              inputs: {
                method: 'POST'
                uri: '@{parameters(\'securityApiUrl\')}/api/indicators'
                headers: {
                  'Content-Type': 'application/json'
                  Authorization: 'Bearer @{body(\'Get_Authentication_Token\').access_token}'
                }
                body: {
                  indicatorValue: '@{item()[0]}' // URL_s
                  indicatorType: 'Url'
                  action: '@{if(equals(item()[5], \'Alert\'), \'Alert\', if(equals(item()[5], \'AlertAndBlock\'), \'AlertAndBlock\', \'Block\'))}'
                  title: 'CTI Auto-Block: @{item()[2]}' // ThreatType_s
                  description: '@{if(equals(item()[3], \'\'), concat(\'High confidence malicious URL from threat feed. Confidence: \', item()[1]), item()[3])}'
                  severity: '@{if(less(item()[1], 70), \'Low\', if(less(item()[1], 90), \'Medium\', \'High\'))}'
                  recommendedActions: 'Block this URL'
                  rbacGroupNames: []
                  generateAlert: true
                }
                retryPolicy: {
                  type: 'fixed'
                  count: 3
                  interval: 'PT30S'
                }
              }
            }
            Log_Transaction_URL: {
              runAfter: {
                Submit_URL_Indicator: [
                  'Succeeded'
                ]
              }
              type: 'ApiConnection'
              inputs: {
                body: {
                  IndicatorType_s: 'URL'
                  IndicatorValue_s: '@{item()[0]}'
                  Action_s: '@{if(equals(item()[5], \'Alert\'), \'Alert\', if(equals(item()[5], \'AlertAndBlock\'), \'AlertAndBlock\', \'Block\'))}'
                  TargetSystem_s: 'Microsoft Defender XDR'
                  Status_s: 'Success'
                  Timestamp_t: '@{utcNow()}'
                  ActionId_g: '@{guid()}'
                  CorrelationId_g: '@{workflow()[\'run\'][\'name\']}'
                  IndicatorId_g: '@{item()[4]}'
                  RunbookName_s: 'CTI-DefenderXDR-Connector'
                  TriggerSource_s: 'Scheduled'
                }
                host: {
                  connection: {
                    name: '@parameters(\'$connections\')[\'azureloganalyticsdatacollector\'][\'connectionId\']'
                  }
                }
                method: 'post'
                path: '/api/logs'
                queries: {
                  logType: 'CTI_TransactionLog_CL'
                }
              }
            }
            Handle_URL_Error: {
              actions: {
                Log_Error_URL: {
                  runAfter: {}
                  type: 'ApiConnection'
                  inputs: {
                    body: {
                      IndicatorType_s: 'URL'
                      IndicatorValue_s: '@{item()[0]}'
                      Action_s: '@{if(equals(item()[5], \'Alert\'), \'Alert\', if(equals(item()[5], \'AlertAndBlock\'), \'AlertAndBlock\', \'Block\'))}'
                      TargetSystem_s: 'Microsoft Defender XDR'
                      Status_s: 'Failed'
                      ErrorMessage_s: '@{outputs(\'Submit_URL_Indicator\')[\'body\']}'
                      ErrorCode_s: '@{outputs(\'Submit_URL_Indicator\')?[\'statusCode\']}'
                      ErrorDetails_s: '@{string(outputs(\'Submit_URL_Indicator\'))}'
                      Timestamp_t: '@{utcNow()}'
                      ActionId_g: '@{guid()}'
                      CorrelationId_g: '@{workflow()[\'run\'][\'name\']}'
                      IndicatorId_g: '@{item()[4]}'
                      RunbookName_s: 'CTI-DefenderXDR-Connector'
                      TriggerSource_s: 'Scheduled'
                    }
                    host: {
                      connection: {
                        name: '@parameters(\'$connections\')[\'azureloganalyticsdatacollector\'][\'connectionId\']'
                      }
                    }
                    method: 'post'
                    path: '/api/logs'
                    queries: {
                      logType: 'CTI_TransactionLog_CL'
                    }
                  }
                }
              }
              runAfter: {
                Submit_URL_Indicator: [
                  'Failed'
                ]
              }
              type: 'Scope'
            }
          }
          runAfter: {
            Process_High_Confidence_URLs: [
              'Succeeded'
            ]
          }
          type: 'Foreach'
          runtimeConfiguration: {
            concurrency: {
              repetitions: 20  // Increased from 10 for faster processing
            }
            staticResult: {
              staticResultOptions: 'Disabled'  // Added for performance
            }
          }
        }
      }
      outputs: {}
    }
    parameters: {
      '$connections': {
        value: {
          azureloganalyticsdatacollector: {
            connectionId: logAnalyticsConnection.id
            connectionName: logAnalyticsConnection.name
            id: subscriptionResourceId('Microsoft.Web/locations/managedApis', location, 'azureloganalyticsdatacollector')
          }
          azuremonitorlogs: {
            connectionId: logAnalyticsQueryConnection.id
            connectionName: logAnalyticsQueryConnection.name
            id: subscriptionResourceId('Microsoft.Web/locations/managedApis', location, 'azuremonitorlogs')
          }
        }
      }
    }
  }
  dependsOn: [
    taxiiConnectorLogicApp
  ]
}

// Add diagnostic settings for defenderEndpointConnector
resource defenderEndpointConnectorDiagnostics 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = {
  scope: defenderEndpointConnector
  name: 'diagnostics'
  properties: {
    workspaceId: ctiWorkspace.id
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

// Microsoft Defender Threat Intelligence (MDTI) Connector
resource mdtiConnectorLogicApp 'Microsoft.Logic/workflows@2019-05-01' = if (enableMDTI) {
  name: mdtiConnectorLogicAppName
  location: location
  tags: tags
  identity: {
    type: 'UserAssigned'
    userAssignedIdentities: {
      '${managedIdentity.id}': {}
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
            uri: '${environment().authentication.loginEndpoint}${parameters(\'tenantId\')}/oauth2/token'
            headers: {
              'Content-Type': 'application/x-www-form-urlencoded'
            }
            body: 'grant_type=client_credentials&client_id=@{parameters(\'clientId\')}&client_secret=@{listSecrets(resourceId(\'Microsoft.KeyVault/vaults/secrets\', \'${keyVaultName}\', \'${clientSecretName}\'), \'2023-02-01\').value}&resource=https://api.securitycenter.microsoft.com/'
            retryPolicy: {
              type: 'fixed'
              count: 3
              interval: 'PT30S'
            }
          }
        }
        Get_MDTI_Indicators: {
          runAfter: {
            Get_Authentication_Token: [
              'Succeeded'
            ]
          }
          type: 'Http'
          inputs: {
            method: 'GET'
            uri: 'https://api.securitycenter.microsoft.com/api/indicators?$filter=sourceseverity eq \'High\' and expirationDateTime gt @{utcNow()}'
            headers: {
              Authorization: 'Bearer @{body(\'Get_Authentication_Token\').access_token}'
              'Content-Type': 'application/json'
            }
            retryPolicy: {
              type: 'fixed'
              count: 3
              interval: 'PT30S'
            }
          }
        }
        Parse_MDTI_Response: {
          runAfter: {
            Get_MDTI_Indicators: [
              'Succeeded'
            ]
          }
          type: 'ParseJson'
          inputs: {
            content: '@body(\'Get_MDTI_Indicators\')'
            schema: {
              type: 'object'
              properties: {
                value: {
                  type: 'array'
                  items: {
                    type: 'object'
                    properties: {
                      id: { type: 'string' }
                      indicatorValue: { type: 'string' }
                      indicatorType: { type: 'string' }
                      title: { type: 'string' }
                      creationTimeDateTimeUtc: { type: 'string' }
                      expirationDateTime: { type: 'string' }
                      action: { type: 'string' }
                      severity: { type: 'string' }
                      description: { type: 'string' }
                    }
                  }
                }
              }
            }
          }
        }
        Process_MDTI_Indicators: {
          foreach: '@body(\'Parse_MDTI_Response\').value'
          actions: {
            Process_IP_Indicator: {
              actions: {
                Send_IP_to_Log_Analytics: {
                  runAfter: {}
                  type: 'ApiConnection'
                  inputs: {
                    body: {
                      IPAddress_s: '@{items(\'Process_MDTI_Indicators\').indicatorValue}'
                      ObjectId_g: '@{items(\'Process_MDTI_Indicators\').id}'
                      IndicatorId_g: '@{guid()}'
                      ConfidenceScore_d: '@{if(equals(items(\'Process_MDTI_Indicators\').severity, \'High\'), 90, if(equals(items(\'Process_MDTI_Indicators\').severity, \'Medium\'), 70, 50))}'
                      SourceFeed_s: 'Microsoft Defender Threat Intelligence'
                      FirstSeen_t: '@{items(\'Process_MDTI_Indicators\').creationTimeDateTimeUtc}'
                      LastSeen_t: '@{utcNow()}'
                      ExpirationDateTime_t: '@{items(\'Process_MDTI_Indicators\').expirationDateTime}'
                      ThreatType_s: '@{if(contains(items(\'Process_MDTI_Indicators\').title, \':\'), last(split(items(\'Process_MDTI_Indicators\').title, \': \')), \'Unknown\')}'
                      Description_s: '@{items(\'Process_MDTI_Indicators\').description}'
                      TLP_s: 'TLP:AMBER'
                      Action_s: '@{items(\'Process_MDTI_Indicators\').action}'
                      DistributionTargets_s: 'Microsoft Sentinel, Microsoft Defender XDR'
                      Active_b: true
                    }
                    host: {
                      connection: {
                        name: '@parameters(\'$connections\')[\'azureloganalyticsdatacollector\'][\'connectionId\']'
                      }
                    }
                    method: 'post'
                    path: '/api/logs'
                    queries: {
                      logType: 'CTI_IPIndicators_CL'
                    }
                  }
                }
                Send_to_ThreatIntelIndicator: {
                  runAfter: {
                    Send_IP_to_Log_Analytics: [
                      'Succeeded'
                    ]
                  }
                  type: 'ApiConnection'
                  inputs: {
                    body: {
                      Type_s: 'ipv4-addr'
                      Value_s: '@{items(\'Process_MDTI_Indicators\').indicatorValue}'
                      Name_s: '@{items(\'Process_MDTI_Indicators\').title}'
                      Description_s: '@{items(\'Process_MDTI_Indicators\').description}'
                      Action_s: '@{toLower(items(\'Process_MDTI_Indicators\').action)}'
                      Confidence_d: '@{if(equals(items(\'Process_MDTI_Indicators\').severity, \'High\'), 90, if(equals(items(\'Process_MDTI_Indicators\').severity, \'Medium\'), 70, 50))}'
                      ValidFrom_t: '@{items(\'Process_MDTI_Indicators\').creationTimeDateTimeUtc}'
                      ValidUntil_t: '@{items(\'Process_MDTI_Indicators\').expirationDateTime}'
                      CreatedTimeUtc_t: '@{items(\'Process_MDTI_Indicators\').creationTimeDateTimeUtc}'
                      UpdatedTimeUtc_t: '@{utcNow()}'
                      Source_s: 'Microsoft Defender Threat Intelligence'
                      SourceRef_s: 'https://ti.defender.microsoft.com'
                      ThreatType_s: '@{if(contains(items(\'Process_MDTI_Indicators\').title, \':\'), last(split(items(\'Process_MDTI_Indicators\').title, \': \')), \'Unknown\')}'
                      TLP_s: 'TLP:AMBER'
                      DistributionTargets_s: 'Microsoft Sentinel, Microsoft Defender XDR'
                      Active_b: true
                      ObjectId_g: '@{items(\'Process_MDTI_Indicators\').id}'
                      IndicatorId_g: '@{guid()}'
                    }
                    host: {
                      connection: {
                        name: '@parameters(\'$connections\')[\'azureloganalyticsdatacollector\'][\'connectionId\']'
                      }
                    }
                    method: 'post'
                    path: '/api/logs'
                    queries: {
                      logType: 'CTI_ThreatIntelIndicator_CL'
                    }
                  }
                }
                Log_Transaction: {
                  runAfter: {
                    Send_to_ThreatIntelIndicator: [
                      'Succeeded'
                    ]
                  }
                  type: 'ApiConnection'
                  inputs: {
                    body: {
                      IndicatorType_s: 'IP'
                      IndicatorValue_s: '@{items(\'Process_MDTI_Indicators\').indicatorValue}'
                      Action_s: '@{items(\'Process_MDTI_Indicators\').action}'
                      TargetSystem_s: 'CTI Platform'
                      Status_s: 'Success'
                      Timestamp_t: '@{utcNow()}'
                      ActionId_g: '@{guid()}'
                      CorrelationId_g: '@{workflow()[\'run\'][\'name\']}'
                      IndicatorId_g: '@{items(\'Process_MDTI_Indicators\').id}'
                      RunbookName_s: 'CTI-MDTI-Connector'
                      TriggerSource_s: 'Scheduled'
                    }
                    host: {
                      connection: {
                        name: '@parameters(\'$connections\')[\'azureloganalyticsdatacollector\'][\'connectionId\']'
                      }
                    }
                    method: 'post'
                    path: '/api/logs'
                    queries: {
                      logType: 'CTI_TransactionLog_CL'
                    }
                  }
                }
              }
              runAfter: {}
              expression: {
                equals: [
                  '@items(\'Process_MDTI_Indicators\').indicatorType'
                  'IpAddress'
                ]
              }
              type: 'If'
            }
            Process_Domain_Indicator: {
              actions: {
                Send_Domain_to_Log_Analytics: {
                  runAfter: {}
                  type: 'ApiConnection'
                  inputs: {
                    body: {
                      Domain_s: '@{items(\'Process_MDTI_Indicators\').indicatorValue}'
                      ObjectId_g: '@{items(\'Process_MDTI_Indicators\').id}'
                      IndicatorId_g: '@{guid()}'
                      ConfidenceScore_d: '@{if(equals(items(\'Process_MDTI_Indicators\').severity, \'High\'), 90, if(equals(items(\'Process_MDTI_Indicators\').severity, \'Medium\'), 70, 50))}'
                      SourceFeed_s: 'Microsoft Defender Threat Intelligence'
                      FirstSeen_t: '@{items(\'Process_MDTI_Indicators\').creationTimeDateTimeUtc}'
                      LastSeen_t: '@{utcNow()}'
                      ExpirationDateTime_t: '@{items(\'Process_MDTI_Indicators\').expirationDateTime}'
                      ThreatType_s: '@{if(contains(items(\'Process_MDTI_Indicators\').title, \':\'), last(split(items(\'Process_MDTI_Indicators\').title, \': \')), \'Unknown\')}'
                      Description_s: '@{items(\'Process_MDTI_Indicators\').description}'
                      TLP_s: 'TLP:AMBER'
                      Action_s: '@{items(\'Process_MDTI_Indicators\').action}'
                      DistributionTargets_s: 'Microsoft Sentinel, Microsoft Defender XDR'
                      Active_b: true
                    }
                    host: {
                      connection: {
                        name: '@parameters(\'$connections\')[\'azureloganalyticsdatacollector\'][\'connectionId\']'
                      }
                    }
                    method: 'post'
                    path: '/api/logs'
                    queries: {
                      logType: 'CTI_DomainIndicators_CL'
                    }
                  }
                }
                Send_to_ThreatIntelIndicator_Domain: {
                  runAfter: {
                    Send_Domain_to_Log_Analytics: [
                      'Succeeded'
                    ]
                  }
                  type: 'ApiConnection'
                  inputs: {
                    body: {
                      Type_s: 'domain-name'
                      Value_s: '@{items(\'Process_MDTI_Indicators\').indicatorValue}'
                      Name_s: '@{items(\'Process_MDTI_Indicators\').title}'
                      Description_s: '@{items(\'Process_MDTI_Indicators\').description}'
                      Action_s: '@{toLower(items(\'Process_MDTI_Indicators\').action)}'
                      Confidence_d: '@{if(equals(items(\'Process_MDTI_Indicators\').severity, \'High\'), 90, if(equals(items(\'Process_MDTI_Indicators\').severity, \'Medium\'), 70, 50))}'
                      ValidFrom_t: '@{items(\'Process_MDTI_Indicators\').creationTimeDateTimeUtc}'
                      ValidUntil_t: '@{items(\'Process_MDTI_Indicators\').expirationDateTime}'
                      CreatedTimeUtc_t: '@{items(\'Process_MDTI_Indicators\').creationTimeDateTimeUtc}'
                      UpdatedTimeUtc_t: '@{utcNow()}'
                      Source_s: 'Microsoft Defender Threat Intelligence'
                      SourceRef_s: 'https://ti.defender.microsoft.com'
                      ThreatType_s: '@{if(contains(items(\'Process_MDTI_Indicators\').title, \':\'), last(split(items(\'Process_MDTI_Indicators\').title, \': \')), \'Unknown\')}'
                      TLP_s: 'TLP:AMBER'
                      DistributionTargets_s: 'Microsoft Sentinel, Microsoft Defender XDR'
                      Active_b: true
                      ObjectId_g: '@{items(\'Process_MDTI_Indicators\').id}'
                      IndicatorId_g: '@{guid()}'
                    }
                    host: {
                      connection: {
                        name: '@parameters(\'$connections\')[\'azureloganalyticsdatacollector\'][\'connectionId\']'
                      }
                    }
                    method: 'post'
                    path: '/api/logs'
                    queries: {
                      logType: 'CTI_ThreatIntelIndicator_CL'
                    }
                  }
                }
                Log_Transaction_Domain: {
                  runAfter: {
                    Send_to_ThreatIntelIndicator_Domain: [
                      'Succeeded'
                    ]
                  }
                  type: 'ApiConnection'
                  inputs: {
                    body: {
                      IndicatorType_s: 'Domain'
                      IndicatorValue_s: '@{items(\'Process_MDTI_Indicators\').indicatorValue}'
                      Action_s: '@{items(\'Process_MDTI_Indicators\').action}'
                      TargetSystem_s: 'CTI Platform'
                      Status_s: 'Success'
                      Timestamp_t: '@{utcNow()}'
                      ActionId_g: '@{guid()}'
                      CorrelationId_g: '@{workflow()[\'run\'][\'name\']}'
                      IndicatorId_g: '@{items(\'Process_MDTI_Indicators\').id}'
                      RunbookName_s: 'CTI-MDTI-Connector'
                      TriggerSource_s: 'Scheduled'
                    }
                    host: {
                      connection: {
                        name: '@parameters(\'$connections\')[\'azureloganalyticsdatacollector\'][\'connectionId\']'
                      }
                    }
                    method: 'post'
                    path: '/api/logs'
                    queries: {
                      logType: 'CTI_TransactionLog_CL'
                    }
                  }
                }
              }
              runAfter: {
                Process_IP_Indicator: [
                  'Succeeded'
                ]
              }
              expression: {
                equals: [
                  '@items(\'Process_MDTI_Indicators\').indicatorType'
                  'DomainName'
                ]
              }
              type: 'If'
            }
            Process_FileHash_Indicator: {
              actions: {
                Send_FileHash_to_Log_Analytics: {
                  runAfter: {}
                  type: 'ApiConnection'
                  inputs: {
                    body: {
                      SHA256_s: '@{items(\'Process_MDTI_Indicators\').indicatorValue}'
                      ObjectId_g: '@{items(\'Process_MDTI_Indicators\').id}'
                      IndicatorId_g: '@{guid()}'
                      ConfidenceScore_d: '@{if(equals(items(\'Process_MDTI_Indicators\').severity, \'High\'), 90, if(equals(items(\'Process_MDTI_Indicators\').severity, \'Medium\'), 70, 50))}'
                      SourceFeed_s: 'Microsoft Defender Threat Intelligence'
                      FirstSeen_t: '@{items(\'Process_MDTI_Indicators\').creationTimeDateTimeUtc}'
                      LastSeen_t: '@{utcNow()}'
                      ExpirationDateTime_t: '@{items(\'Process_MDTI_Indicators\').expirationDateTime}'
                      ThreatType_s: '@{if(contains(items(\'Process_MDTI_Indicators\').title, \':\'), last(split(items(\'Process_MDTI_Indicators\').title, \': \')), \'Unknown\')}'
                      MalwareFamily_s: '@{if(contains(items(\'Process_MDTI_Indicators\').title, \':\'), last(split(items(\'Process_MDTI_Indicators\').title, \': \')), \'Unknown\')}'
                      Description_s: '@{items(\'Process_MDTI_Indicators\').description}'
                      TLP_s: 'TLP:AMBER'
                      Action_s: '@{items(\'Process_MDTI_Indicators\').action}'
                      DistributionTargets_s: 'Microsoft Sentinel, Microsoft Defender XDR'
                      Active_b: true
                    }
                    host: {
                      connection: {
                        name: '@parameters(\'$connections\')[\'azureloganalyticsdatacollector\'][\'connectionId\']'
                      }
                    }
                    method: 'post'
                    path: '/api/logs'
                    queries: {
                      logType: 'CTI_FileHashIndicators_CL'
                    }
                  }
                }
                Send_to_ThreatIntelIndicator_Hash: {
                  runAfter: {
                    Send_FileHash_to_Log_Analytics: [
                      'Succeeded'
                    ]
                  }
                  type: 'ApiConnection'
                  inputs: {
                    body: {
                      Type_s: 'file-hash-sha256'
                      Value_s: '@{items(\'Process_MDTI_Indicators\').indicatorValue}'
                      Name_s: '@{items(\'Process_MDTI_Indicators\').title}'
                      Description_s: '@{items(\'Process_MDTI_Indicators\').description}'
                      Action_s: '@{toLower(items(\'Process_MDTI_Indicators\').action)}'
                      Confidence_d: '@{if(equals(items(\'Process_MDTI_Indicators\').severity, \'High\'), 90, if(equals(items(\'Process_MDTI_Indicators\').severity, \'Medium\'), 70, 50))}'
                      ValidFrom_t: '@{items(\'Process_MDTI_Indicators\').creationTimeDateTimeUtc}'
                      ValidUntil_t: '@{items(\'Process_MDTI_Indicators\').expirationDateTime}'
                      CreatedTimeUtc_t: '@{items(\'Process_MDTI_Indicators\').creationTimeDateTimeUtc}'
                      UpdatedTimeUtc_t: '@{utcNow()}'
                      Source_s: 'Microsoft Defender Threat Intelligence'
                      SourceRef_s: 'https://ti.defender.microsoft.com'
                      ThreatType_s: '@{if(contains(items(\'Process_MDTI_Indicators\').title, \':\'), last(split(items(\'Process_MDTI_Indicators\').title, \': \')), \'Unknown\')}'
                      TLP_s: 'TLP:AMBER'
                      DistributionTargets_s: 'Microsoft Sentinel, Microsoft Defender XDR'
                      Active_b: true
                      ObjectId_g: '@{items(\'Process_MDTI_Indicators\').id}'
                      IndicatorId_g: '@{guid()}'
                    }
                    host: {
                      connection: {
                        name: '@parameters(\'$connections\')[\'azureloganalyticsdatacollector\'][\'connectionId\']'
                      }
                    }
                    method: 'post'
                    path: '/api/logs'
                    queries: {
                      logType: 'CTI_ThreatIntelIndicator_CL'
                    }
                  }
                }
                Log_Transaction_FileHash: {
                  runAfter: {
                    Send_to_ThreatIntelIndicator_Hash: [
                      'Succeeded'
                    ]
                  }
                  type: 'ApiConnection'
                  inputs: {
                    body: {
                      IndicatorType_s: 'FileHash'
                      IndicatorValue_s: '@{items(\'Process_MDTI_Indicators\').indicatorValue}'
                      Action_s: '@{items(\'Process_MDTI_Indicators\').action}'
                      TargetSystem_s: 'CTI Platform'
                      Status_s: 'Success'
                      Timestamp_t: '@{utcNow()}'
                      ActionId_g: '@{guid()}'
                      CorrelationId_g: '@{workflow()[\'run\'][\'name\']}'
                      IndicatorId_g: '@{items(\'Process_MDTI_Indicators\').id}'
                      RunbookName_s: 'CTI-MDTI-Connector'
                      TriggerSource_s: 'Scheduled'
                    }
                    host: {
                      connection: {
                        name: '@parameters(\'$connections\')[\'azureloganalyticsdatacollector\'][\'connectionId\']'
                      }
                    }
                    method: 'post'
                    path: '/api/logs'
                    queries: {
                      logType: 'CTI_TransactionLog_CL'
                    }
                  }
                }
              }
              runAfter: {
                Process_Domain_Indicator: [
                  'Succeeded'
                ]
              }
              expression: {
                or: [
                  {
                    equals: [
                      '@items(\'Process_MDTI_Indicators\').indicatorType'
                      'FileSha256'
                    ]
                  }
                  {
                    equals: [
                      '@items(\'Process_MDTI_Indicators\').indicatorType'
                      'FileSha1'
                    ]
                  }
                  {
                    equals: [
                      '@items(\'Process_MDTI_Indicators\').indicatorType'
                      'FileMd5'
                    ]
                  }
                ]
              }
              type: 'If'
            }
            Handle_Error: {
              actions: {
                Log_Error: {
                  runAfter: {}
                  type: 'ApiConnection'
                  inputs: {
                    body: {
                      IndicatorType_s: '@{items(\'Process_MDTI_Indicators\').indicatorType}'
                      IndicatorValue_s: '@{items(\'Process_MDTI_Indicators\').indicatorValue}'
                      Action_s: '@{items(\'Process_MDTI_Indicators\').action}'
                      TargetSystem_s: 'CTI Platform'
                      Status_s: 'Failed'
                      ErrorMessage_s: 'Failed to process indicator'
                      ErrorCode_s: '500'
                      ErrorDetails_s: '@{string(items(\'Process_MDTI_Indicators\'))}'
                      Timestamp_t: '@{utcNow()}'
                      ActionId_g: '@{guid()}'
                      CorrelationId_g: '@{workflow()[\'run\'][\'name\']}'
                      IndicatorId_g: '@{items(\'Process_MDTI_Indicators\').id}'
                      RunbookName_s: 'CTI-MDTI-Connector'
                      TriggerSource_s: 'Scheduled'
                    }
                    host: {
                      connection: {
                        name: '@parameters(\'$connections\')[\'azureloganalyticsdatacollector\'][\'connectionId\']'
                      }
                    }
                    method: 'post'
                    path: '/api/logs'
                    queries: {
                      logType: 'CTI_TransactionLog_CL'
                    }
                  }
                }
              }
              runAfter: {
                Process_FileHash_Indicator: [
                  'Failed'
                ]
              }
              type: 'Scope'
            }
          }
          runAfter: {
            Parse_MDTI_Response: [
              'Succeeded'
            ]
          }
          type: 'Foreach'
          runtimeConfiguration: {
            concurrency: {
              repetitions: 20  // Increased from default for better performance
            }
            staticResult: {
              staticResultOptions: 'Disabled'  // Added for performance
            }
          }
        }
        Handle_Main_Error: {
          actions: {
            Log_Main_Error: {
              runAfter: {}
              type: 'ApiConnection'
              inputs: {
                body: {
                  ErrorSource_s: 'MDTI-Connector'
                  ErrorMessage_s: 'Failed to retrieve MDTI indicators'
                  ErrorCode_s: '@{outputs(\'Get_MDTI_Indicators\')?[\'statusCode\']}'
                  ErrorDetails_s: '@{outputs(\'Get_MDTI_Indicators\')?[\'body\']}'
                  Timestamp_t: '@{utcNow()}'
                  ActionId_g: '@{guid()}'
                  CorrelationId_g: '@{workflow()[\'run\'][\'name\']}'
                  RunbookName_s: 'CTI-MDTI-Connector'
                  TriggerSource_s: 'Scheduled'
                }
                host: {
                  connection: {
                    name: '@parameters(\'$connections\')[\'azureloganalyticsdatacollector\'][\'connectionId\']'
                  }
                }
                method: 'post'
                path: '/api/logs'
                queries: {
                  logType: 'CTI_TransactionLog_CL'
                }
              }
            }
          }
          runAfter: {
            Get_MDTI_Indicators: [
              'Failed'
            ]
          }
          type: 'Scope'
        }
      }
    }
    parameters: {
      '$connections': {
        value: {
          azureloganalyticsdatacollector: {
            connectionId: logAnalyticsConnection.id
            connectionName: logAnalyticsConnection.name
            id: subscriptionResourceId('Microsoft.Web/locations/managedApis', location, 'azureloganalyticsdatacollector')
          }
          azuremonitorlogs: {
            connectionId: logAnalyticsQueryConnection.id
            connectionName: logAnalyticsQueryConnection.name
            id: subscriptionResourceId('Microsoft.Web/locations/managedApis', location, 'azuremonitorlogs')
          }
        }
      }
    }
  }
  dependsOn: [
    defenderEndpointConnector
  ]
}

// Add diagnostic settings for MDTI connector
resource mdtiConnectorDiagnostics 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = if (enableMDTI) {
  scope: mdtiConnectorLogicApp
  name: 'diagnostics'
  properties: {
    workspaceId: ctiWorkspace.id
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

// Microsoft Entra ID Connector
resource entraIDConnectorLogicApp 'Microsoft.Logic/workflows@2019-05-01' = {
  name: entraIDConnectorLogicAppName
  location: location
  tags: tags
  identity: {
    type: 'UserAssigned'
    userAssignedIdentities: {
      '${managedIdentity.id}': {}
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
        'graphApiUrl': {
          defaultValue: graphApiUrl
          type: 'String'
        }
      }
      triggers: {
        Recurrence: {
          recurrence: {
            frequency: 'Day'
            interval: 1
          }
          type: 'Recurrence'
        }
      }
      actions: {
        Get_High_Risk_Users: {
          runAfter: {}
          type: 'ApiConnection'
          inputs: {
            host: {
              connection: {
                name: '@parameters(\'$connections\')[\'microsoftgraph\'][\'connectionId\']'
              }
            }
            method: 'get'
            path: '/v1.0/identityProtection/riskyUsers'
            queries: {
              $filter: 'riskLevel eq \'high\''
              $select: 'id,userPrincipalName,riskLevel,riskState,riskDetail,riskLastUpdatedDateTime'
            }
          }
        }
        Process_Risky_Users: {
          foreach: '@body(\'Get_High_Risk_Users\')?[\'value\']'
          actions: {
            Send_to_Log_Analytics: {
              runAfter: {}
              type: 'ApiConnection'
              inputs: {
                body: {
                  EmailAddress_s: '@{items(\'Process_Risky_Users\')?[\'userPrincipalName\']}'
                  ObjectId_g: '@{items(\'Process_Risky_Users\')?[\'id\']}'
                  IndicatorId_g: '@{guid()}'
                  ConfidenceScore_d: 90
                  SourceFeed_s: 'Microsoft Entra ID'
                  FirstSeen_t: '@{items(\'Process_Risky_Users\')?[\'riskLastUpdatedDateTime\']}'
                  LastSeen_t: '@{utcNow()}'
                  ExpirationDateTime_t: '@{addDays(utcNow(), 7)}'
                  ThreatType_s: '@{items(\'Process_Risky_Users\')?[\'riskDetail\']}'
                  Description_s: 'High risk user detected by Microsoft Entra ID'
                  TLP_s: 'TLP:AMBER'
                  Action_s: 'Alert'
                  DistributionTargets_s: 'Microsoft Sentinel'
                  Active_b: true
                }
                host: {
                  connection: {
                    name: '@parameters(\'$connections\')[\'azureloganalyticsdatacollector\'][\'connectionId\']'
                  }
                }
                method: 'post'
                path: '/api/logs'
                queries: {
                  logType: 'CTI_EmailIndicators_CL'
                }
              }
            }
            Send_to_ThreatIntelIndicator: {
              runAfter: {
                Send_to_Log_Analytics: [
                  'Succeeded'
                ]
              }
              type: 'ApiConnection'
              inputs: {
                body: {
                  Type_s: 'email-addr'
                  Value_s: '@{items(\'Process_Risky_Users\')?[\'userPrincipalName\']}'
                  Name_s: 'High risk user - @{items(\'Process_Risky_Users\')?[\'userPrincipalName\']}'
                  Description_s: 'High risk user detected by Microsoft Entra ID. Risk type: @{items(\'Process_Risky_Users\')?[\'riskDetail\']}'
                  Action_s: 'alert'
                  Confidence_d: 90
                  ValidFrom_t: '@{items(\'Process_Risky_Users\')?[\'riskLastUpdatedDateTime\']}'
                  ValidUntil_t: '@{addDays(utcNow(), 7)}'
                  CreatedTimeUtc_t: '@{items(\'Process_Risky_Users\')?[\'riskLastUpdatedDateTime\']}'
                  UpdatedTimeUtc_t: '@{utcNow()}'
                  Source_s: 'Microsoft Entra ID'
                  SourceRef_s: '@{parameters(\'graphApiUrl\')}/identityProtection/riskyUsers'
                  ThreatType_s: '@{items(\'Process_Risky_Users\')?[\'riskDetail\']}'
                  TLP_s: 'TLP:AMBER'
                  DistributionTargets_s: 'Microsoft Sentinel'
                  Active_b: true
                  ObjectId_g: '@{items(\'Process_Risky_Users\')?[\'id\']}'
                  IndicatorId_g: '@{guid()}'
                }
                host: {
                  connection: {
                    name: '@parameters(\'$connections\')[\'azureloganalyticsdatacollector\'][\'connectionId\']'
                  }
                }
                method: 'post'
                path: '/api/logs'
                queries: {
                  logType: 'CTI_ThreatIntelIndicator_CL'
                }
              }
            }
            Log_Transaction: {
              runAfter: {
                Send_to_ThreatIntelIndicator: [
                  'Succeeded'
                ]
              }
              type: 'ApiConnection'
              inputs: {
                body: {
                  IndicatorType_s: 'Email'
                  IndicatorValue_s: '@{items(\'Process_Risky_Users\')?[\'userPrincipalName\']}'
                  Action_s: 'Alert'
                  TargetSystem_s: 'CTI Platform'
                  Status_s: 'Success'
                  Timestamp_t: '@{utcNow()}'
                  ActionId_g: '@{guid()}'
                  CorrelationId_g: '@{workflow()[\'run\'][\'name\']}'
                  IndicatorId_g: '@{guid()}'
                  RunbookName_s: 'CTI-EntraID-Connector'
                  TriggerSource_s: 'Scheduled'
                }
                host: {
                  connection: {
                    name: '@parameters(\'$connections\')[\'azureloganalyticsdatacollector\'][\'connectionId\']'
                  }
                }
                method: 'post'
                path: '/api/logs'
                queries: {
                  logType: 'CTI_TransactionLog_CL'
                }
              }
            }
            Handle_Error: {
              actions: {
                Log_Error: {
                  runAfter: {}
                  type: 'ApiConnection'
                  inputs: {
                    body: {
                      IndicatorType_s: 'Email'
                      IndicatorValue_s: '@{items(\'Process_Risky_Users\')?[\'userPrincipalName\']}'
                      Action_s: 'Alert'
                      TargetSystem_s: 'CTI Platform'
                      Status_s: 'Failed'
                      ErrorMessage_s: 'Failed to process risky user'
                      ErrorCode_s: '500'
                      ErrorDetails_s: '@{string(items(\'Process_Risky_Users\'))}'
                      Timestamp_t: '@{utcNow()}'
                      ActionId_g: '@{guid()}'
                      CorrelationId_g: '@{workflow()[\'run\'][\'name\']}'
                      RunbookName_s: 'CTI-EntraID-Connector'
                      TriggerSource_s: 'Scheduled'
                    }
                    host: {
                      connection: {
                        name: '@parameters(\'$connections\')[\'azureloganalyticsdatacollector\'][\'connectionId\']'
                      }
                    }
                    method: 'post'
                    path: '/api/logs'
                    queries: {
                      logType: 'CTI_TransactionLog_CL'
                    }
                  }
                }
              }
              runAfter: {
                Send_to_Log_Analytics: [
                  'Failed'
                ]
              }
              type: 'Scope'
            }
          }
          runAfter: {
            Get_High_Risk_Users: [
              'Succeeded'
            ]
          }
          type: 'Foreach'
          runtimeConfiguration: {
            concurrency: {
              repetitions: 20  // Increased for better performance
            }
            staticResult: {
              staticResultOptions: 'Disabled'  // Added for performance
            }
          }
        }
        Handle_Main_Error: {
          actions: {
            Log_Main_Error: {
              runAfter: {}
              type: 'ApiConnection'
              inputs: {
                body: {
                  ErrorSource_s: 'EntraID-Connector'
                  ErrorMessage_s: 'Failed to retrieve risky users'
                  ErrorCode_s: '@{outputs(\'Get_High_Risk_Users\')?[\'statusCode\']}'
                  ErrorDetails_s: '@{outputs(\'Get_High_Risk_Users\')?[\'body\']}'
                  Timestamp_t: '@{utcNow()}'
                  ActionId_g: '@{guid()}'
                  CorrelationId_g: '@{workflow()[\'run\'][\'name\']}'
                  RunbookName_s: 'CTI-EntraID-Connector'
                  TriggerSource_s: 'Scheduled'
                }
                host: {
                  connection: {
                    name: '@parameters(\'$connections\')[\'azureloganalyticsdatacollector\'][\'connectionId\']'
                  }
                }
                method: 'post'
                path: '/api/logs'
                queries: {
                  logType: 'CTI_TransactionLog_CL'
                }
              }
            }
          }
          runAfter: {
            Get_High_Risk_Users: [
              'Failed'
            ]
          }
          type: 'Scope'
        }
      }
    }
    parameters: {
      '$connections': {
        value: {
          azureloganalyticsdatacollector: {
            connectionId: logAnalyticsConnection.id
            connectionName: logAnalyticsConnection.name
            id: subscriptionResourceId('Microsoft.Web/locations/managedApis', location, 'azureloganalyticsdatacollector')
          }
          microsoftgraph: {
            connectionId: microsoftGraphConnection.id
            connectionName: microsoftGraphConnection.name
            id: subscriptionResourceId('Microsoft.Web/locations/managedApis', location, 'microsoftgraph')
          }
        }
      }
    }
  }
  dependsOn: [
    mdtiConnectorLogicApp
  ]
}

// Add diagnostic settings for Entra ID connector
resource entraIDConnectorDiagnostics 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = {
  scope: entraIDConnectorLogicApp
  name: 'diagnostics'
  properties: {
    workspaceId: ctiWorkspace.id
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

// Exchange Online Connector
resource exoConnectorLogicApp 'Microsoft.Logic/workflows@2019-05-01' = {
  name: exoConnectorLogicAppName
  location: location
  tags: tags
  identity: {
    type: 'UserAssigned'
    userAssignedIdentities: {
      '${managedIdentity.id}': {}
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
      }
      triggers: {
        Recurrence: {
          recurrence: {
            frequency: 'Hour'
            interval: 12
          }
          type: 'Recurrence'
        }
      }
      actions: {
        Get_High_Confidence_Indicators: {
          runAfter: {}
          type: 'ApiConnection'
          inputs: {
            body: 'CTI_ThreatIntelIndicator_CL \n| where Confidence_d >= 85 and Active_b == true\n| where TimeGenerated > ago(1d)\n| where "Exchange Online" in (split(DistributionTargets_s, ", "))\n| where Type_s in ("domain-name", "url", "email-addr", "ipv4-addr")\n| project Type_s, Value_s, Confidence_d, ThreatType_s, Description_s, Action_s, IndicatorId_g\n| limit 500'
            host: {
              connection: {
                name: '@parameters(\'$connections\')[\'azuremonitorlogs\'][\'connectionId\']'
              }
            }
            method: 'post'
            path: '/queryData'
            queries: {
              resourcegroups: '@resourceGroup().name'
              resourcename: '@{parameters(\'workspaceName\')}'
              resourcetype: 'Log Analytics Workspace'
              subscriptions: '@{subscription().subscriptionId}'
              timerange: 'Last day'
            }
          }
        }
        Process_EXO_Indicators: {
          foreach: '@body(\'Get_High_Confidence_Indicators\').tables[0].rows'
          actions: {
            Submit_to_EXO: {
              runAfter: {}
              type: 'ApiConnection'
              inputs: {
                host: {
                  connection: {
                    name: '@parameters(\'$connections\')[\'microsoftgraph\'][\'connectionId\']'
                  }
                }
                method: 'post'
                path: '/v1.0/security/threatIntelligence/blockedSenders'
                body: {
                  senderAddress: '@{if(equals(item()[0], \'email-addr\'), item()[1], if(equals(item()[0], \'domain-name\'), concat(\'*@\', item()[1]), \'\'))}'
                  senderDomain: '@{if(equals(item()[0], \'domain-name\'), item()[1], \'\')}'
                  senderIP: '@{if(equals(item()[0], \'ipv4-addr\'), item()[1], \'\')}'
                  threatType: '@{if(empty(item()[3]), \'Malware\', item()[3])}'
                  confidenceLevel: '@{if(greater(item()[2], 90), \'High\', if(greater(item()[2], 70), \'Medium\', \'Low\'))}'
                  note: '@{if(empty(item()[4]), concat(\'Added by CTI platform - ThreatType: \', item()[3]), item()[4])}'
                }
              }
            }
            Log_Transaction: {
              runAfter: {
                Submit_to_EXO: [
                  'Succeeded'
                ]
              }
              type: 'ApiConnection'
              inputs: {
                body: {
                  IndicatorType_s: '@{item()[0]}'
                  IndicatorValue_s: '@{item()[1]}'
                  Action_s: '@{item()[5]}'
                  TargetSystem_s: 'Exchange Online'
                  Status_s: 'Success'
                  Timestamp_t: '@{utcNow()}'
                  ActionId_g: '@{guid()}'
                  CorrelationId_g: '@{workflow()[\'run\'][\'name\']}'
                  IndicatorId_g: '@{item()[6]}'
                  RunbookName_s: 'CTI-ExchangeOnline-Connector'
                  TriggerSource_s: 'Scheduled'
                }
                host: {
                  connection: {
                    name: '@parameters(\'$connections\')[\'azureloganalyticsdatacollector\'][\'connectionId\']'
                  }
                }
                method: 'post'
                path: '/api/logs'
                queries: {
                  logType: 'CTI_TransactionLog_CL'
                }
              }
            }
            Handle_Error: {
              actions: {
                Log_Error: {
                  runAfter: {}
                  type: 'ApiConnection'
                  inputs: {
                    body: {
                      IndicatorType_s: '@{item()[0]}'
                      IndicatorValue_s: '@{item()[1]}'
                      Action_s: '@{item()[5]}'
                      TargetSystem_s: 'Exchange Online'
                      Status_s: 'Failed'
                      ErrorMessage_s: '@{outputs(\'Submit_to_EXO\')[\'body\']}'
                      ErrorCode_s: '@{outputs(\'Submit_to_EXO\')?[\'statusCode\']}'
                      ErrorDetails_s: '@{string(outputs(\'Submit_to_EXO\'))}'
                      Timestamp_t: '@{utcNow()}'
                      ActionId_g: '@{guid()}'
                      CorrelationId_g: '@{workflow()[\'run\'][\'name\']}'
                      IndicatorId_g: '@{item()[6]}'
                      RunbookName_s: 'CTI-ExchangeOnline-Connector'
                      TriggerSource_s: 'Scheduled'
                    }
                    host: {
                      connection: {
                        name: '@parameters(\'$connections\')[\'azureloganalyticsdatacollector\'][\'connectionId\']'
                      }
                    }
                    method: 'post'
                    path: '/api/logs'
                    queries: {
                      logType: 'CTI_TransactionLog_CL'
                    }
                  }
                }
              }
              runAfter: {
                Submit_to_EXO: [
                  'Failed'
                ]
              }
              type: 'Scope'
            }
          }
          runAfter: {
            Get_High_Confidence_Indicators: [
              'Succeeded'
            ]
          }
          type: 'Foreach'
          runtimeConfiguration: {
            concurrency: {
              repetitions: 20  // Increased for better performance
            }
            staticResult: {
              staticResultOptions: 'Disabled'  // Added for performance
            }
          }
        }
        Handle_Main_Error: {
          actions: {
            Log_Main_Error: {
              runAfter: {}
              type: 'ApiConnection'
              inputs: {
                body: {
                  ErrorSource_s: 'ExchangeOnline-Connector'
                  ErrorMessage_s: 'Failed to retrieve indicators'
                  ErrorCode_s: '@{outputs(\'Get_High_Confidence_Indicators\')?[\'statusCode\']}'
                  ErrorDetails_s: '@{outputs(\'Get_High_Confidence_Indicators\')?[\'body\']}'
                  Timestamp_t: '@{utcNow()}'
                  ActionId_g: '@{guid()}'
                  CorrelationId_g: '@{workflow()[\'run\'][\'name\']}'
                  RunbookName_s: 'CTI-ExchangeOnline-Connector'
                  TriggerSource_s: 'Scheduled'
                }
                host: {
                  connection: {
                    name: '@parameters(\'$connections\')[\'azureloganalyticsdatacollector\'][\'connectionId\']'
                  }
                }
                method: 'post'
                path: '/api/logs'
                queries: {
                  logType: 'CTI_TransactionLog_CL'
                }
              }
            }
          }
          runAfter: {
            Get_High_Confidence_Indicators: [
              'Failed'
            ]
          }
          type: 'Scope'
        }
      }
    }
    parameters: {
      '$connections': {
        value: {
          azureloganalyticsdatacollector: {
            connectionId: logAnalyticsConnection.id
            connectionName: logAnalyticsConnection.name
            id: subscriptionResourceId('Microsoft.Web/locations/managedApis', location, 'azureloganalyticsdatacollector')
          }
          azuremonitorlogs: {
            connectionId: logAnalyticsQueryConnection.id
            connectionName: logAnalyticsQueryConnection.name
            id: subscriptionResourceId('Microsoft.Web/locations/managedApis', location, 'azuremonitorlogs')
          }
          microsoftgraph: {
            connectionId: microsoftGraphConnection.id
            connectionName: microsoftGraphConnection.name
            id: subscriptionResourceId('Microsoft.Web/locations/managedApis', location, 'microsoftgraph')
          }
        }
      }
    }
  }
  dependsOn: [
    entraIDConnectorLogicApp
  ]
}

// Add diagnostic settings for Exchange Online connector
resource exoConnectorDiagnostics 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = {
  scope: exoConnectorLogicApp
  name: 'diagnostics'
  properties: {
    workspaceId: ctiWorkspace.id
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

// Security Copilot Connector - Conditional
resource securityCopilotConnector 'Microsoft.Logic/workflows@2019-05-01' = if (enableSecurityCopilot) {
  name: securityCopilotConnectorName
  location: location
  tags: tags
  identity: {
    type: 'UserAssigned'
    userAssignedIdentities: {
      '${managedIdentity.id}': {}
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
      }
      triggers: {
        Recurrence: {
          recurrence: {
            frequency: 'Day'
            interval: 1
          }
          type: 'Recurrence'
        }
      }
      actions: {
        Get_Intelligence: {
          runAfter: {}
          type: 'ApiConnection'
          inputs: {
            body: 'CTI_ThreatIntelIndicator_CL \n| where TimeGenerated > ago(7d)\n| where Active_b == true\n| where Source_s != "Microsoft Security Copilot"\n| order by Confidence_d desc\n| project Type_s, Value_s, Description_s, Source_s, ThreatType_s, Confidence_d, IndicatorId_g, ValidFrom_t\n| limit 100'
            host: {
              connection: {
                name: '@parameters(\'$connections\')[\'azuremonitorlogs\'][\'connectionId\']'
              }
            }
            method: 'post'
            path: '/queryData'
            queries: {
              resourcegroups: '@resourceGroup().name'
              resourcename: '@{parameters(\'workspaceName\')}'
              resourcetype: 'Log Analytics Workspace'
              subscriptions: '@{subscription().subscriptionId}'
              timerange: 'Last 7 days'
            }
          }
        }
        Process_For_Copilot: {
          foreach: '@body(\'Get_Intelligence\').tables[0].rows'
          actions: {
            Format_For_DCR: {
              runAfter: {}
              type: 'Compose'
              inputs: {
                timestamp: '@{utcNow()}'
                indicatorType: '@{item()[0]}'
                indicatorValue: '@{item()[1]}'
                description: '@{if(empty(item()[2]), concat(\'Threat type: \', item()[4]), item()[2])}'
                source: '@{item()[3]}'
                confidence: '@{item()[5]}'
                firstObserved: '@{item()[7]}'
                id: '@{item()[6]}'
              }
            }
            Log_To_Copilot_DCE: {
              runAfter: {
                Format_For_DCR: [
                  'Succeeded'
                ]
              }
              type: 'Http'
              inputs: {
                method: 'POST'
                uri: 'https://@{dceNameForCopilot}.@{location}-1.ingest.monitor.azure.com/dataCollectionRules/@{dceCopilotIntegrationName}/streams/Custom-CTIThreatIndicators_CL?api-version=2021-11-01-preview'
                headers: {
                  'Content-Type': 'application/json'
                  'Authorization': 'Bearer @{listKeys(resourceId(\'Microsoft.OperationalInsights/workspaces\', ctiWorkspaceName), \'2022-10-01\').primarySharedKey}'
                }
                body: '@outputs(\'Format_For_DCR\')'
                retryPolicy: {
                  type: 'fixed'
                  count: 3
                  interval: 'PT30S'
                }
              }
            }
            Log_Transaction: {
              runAfter: {
                Log_To_Copilot_DCE: [
                  'Succeeded'
                ]
              }
              type: 'ApiConnection'
              inputs: {
                body: {
                  IndicatorType_s: '@{item()[0]}'
                  IndicatorValue_s: '@{item()[1]}'
                  Action_s: 'Share'
                  TargetSystem_s: 'Microsoft Security Copilot'
                  Status_s: 'Success'
                  Timestamp_t: '@{utcNow()}'
                  ActionId_g: '@{guid()}'
                  CorrelationId_g: '@{workflow()[\'run\'][\'name\']}'
                  IndicatorId_g: '@{item()[6]}'
                  RunbookName_s: 'CTI-SecurityCopilot-Connector'
                  TriggerSource_s: 'Scheduled'
                }
                host: {
                  connection: {
                    name: '@parameters(\'$connections\')[\'azureloganalyticsdatacollector\'][\'connectionId\']'
                  }
                }
                method: 'post'
                path: '/api/logs'
                queries: {
                  logType: 'CTI_TransactionLog_CL'
                }
              }
            }
            Handle_Error: {
              actions: {
                Log_Error: {
                  runAfter: {}
                  type: 'ApiConnection'
                  inputs: {
                    body: {
                      IndicatorType_s: '@{item()[0]}'
                      IndicatorValue_s: '@{item()[1]}'
                      Action_s: 'Share'
                      TargetSystem_s: 'Microsoft Security Copilot'
                      Status_s: 'Failed'
                      ErrorMessage_s: '@{outputs(\'Log_To_Copilot_DCE\')[\'body\']}'
                      ErrorCode_s: '@{outputs(\'Log_To_Copilot_DCE\')?[\'statusCode\']}'
                      ErrorDetails_s: '@{string(outputs(\'Log_To_Copilot_DCE\'))}'
                      Timestamp_t: '@{utcNow()}'
                      ActionId_g: '@{guid()}'
                      CorrelationId_g: '@{workflow()[\'run\'][\'name\']}'
                      IndicatorId_g: '@{item()[6]}'
                      RunbookName_s: 'CTI-SecurityCopilot-Connector'
                      TriggerSource_s: 'Scheduled'
                    }
                    host: {
                      connection: {
                        name: '@parameters(\'$connections\')[\'azureloganalyticsdatacollector\'][\'connectionId\']'
                      }
                    }
                    method: 'post'
                    path: '/api/logs'
                    queries: {
                      logType: 'CTI_TransactionLog_CL'
                    }
                  }
                }
              }
              runAfter: {
                Log_To_Copilot_DCE: [
                  'Failed'
                ]
              }
              type: 'Scope'
            }
          }
          runAfter: {
            Get_Intelligence: [
              'Succeeded'
            ]
          }
          type: 'Foreach'
          runtimeConfiguration: {
            concurrency: {
              repetitions: 20  // Increased for better performance
            }
            staticResult: {
              staticResultOptions: 'Disabled'  // Added for performance
            }
          }
        }
        Handle_Main_Error: {
          actions: {
            Log_Main_Error: {
              runAfter: {}
              type: 'ApiConnection'
              inputs: {
                body: {
                  ErrorSource_s: 'SecurityCopilot-Connector'
                  ErrorMessage_s: 'Failed to retrieve intelligence'
                  ErrorCode_s: '@{outputs(\'Get_Intelligence\')?[\'statusCode\']}'
                  ErrorDetails_s: '@{outputs(\'Get_Intelligence\')?[\'body\']}'
                  Timestamp_t: '@{utcNow()}'
                  ActionId_g: '@{guid()}'
                  CorrelationId_g: '@{workflow()[\'run\'][\'name\']}'
                  RunbookName_s: 'CTI-SecurityCopilot-Connector'
                  TriggerSource_s: 'Scheduled'
                }
                host: {
                  connection: {
                    name: '@parameters(\'$connections\')[\'azureloganalyticsdatacollector\'][\'connectionId\']'
                  }
                }
                method: 'post'
                path: '/api/logs'
                queries: {
                  logType: 'CTI_TransactionLog_CL'
                }
              }
            }
          }
          runAfter: {
            Get_Intelligence: [
              'Failed'
            ]
          }
          type: 'Scope'
        }
      }
    }
    parameters: {
      '$connections': {
        value: {
          azureloganalyticsdatacollector: {
            connectionId: logAnalyticsConnection.id
            connectionName: logAnalyticsConnection.name
            id: subscriptionResourceId('Microsoft.Web/locations/managedApis', location, 'azureloganalyticsdatacollector')
          }
          azuremonitorlogs: {
            connectionId: logAnalyticsQueryConnection.id
            connectionName: logAnalyticsQueryConnection.name
            id: subscriptionResourceId('Microsoft.Web/locations/managedApis', location, 'azuremonitorlogs')
          }
        }
      }
    }
  }
  dependsOn: [
    exoConnectorLogicApp
  ]
}

// Add diagnostic settings for Security Copilot connector
resource securityCopilotConnectorDiagnostics 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = if (enableSecurityCopilot) {
  scope: securityCopilotConnector
  name: 'diagnostics'
  properties: {
    workspaceId: ctiWorkspace.id
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

// Data Collection Endpoint for Security Copilot integration
resource dce 'Microsoft.Insights/dataCollectionEndpoints@2021-09-01-preview' = if (enableSecurityCopilot) {
  name: dceNameForCopilot
  location: location
  tags: tags
  kind: 'Windows'
  properties: {
    networkAcls: {
      publicNetworkAccess: 'Enabled'
    }
  }
}

// Housekeeping Logic App
resource housekeepingLogicApp 'Microsoft.Logic/workflows@2019-05-01' = {
  name: housekeepingLogicAppName
  location: location
  tags: tags
  identity: {
    type: 'UserAssigned'
    userAssignedIdentities: {
      '${managedIdentity.id}': {}
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
      }
      triggers: {
        Recurrence: {
          recurrence: {
            frequency: 'Day'
            interval: 1
            schedule: {
              hours: [
                1
              ]
            }
          }
          type: 'Recurrence'
        }
      }
      actions: {
        Expire_Old_Indicators: {
          runAfter: {}
          type: 'ApiConnection'
          inputs: {
            body: 'CTI_ThreatIntelIndicator_CL \n| where ValidUntil_t < now() and Active_b == true\n| project IndicatorId_g, Type_s, Value_s'
            host: {
              connection: {
                name: '@parameters(\'$connections\')[\'azuremonitorlogs\'][\'connectionId\']'
              }
            }
            method: 'post'
            path: '/queryData'
            queries: {
              resourcegroups: '@resourceGroup().name'
              resourcename: '@{parameters(\'workspaceName\')}'
              resourcetype: 'Log Analytics Workspace'
              subscriptions: '@{subscription().subscriptionId}'
              timerange: 'Last 90 days'
            }
          }
        }
        Process_Expired_Indicators: {
          foreach: '@body(\'Expire_Old_Indicators\').tables[0].rows'
          actions: {
            Set_Indicator_Inactive: {
              runAfter: {}
              type: 'ApiConnection'
              inputs: {
                body: 'let indicatorId = "@{item()[0]}";\nlet indicatorType = "@{item()[1]}";\nlet indicatorValue = "@{item()[2]}";\n\nCTI_ThreatIntelIndicator_CL\n| where IndicatorId_g == indicatorId\n| extend Active_b = false\n| project-away Active_b, TimeGenerated\n'
                host: {
                  connection: {
                    name: '@parameters(\'$connections\')[\'azureloganalyticsdatacollector\'][\'connectionId\']'
                  }
                }
                method: 'post'
                path: '/api/logs'
                queries: {
                  logType: 'CTI_ThreatIntelIndicator_CL'
                }
              }
            }
            Update_Specific_Indicator_Table: {
              runAfter: {
                Set_Indicator_Inactive: [
                  'Succeeded'
                ]
              }
              type: 'Switch'
              expression: '@item()[1]'
              cases: {
                IP_Address: {
                  case: 'ipv4-addr'
                  actions: {
                    Update_IP_Table: {
                      runAfter: {}
                      type: 'ApiConnection'
                      inputs: {
                        body: 'CTI_IPIndicators_CL\n| where IndicatorId_g == "@{item()[0]}"\n| extend Active_b = false\n| project-away Active_b, TimeGenerated\n'
                        host: {
                          connection: {
                            name: '@parameters(\'$connections\')[\'azureloganalyticsdatacollector\'][\'connectionId\']'
                          }
                        }
                        method: 'post'
                        path: '/api/logs'
                        queries: {
                          logType: 'CTI_IPIndicators_CL'
                        }
                      }
                    }
                  }
                }
                Domain_Name: {
                  case: 'domain-name'
                  actions: {
                    Update_Domain_Table: {
                      runAfter: {}
                      type: 'ApiConnection'
                      inputs: {
                        body: 'CTI_DomainIndicators_CL\n| where IndicatorId_g == "@{item()[0]}"\n| extend Active_b = false\n| project-away Active_b, TimeGenerated\n'
                        host: {
                          connection: {
                            name: '@parameters(\'$connections\')[\'azureloganalyticsdatacollector\'][\'connectionId\']'
                          }
                        }
                        method: 'post'
                        path: '/api/logs'
                        queries: {
                          logType: 'CTI_DomainIndicators_CL'
                        }
                      }
                    }
                  }
                }
                URL: {
                  case: 'url'
                  actions: {
                    Update_URL_Table: {
                      runAfter: {}
                      type: 'ApiConnection'
                      inputs: {
                        body: 'CTI_URLIndicators_CL\n| where IndicatorId_g == "@{item()[0]}"\n| extend Active_b = false\n| project-away Active_b, TimeGenerated\n'
                        host: {
                          connection: {
                            name: '@parameters(\'$connections\')[\'azureloganalyticsdatacollector\'][\'connectionId\']'
                          }
                        }
                        method: 'post'
                        path: '/api/logs'
                        queries: {
                          logType: 'CTI_URLIndicators_CL'
                        }
                      }
                    }
                  }
                }
                File_Hash: {
                  case: 'file-hash-sha256'
                  actions: {
                    Update_FileHash_Table: {
                      runAfter: {}
                      type: 'ApiConnection'
                      inputs: {
                        body: 'CTI_FileHashIndicators_CL\n| where IndicatorId_g == "@{item()[0]}"\n| extend Active_b = false\n| project-away Active_b, TimeGenerated\n'
                        host: {
                          connection: {
                            name: '@parameters(\'$connections\')[\'azureloganalyticsdatacollector\'][\'connectionId\']'
                          }
                        }
                        method: 'post'
                        path: '/api/logs'
                        queries: {
                          logType: 'CTI_FileHashIndicators_CL'
                        }
                      }
                    }
                  }
                }
                Email_Address: {
                  case: 'email-addr'
                  actions: {
                    Update_Email_Table: {
                      runAfter: {}
                      type: 'ApiConnection'
                      inputs: {
                        body: 'CTI_EmailIndicators_CL\n| where IndicatorId_g == "@{item()[0]}"\n| extend Active_b = false\n| project-away Active_b, TimeGenerated\n'
                        host: {
                          connection: {
                            name: '@parameters(\'$connections\')[\'azureloganalyticsdatacollector\'][\'connectionId\']'
                          }
                        }
                        method: 'post'
                        path: '/api/logs'
                        queries: {
                          logType: 'CTI_EmailIndicators_CL'
                        }
                      }
                    }
                  }
                }
              }
              default: {
                actions: {
                  Default_Action: {
                    runAfter: {}
                    type: 'ApiConnection'
                    inputs: {
                      body: {
                        IndicatorType_s: '@{item()[1]}'
                        IndicatorValue_s: '@{item()[2]}'
                        Action_s: 'Expire'
                        TargetSystem_s: 'CTI Platform'
                        Status_s: 'Success'
                        Timestamp_t: '@{utcNow()}'
                        ActionId_g: '@{guid()}'
                        CorrelationId_g: '@{workflow()[\'run\'][\'name\']}'
                        IndicatorId_g: '@{item()[0]}'
                        RunbookName_s: 'CTI-Housekeeping'
                        TriggerSource_s: 'Scheduled'
                      }
                      host: {
                        connection: {
                          name: '@parameters(\'$connections\')[\'azureloganalyticsdatacollector\'][\'connectionId\']'
                        }
                      }
                      method: 'post'
                      path: '/api/logs'
                      queries: {
                        logType: 'CTI_TransactionLog_CL'
                      }
                    }
                  }
                }
              }
            }
            Log_Transaction: {
              runAfter: {
                Update_Specific_Indicator_Table: [
                  'Succeeded'
                ]
              }
              type: 'ApiConnection'
              inputs: {
                body: {
                  IndicatorType_s: '@{item()[1]}'
                  IndicatorValue_s: '@{item()[2]}'
                  Action_s: 'Expire'
                  TargetSystem_s: 'CTI Platform'
                  Status_s: 'Success'
                  Timestamp_t: '@{utcNow()}'
                  ActionId_g: '@{guid()}'
                  CorrelationId_g: '@{workflow()[\'run\'][\'name\']}'
                  IndicatorId_g: '@{item()[0]}'
                  RunbookName_s: 'CTI-Housekeeping'
                  TriggerSource_s: 'Scheduled'
                }
                host: {
                  connection: {
                    name: '@parameters(\'$connections\')[\'azureloganalyticsdatacollector\'][\'connectionId\']'
                  }
                }
                method: 'post'
                path: '/api/logs'
                queries: {
                  logType: 'CTI_TransactionLog_CL'
                }
              }
            }
            Handle_Error: {
              actions: {
                Log_Error: {
                  runAfter: {}
                  type: 'ApiConnection'
                  inputs: {
                    body: {
                      IndicatorType_s: '@{item()[1]}'
                      IndicatorValue_s: '@{item()[2]}'
                      Action_s: 'Expire'
                      TargetSystem_s: 'CTI Platform'
                      Status_s: 'Failed'
                      ErrorMessage_s: 'Failed to expire indicator'
                      ErrorCode_s: '500'
                      ErrorDetails_s: '@{string(item())}'
                      Timestamp_t: '@{utcNow()}'
                      ActionId_g: '@{guid()}'
                      CorrelationId_g: '@{workflow()[\'run\'][\'name\']}'
                      IndicatorId_g: '@{item()[0]}'
                      RunbookName_s: 'CTI-Housekeeping'
                      TriggerSource_s: 'Scheduled'
                    }
                    host: {
                      connection: {
                        name: '@parameters(\'$connections\')[\'azureloganalyticsdatacollector\'][\'connectionId\']'
                      }
                    }
                    method: 'post'
                    path: '/api/logs'
                    queries: {
                      logType: 'CTI_TransactionLog_CL'
                    }
                  }
                }
              }
              runAfter: {
                Set_Indicator_Inactive: [
                  'Failed'
                ]
              }
              type: 'Scope'
            }
          }
          runAfter: {
            Expire_Old_Indicators: [
              'Succeeded'
            ]
          }
          type: 'Foreach'
          runtimeConfiguration: {
            concurrency: {
              repetitions: 20  // Increased for better performance
            }
            staticResult: {
              staticResultOptions: 'Disabled'  // Added for performance
            }
          }
        }
        Clean_Old_Logs: {
          runAfter: {
            Process_Expired_Indicators: [
              'Succeeded'
            ]
          }
          type: 'ApiConnection'
          inputs: {
            body: {
              LogCleaning_s: 'Cleaned logs older than 90 days'
              TargetSystem_s: 'CTI Platform'
              Status_s: 'Success'
              Timestamp_t: '@{utcNow()}'
              ActionId_g: '@{guid()}'
              CorrelationId_g: '@{workflow()[\'run\'][\'name\']}'
              RunbookName_s: 'CTI-Housekeeping'
              TriggerSource_s: 'Scheduled'
            }
            host: {
              connection: {
                name: '@parameters(\'$connections\')[\'azureloganalyticsdatacollector\'][\'connectionId\']'
              }
            }
            method: 'post'
            path: '/api/logs'
            queries: {
              logType: 'CTI_TransactionLog_CL'
            }
          }
        }
        Handle_Main_Error: {
          actions: {
            Log_Main_Error: {
              runAfter: {}
              type: 'ApiConnection'
              inputs: {
                body: {
                  ErrorSource_s: 'Housekeeping'
                  ErrorMessage_s: 'Failed to expire old indicators'
                  ErrorCode_s: '@{outputs(\'Expire_Old_Indicators\')?[\'statusCode\']}'
                  ErrorDetails_s: '@{outputs(\'Expire_Old_Indicators\')?[\'body\']}'
                  Timestamp_t: '@{utcNow()}'
                  ActionId_g: '@{guid()}'
                  CorrelationId_g: '@{workflow()[\'run\'][\'name\']}'
                  RunbookName_s: 'CTI-Housekeeping'
                  TriggerSource_s: 'Scheduled'
                }
                host: {
                  connection: {
                    name: '@parameters(\'$connections\')[\'azureloganalyticsdatacollector\'][\'connectionId\']'
                  }
                }
                method: 'post'
                path: '/api/logs'
                queries: {
                  logType: 'CTI_TransactionLog_CL'
                }
              }
            }
          }
          runAfter: {
            Expire_Old_Indicators: [
              'Failed'
            ]
          }
          type: 'Scope'
        }
      }
    }
    parameters: {
      '$connections': {
        value: {
          azureloganalyticsdatacollector: {
            connectionId: logAnalyticsConnection.id
            connectionName: logAnalyticsConnection.name
            id: subscriptionResourceId('Microsoft.Web/locations/managedApis', location, 'azureloganalyticsdatacollector')
          }
          azuremonitorlogs: {
            connectionId: logAnalyticsQueryConnection.id
            connectionName: logAnalyticsQueryConnection.name
            id: subscriptionResourceId('Microsoft.Web/locations/managedApis', location, 'azuremonitorlogs')
          }
        }
      }
    }
  }
  dependsOn: [
    securityCopilotConnector
  ]
}

// Add diagnostic settings for Housekeeping Logic App
resource housekeepingLogicAppDiagnostics 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = {
  scope: housekeepingLogicApp
  name: 'diagnostics'
  properties: {
    workspaceId: ctiWorkspace.id
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

// Threat Feed Sync Logic App
resource threatFeedSyncLogicApp 'Microsoft.Logic/workflows@2019-05-01' = {
  name: threatFeedSyncLogicAppName
  location: location
  tags: tags
  identity: {
    type: 'UserAssigned'
    userAssignedIdentities: {
      '${managedIdentity.id}': {}
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
      }
      triggers: {
        Recurrence: {
          recurrence: {
            frequency: 'Day'
            interval: 1
          }
          type: 'Recurrence'
        }
      }
      actions: {
        Get_Feed_List: {
          runAfter: {}
          type: 'ApiConnection'
          inputs: {
            body: 'CTI_IntelligenceFeeds_CL\n| where FeedType_s == "CSV" and Active_b == true\n| project FeedId_g, FeedName_s, FeedURL_s, ConfigData_s, FeedType_s, ContentMapping_s'
            host: {
              connection: {
                name: '@parameters(\'$connections\')[\'azuremonitorlogs\'][\'connectionId\']'
              }
            }
            method: 'post'
            path: '/queryData'
            queries: {
              resourcegroups: '@resourceGroup().name'
              resourcename: '@{parameters(\'workspaceName\')}'
              resourcetype: 'Log Analytics Workspace'
              subscriptions: '@{subscription().subscriptionId}'
              timerange: 'Last 7 days'
            }
          }
        }
        Process_Feeds: {
          foreach: '@body(\'Get_Feed_List\').tables[0].rows'
          actions: {
            Get_Feed_Content: {
              runAfter: {}
              type: 'Http'
              inputs: {
                method: 'GET'
                uri: '@{item()[2]}' // FeedURL_s
                retryPolicy: {
                  type: 'fixed'
                  count: 3
                  interval: 'PT30S'
                }
              }
            }
            Parse_Feed_Content: {
              runAfter: {
                Get_Feed_Content: [
                  'Succeeded'
                ]
              }
              type: 'ParseJson'
              inputs: {
                content: '@if(startsWith(body(\'Get_Feed_Content\'), \'[\'), body(\'Get_Feed_Content\'), concat(\'[\', body(\'Get_Feed_Content\'), \']\'))'
                schema: {
                  type: 'array'
                  items: {
                    type: 'object'
                  }
                }
              }
            }
            Parse_Column_Mapping: {
              runAfter: {
                Parse_Feed_Content: [
                  'Succeeded'
                ]
              }
              type: 'ParseJson'
              inputs: {
                content: '@{if(empty(item()[5]), \'{}\', item()[5])}'
                schema: {
                  type: 'object'
                  properties: {
                    valueField: { type: 'string' }
                    typeField: { type: 'string' }
                    confidenceField: { type: 'string' }
                    descriptionField: { type: 'string' }
                    dateField: { type: 'string' }
                    threatTypeField: { type: 'string' }
                  }
                }
              }
            }
            Process_Feed_Items: {
              foreach: '@body(\'Parse_Feed_Content\')'
              actions: {
                Process_IP_Indicator: {
                  actions: {
                    Get_Indicator_Value: {
                      runAfter: {}
                      type: 'Compose'
                      inputs: '@{if(equals(body(\'Parse_Column_Mapping\')?[\'valueField\'], null), items(\'Process_Feed_Items\')?[\'indicator\'], items(\'Process_Feed_Items\')?[body(\'Parse_Column_Mapping\').valueField])}'
                    }
                    Send_IP_to_Log_Analytics: {
                      runAfter: {
                        Get_Indicator_Value: [
                          'Succeeded'
                        ]
                      }
                      type: 'ApiConnection'
                      inputs: {
                        body: {
                          IPAddress_s: '@{outputs(\'Get_Indicator_Value\')}'
                          ObjectId_g: '@{guid()}'
                          IndicatorId_g: '@{guid()}'
                          ConfidenceScore_d: '@{if(equals(body(\'Parse_Column_Mapping\')?[\'confidenceField\'], null), 70, int(items(\'Process_Feed_Items\')?[body(\'Parse_Column_Mapping\').confidenceField]))}'
                          SourceFeed_s: '@{item()[1]}'
                          FirstSeen_t: '@{if(equals(body(\'Parse_Column_Mapping\')?[\'dateField\'], null), utcNow(), items(\'Process_Feed_Items\')?[body(\'Parse_Column_Mapping\').dateField])}'
                          LastSeen_t: '@{utcNow()}'
                          ExpirationDateTime_t: '@{addDays(utcNow(), 30)}'
                          ThreatType_s: '@{if(equals(body(\'Parse_Column_Mapping\')?[\'threatTypeField\'], null), \'Unknown\', items(\'Process_Feed_Items\')?[body(\'Parse_Column_Mapping\').threatTypeField])}'
                          Description_s: '@{if(equals(body(\'Parse_Column_Mapping\')?[\'descriptionField\'], null), concat(\'IP from threat feed: \', item()[1]), items(\'Process_Feed_Items\')?[body(\'Parse_Column_Mapping\').descriptionField])}'
                          TLP_s: 'TLP:AMBER'
                          Action_s: 'Alert'
                          DistributionTargets_s: 'Microsoft Sentinel'
                          Active_b: true
                        }
                        host: {
                          connection: {
                            name: '@parameters(\'$connections\')[\'azureloganalyticsdatacollector\'][\'connectionId\']'
                          }
                        }
                        method: 'post'
                        path: '/api/logs'
                        queries: {
                          logType: 'CTI_IPIndicators_CL'
                        }
                      }
                    }
                    Send_to_ThreatIntelIndicator: {
                      runAfter: {
                        Send_IP_to_Log_Analytics: [
                          'Succeeded'
                        ]
                      }
                      type: 'ApiConnection'
                      inputs: {
                        body: {
                          Type_s: 'ipv4-addr'
                          Value_s: '@{outputs(\'Get_Indicator_Value\')}'
                          Name_s: '@{concat(\'Malicious IP - \', outputs(\'Get_Indicator_Value\'))}'
                          Description_s: '@{if(equals(body(\'Parse_Column_Mapping\')?[\'descriptionField\'], null), concat(\'IP from threat feed: \', item()[1]), items(\'Process_Feed_Items\')?[body(\'Parse_Column_Mapping\').descriptionField])}'
                          Action_s: 'alert'
                          Confidence_d: '@{if(equals(body(\'Parse_Column_Mapping\')?[\'confidenceField\'], null), 70, int(items(\'Process_Feed_Items\')?[body(\'Parse_Column_Mapping\').confidenceField]))}'
                          ValidFrom_t: '@{if(equals(body(\'Parse_Column_Mapping\')?[\'dateField\'], null), utcNow(), items(\'Process_Feed_Items\')?[body(\'Parse_Column_Mapping\').dateField])}'
                          ValidUntil_t: '@{addDays(utcNow(), 30)}'
                          CreatedTimeUtc_t: '@{utcNow()}'
                          UpdatedTimeUtc_t: '@{utcNow()}'
                          Source_s: '@{item()[1]}'
                          SourceRef_s: '@{item()[2]}'
                          ThreatType_s: '@{if(equals(body(\'Parse_Column_Mapping\')?[\'threatTypeField\'], null), \'Unknown\', items(\'Process_Feed_Items\')?[body(\'Parse_Column_Mapping\').threatTypeField])}'
                          TLP_s: 'TLP:AMBER'
                          DistributionTargets_s: 'Microsoft Sentinel'
                          Active_b: true
                          ObjectId_g: '@{guid()}'
                          IndicatorId_g: '@{guid()}'
                        }
                        host: {
                          connection: {
                            name: '@parameters(\'$connections\')[\'azureloganalyticsdatacollector\'][\'connectionId\']'
                          }
                        }
                        method: 'post'
                        path: '/api/logs'
                        queries: {
                          logType: 'CTI_ThreatIntelIndicator_CL'
                        }
                      }
                    }
                  }
                  runAfter: {
                    Parse_Column_Mapping: [
                      'Succeeded'
                    ]
                  }
                  expression: {
                    and: [
                      {
                        or: [
                          {
                            equals: [
                              '@if(equals(body(\'Parse_Column_Mapping\')?[\'typeField\'], null), items(\'Process_Feed_Items\')?[\'type\'], items(\'Process_Feed_Items\')?[body(\'Parse_Column_Mapping\').typeField])'
                              'ip'
                            ]
                          }
                          {
                            equals: [
                              '@if(equals(body(\'Parse_Column_Mapping\')?[\'typeField\'], null), items(\'Process_Feed_Items\')?[\'type\'], items(\'Process_Feed_Items\')?[body(\'Parse_Column_Mapping\').typeField])'
                              'ipv4'
                            ]
                          }
                          {
                            equals: [
                              '@if(equals(body(\'Parse_Column_Mapping\')?[\'typeField\'], null), items(\'Process_Feed_Items\')?[\'type\'], items(\'Process_Feed_Items\')?[body(\'Parse_Column_Mapping\').typeField])'
                              'ipv4-addr'
                            ]
                          }
                        ]
                      }
                    ]
                  }
                  type: 'If'
                }
                // Additional indicator type processing would go here (domains, file hashes, etc.)
                Log_Transaction: {
                  runAfter: {
                    Process_IP_Indicator: [
                      'Succeeded'
                    ]
                  }
                  type: 'ApiConnection'
                  inputs: {
                    body: {
                      IndicatorType_s: '@{if(equals(body(\'Parse_Column_Mapping\')?[\'typeField\'], null), items(\'Process_Feed_Items\')?[\'type\'], items(\'Process_Feed_Items\')?[body(\'Parse_Column_Mapping\').typeField])}'
                      IndicatorValue_s: '@{if(equals(body(\'Parse_Column_Mapping\')?[\'valueField\'], null), items(\'Process_Feed_Items\')?[\'indicator\'], items(\'Process_Feed_Items\')?[body(\'Parse_Column_Mapping\').valueField])}'
                      Action_s: 'Import'
                      TargetSystem_s: 'CTI Platform'
                      Status_s: 'Success'
                      Timestamp_t: '@{utcNow()}'
                      ActionId_g: '@{guid()}'
                      CorrelationId_g: '@{workflow()[\'run\'][\'name\']}'
                      RunbookName_s: 'CTI-ThreatFeedSync'
                      TriggerSource_s: 'Scheduled'
                    }
                    host: {
                      connection: {
                        name: '@parameters(\'$connections\')[\'azureloganalyticsdatacollector\'][\'connectionId\']'
                      }
                    }
                    method: 'post'
                    path: '/api/logs'
                    queries: {
                      logType: 'CTI_TransactionLog_CL'
                    }
                  }
                }
                Handle_Error: {
                  actions: {
                    Log_Error: {
                      runAfter: {}
                      type: 'ApiConnection'
                      inputs: {
                        body: {
                          IndicatorType_s: '@{if(equals(body(\'Parse_Column_Mapping\')?[\'typeField\'], null), items(\'Process_Feed_Items\')?[\'type\'], items(\'Process_Feed_Items\')?[body(\'Parse_Column_Mapping\').typeField])}'
                          IndicatorValue_s: '@{if(equals(body(\'Parse_Column_Mapping\')?[\'valueField\'], null), items(\'Process_Feed_Items\')?[\'indicator\'], items(\'Process_Feed_Items\')?[body(\'Parse_Column_Mapping\').valueField])}'
                          Action_s: 'Import'
                          TargetSystem_s: 'CTI Platform'
                          Status_s: 'Failed'
                          ErrorMessage_s: 'Failed to process feed item'
                          ErrorCode_s: '500'
                          ErrorDetails_s: '@{string(items(\'Process_Feed_Items\'))}'
                          Timestamp_t: '@{utcNow()}'
                          ActionId_g: '@{guid()}'
                          CorrelationId_g: '@{workflow()[\'run\'][\'name\']}'
                          RunbookName_s: 'CTI-ThreatFeedSync'
                          TriggerSource_s: 'Scheduled'
                        }
                        host: {
                          connection: {
                            name: '@parameters(\'$connections\')[\'azureloganalyticsdatacollector\'][\'connectionId\']'
                          }
                        }
                        method: 'post'
                        path: '/api/logs'
                        queries: {
                          logType: 'CTI_TransactionLog_CL'
                        }
                      }
                    }
                  }
                  runAfter: {
                    Process_IP_Indicator: [
                      'Failed'
                    ]
                  }
                  type: 'Scope'
                }
              }
              runAfter: {
                Parse_Column_Mapping: [
                  'Succeeded'
                ]
              }
              type: 'Foreach'
              runtimeConfiguration: {
                concurrency: {
                  repetitions: 20  // Increased for better performance
                }
                staticResult: {
                  staticResultOptions: 'Disabled'  // Added for performance
                }
              }
            }
            Update_Feed_Status: {
              runAfter: {
                Process_Feed_Items: [
                  'Succeeded'
                ]
              }
              type: 'ApiConnection'
              inputs: {
                body: {
                  FeedId_g: '@{item()[0]}'
                  FeedName_s: '@{item()[1]}'
                  FeedType_s: '@{item()[4]}'
                  FeedURL_s: '@{item()[2]}'
                  Status_s: 'Active'
                  LastUpdated_t: '@{utcNow()}'
                  UpdateFrequency_s: '24 hours'
                  IndicatorCount_d: '@{length(body(\'Parse_Feed_Content\'))}'
                  ConfigData_s: '@{item()[3]}'
                  ContentMapping_s: '@{item()[5]}'
                  Active_b: true
                }
                host: {
                  connection: {
                    name: '@parameters(\'$connections\')[\'azureloganalyticsdatacollector\'][\'connectionId\']'
                  }
                }
                method: 'post'
                path: '/api/logs'
                queries: {
                  logType: 'CTI_IntelligenceFeeds_CL'
                }
              }
            }
            Handle_Feed_Error: {
              actions: {
                Log_Feed_Error: {
                  runAfter: {}
                  type: 'ApiConnection'
                  inputs: {
                    body: {
                      ErrorSource_s: 'ThreatFeedSync'
                      ErrorMessage_s: 'Failed to process feed'
                      ErrorCode_s: '@{outputs(\'Get_Feed_Content\')?[\'statusCode\']}'
                      ErrorDetails_s: '@{outputs(\'Get_Feed_Content\')?[\'body\']}'
                      Timestamp_t: '@{utcNow()}'
                      ActionId_g: '@{guid()}'
                      CorrelationId_g: '@{workflow()[\'run\'][\'name\']}'
                      RunbookName_s: 'CTI-ThreatFeedSync'
                      TriggerSource_s: 'Scheduled'
                    }
                    host: {
                      connection: {
                        name: '@parameters(\'$connections\')[\'azureloganalyticsdatacollector\'][\'connectionId\']'
                      }
                    }
                    method: 'post'
                    path: '/api/logs'
                    queries: {
                      logType: 'CTI_TransactionLog_CL'
                    }
                  }
                }
              }
              runAfter: {
                Get_Feed_Content: [
                  'Failed'
                ]
              }
              type: 'Scope'
            }
          }
          runAfter: {
            Get_Feed_List: [
              'Succeeded'
            ]
          }
          type: 'Foreach'
          runtimeConfiguration: {
            concurrency: {
              repetitions: 5  // Lower concurrency for feed processing
            }
          }
        }
        Handle_Main_Error: {
          actions: {
            Log_Main_Error: {
              runAfter: {}
              type: 'ApiConnection'
              inputs: {
                body: {
                  ErrorSource_s: 'ThreatFeedSync'
                  ErrorMessage_s: 'Failed to retrieve feeds'
                  ErrorCode_s: '@{outputs(\'Get_Feed_List\')?[\'statusCode\']}'
                  ErrorDetails_s: '@{outputs(\'Get_Feed_List\')?[\'body\']}'
                  Timestamp_t: '@{utcNow()}'
                  ActionId_g: '@{guid()}'
                  CorrelationId_g: '@{workflow()[\'run\'][\'name\']}'
                  RunbookName_s: 'CTI-ThreatFeedSync'
                  TriggerSource_s: 'Scheduled'
                }
                host: {
                  connection: {
                    name: '@parameters(\'$connections\')[\'azureloganalyticsdatacollector\'][\'connectionId\']'
                  }
                }
                method: 'post'
                path: '/api/logs'
                queries: {
                  logType: 'CTI_TransactionLog_CL'
                }
              }
            }
          }
          runAfter: {
            Get_Feed_List: [
              'Failed'
            ]
          }
          type: 'Scope'
        }
      }
    }
    parameters: {
      '$connections': {
        value: {
          azureloganalyticsdatacollector: {
            connectionId: logAnalyticsConnection.id
            connectionName: logAnalyticsConnection.name
            id: subscriptionResourceId('Microsoft.Web/locations/managedApis', location, 'azureloganalyticsdatacollector')
          }
          azuremonitorlogs: {
            connectionId: logAnalyticsQueryConnection.id
            connectionName: logAnalyticsQueryConnection.name
            id: subscriptionResourceId('Microsoft.Web/locations/managedApis', location, 'azuremonitorlogs')
          }
        }
      }
    }
  }
  dependsOn: [
    housekeepingLogicApp
  ]
}

// Add diagnostic settings for Threat Feed Sync Logic App
resource threatFeedSyncLogicAppDiagnostics 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = {
  scope: threatFeedSyncLogicApp
  name: 'diagnostics'
  properties: {
    workspaceId: ctiWorkspace.id
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

// Microsoft Sentinel integration (conditional)
resource sentinelSolution 'Microsoft.OperationsManagement/solutions@2015-11-01-preview' = if (enableSentinelIntegration && empty(existingSentinelWorkspaceId)) {
  name: 'SecurityInsights(${ctiWorkspaceName})'
  location: location
  tags: tags
  plan: {
    name: 'SecurityInsights(${ctiWorkspaceName})'
    publisher: 'Microsoft'
    product: 'OMSGallery/SecurityInsights'
    promotionCode: ''
  }
  properties: {
    workspaceResourceId: ctiWorkspace.id
  }
}

// Implement Analytics Rules if enabled
resource analyticRules 'Microsoft.SecurityInsights/alertRules@2022-11-01' = if (enableAnalyticsRules && enableSentinelIntegration) {
  name: 'CTI-ThreatIntelMatch'
  scope: resourceId('Microsoft.OperationalInsights/workspaces', ctiWorkspaceName)
  kind: 'ThreatIntelligence'
  properties: {
    displayName: 'Threat Intelligence Indicator Match'
    enabled: true
    productFilter: 'Microsoft Sentinel'
    severitiesFilter: ['High']
    sourceSettings: [
      {
        sourceId: 'Azure Sentinel'
        sourceType: 'SentinelAlerting'
        status: 'Enabled'
      }
    ]
  }
  dependsOn: [
    enableSentinelIntegration && empty(existingSentinelWorkspaceId) ? sentinelSolution : ctiWorkspace
  ]
}

// Implement Hunting Queries if enabled
resource huntingQuery 'Microsoft.OperationalInsights/workspaces/savedSearches@2020-08-01' = if (enableHuntingQueries && enableSentinelIntegration) {
  parent: ctiWorkspace
  name: 'CTI-DomainIOCMatch'
  properties: {
    category: 'Hunting Queries'
    displayName: 'Domain IOC matches in DNS queries'
    query: 'let iocs = CTI_DomainIndicators_CL | where Active_b == true;\nDnsEvents | where Name has_any (iocs)'
    version: 2
    tags: [
      {
        name: 'description'
        value: 'Finds matches of domain indicators in DNS query logs'
      }
      {
        name: 'tactics'
        value: 'CommandAndControl,Exfiltration'
      }
      {
        name: 'techniques'
        value: 'T1071,T1567'
      }
    ]
  }
}

// Outputs for the template
output ctiWorkspaceId string = ctiWorkspace.id
output ctiWorkspaceName string = ctiWorkspace.name
output keyVaultName string = keyVault.name
output managedIdentityId string = managedIdentity.id
output managedIdentityPrincipalId string = managedIdentity.properties.principalId
output taxiiConnectorName string = taxiiConnectorLogicAppName
output defenderConnectorName string = defenderEndpointConnectorName
output mdtiConnectorName string = enableMDTI ? mdtiConnectorLogicAppName : ''
output entraIdConnectorName string = entraIDConnectorLogicAppName
output exoConnectorName string = exoConnectorLogicAppName
output securityCopilotConnectorName string = enableSecurityCopilot ? securityCopilotConnectorName : ''
output housekeepingName string = housekeepingLogicAppName

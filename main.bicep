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
var dceCopilotIntegrationName = 'DCE-CTI-SecurityCopilot'

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

// Key Vault for storing secrets
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
      defaultAction: 'Allow'
      bypass: 'AzureServices'
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

// Logic App Service Plan (Premium for reliable execution)
resource logicAppServicePlan 'Microsoft.Web/serverfarms@2022-09-01' = {
  name: logicAppServicePlanName
  location: location
  tags: tags
  sku: {
    name: 'WS1'
    tier: 'WorkflowStandard'
  }
  properties: {}
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
      'workspace': ctiWorkspace.properties.customerId
      'workspaceKey': listKeys(ctiWorkspace.id, '2022-10-01').primarySharedKey
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
      'token:TenantId': tenantId
      'token:clientId': appClientId
      'token:clientSecret': listSecrets(clientSecretValue.id, '2023-02-01').value
      'token:grantType': 'client_credentials'
    }
  }
  dependsOn: [
    clientSecretValue
    keyVaultRoleAssignment
  ]
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
      'token:clientSecret': listSecrets(clientSecretValue.id, '2023-02-01').value
      'token:grantType': 'client_credentials'
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
                      repetitions: 10
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
                      Timestamp_t: '@{utcNow()}'
                      ActionId_g: '@{guid()}'
                      CorrelationId_g: '@{guid()}'
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
            uri: 'https://login.microsoftonline.com/@{parameters(\'tenantId\')}/oauth2/token'
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
                  CorrelationId_g: '@{guid()}'
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
                      Timestamp_t: '@{utcNow()}'
                      ActionId_g: '@{guid()}'
                      CorrelationId_g: '@{guid()}'
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
              repetitions: 10
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
                  CorrelationId_g: '@{guid()}'
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
                      Timestamp_t: '@{utcNow()}'
                      ActionId_g: '@{guid()}'
                      CorrelationId_g: '@{guid()}'
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
              repetitions: 10
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
                  CorrelationId_g: '@{guid()}'
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
                      Timestamp_t: '@{utcNow()}'
                      ActionId_g: '@{guid()}'
                      CorrelationId_g: '@{guid()}'
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
              repetitions: 10
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

// Microsoft Defender Threat Intelligence connector
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
            frequency: 'Day'
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
            uri: 'https://login.microsoftonline.com/@{parameters(\'tenantId\')}/oauth2/token'
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
        Get_MDTI_Indicators: {
          runAfter: {
            Get_Authentication_Token: [
              'Succeeded'
            ]
          }
          type: 'Http'
          inputs: {
            method: 'GET'
            uri: 'https://api.securitycenter.windows.com/api/indicators?$filter=confidenceLevel ge 50&$top=100'
            headers: {
              Accept: 'application/json'
              Authorization: 'Bearer @{body(\'Get_Authentication_Token\').access_token}'
            }
            retryPolicy: {
              type: 'fixed'
              count: 3
              interval: 'PT30S'
            }
          }
        }
        Parse_MDTI_Indicators: {
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
                      indicatorValue: {
                        type: 'string'
                      }
                      indicatorType: {
                        type: 'string'
                      }
                      title: {
                        type: 'string'
                      }
                      description: {
                        type: 'string'
                      }
                      expirationTime: {
                        type: 'string'
                      }
                      severity: {
                        type: 'string'
                      }
                      confidence: {
                        type: 'integer'
                      }
                    }
                  }
                }
              }
            }
          }
        }
        Process_MDTI_Indicators: {
          foreach: '@body(\'Parse_MDTI_Indicators\').value'
          actions: {
            Determine_Indicator_Type: {
              actions: {
                Process_IP_Indicator: {
                  actions: {
                    Send_IP_to_Log_Analytics: {
                      runAfter: {}
                      type: 'ApiConnection'
                      inputs: {
                        body: {
                          IPAddress_s: '@{items(\'Process_MDTI_Indicators\').indicatorValue}'
                          ObjectId_g: '@{guid()}'
                          IndicatorId_g: '@{guid()}'
                          ConfidenceScore_d: '@{items(\'Process_MDTI_Indicators\').confidence}'
                          SourceFeed_s: 'Microsoft Defender Threat Intelligence'
                          FirstSeen_t: '@{utcNow()}'
                          LastSeen_t: '@{utcNow()}'
                          ExpirationDateTime_t: '@{items(\'Process_MDTI_Indicators\').expirationTime}'
                          ThreatType_s: '@{if(contains(items(\'Process_MDTI_Indicators\'), \'title\'), items(\'Process_MDTI_Indicators\').title, \'Unknown\')}'
                          Description_s: '@{items(\'Process_MDTI_Indicators\').description}'
                          TLP_s: 'TLP:AMBER'
                          Action_s: '@{if(equals(items(\'Process_MDTI_Indicators\').severity, \'High\'), \'AlertAndBlock\', \'Alert\')}'
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
                    Send_to_ThreatIntelIndicator_IP: {
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
                          Pattern_s: ''
                          PatternType_s: 'stix'
                          Name_s: '@{if(contains(items(\'Process_MDTI_Indicators\'), \'title\'), items(\'Process_MDTI_Indicators\').title, \'IP Indicator\')}'
                          Description_s: '@{items(\'Process_MDTI_Indicators\').description}'
                          Action_s: '@{if(equals(items(\'Process_MDTI_Indicators\').severity, \'High\'), \'AlertAndBlock\', \'Alert\')}'
                          Confidence_d: '@{items(\'Process_MDTI_Indicators\').confidence}'
                          ValidFrom_t: '@{utcNow()}'
                          ValidUntil_t: '@{items(\'Process_MDTI_Indicators\').expirationTime}'
                          CreatedTimeUtc_t: '@{utcNow()}'
                          UpdatedTimeUtc_t: '@{utcNow()}'
                          Source_s: 'Microsoft Defender Threat Intelligence'
                          SourceRef_s: 'https://ti.defender.microsoft.com/'
                          KillChainPhases_s: ''
                          Labels_s: '@{if(contains(items(\'Process_MDTI_Indicators\'), \'title\'), items(\'Process_MDTI_Indicators\').title, \'\')}'
                          ThreatType_s: '@{if(contains(items(\'Process_MDTI_Indicators\'), \'title\'), items(\'Process_MDTI_Indicators\').title, \'Unknown\')}'
                          TLP_s: 'TLP:AMBER'
                          DistributionTargets_s: 'Microsoft Sentinel, Microsoft Defender XDR'
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
                          ObjectId_g: '@{guid()}'
                          IndicatorId_g: '@{guid()}'
                          ConfidenceScore_d: '@{items(\'Process_MDTI_Indicators\').confidence}'
                          SourceFeed_s: 'Microsoft Defender Threat Intelligence'
                          FirstSeen_t: '@{utcNow()}'
                          LastSeen_t: '@{utcNow()}'
                          ExpirationDateTime_t: '@{items(\'Process_MDTI_Indicators\').expirationTime}'
                          ThreatType_s: '@{if(contains(items(\'Process_MDTI_Indicators\'), \'title\'), items(\'Process_MDTI_Indicators\').title, \'Unknown\')}'
                          Description_s: '@{items(\'Process_MDTI_Indicators\').description}'
                          TLP_s: 'TLP:AMBER'
                          Action_s: '@{if(equals(items(\'Process_MDTI_Indicators\').severity, \'High\'), \'AlertAndBlock\', \'Alert\')}'
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
                          Pattern_s: ''
                          PatternType_s: 'stix'
                          Name_s: '@{if(contains(items(\'Process_MDTI_Indicators\'), \'title\'), items(\'Process_MDTI_Indicators\').title, \'Domain Indicator\')}'
                          Description_s: '@{items(\'Process_MDTI_Indicators\').description}'
                          Action_s: '@{if(equals(items(\'Process_MDTI_Indicators\').severity, \'High\'), \'AlertAndBlock\', \'Alert\')}'
                          Confidence_d: '@{items(\'Process_MDTI_Indicators\').confidence}'
                          ValidFrom_t: '@{utcNow()}'
                          ValidUntil_t: '@{items(\'Process_MDTI_Indicators\').expirationTime}'
                          CreatedTimeUtc_t: '@{utcNow()}'
                          UpdatedTimeUtc_t: '@{utcNow()}'
                          Source_s: 'Microsoft Defender Threat Intelligence'
                          SourceRef_s: 'https://ti.defender.microsoft.com/'
                          KillChainPhases_s: ''
                          Labels_s: '@{if(contains(items(\'Process_MDTI_Indicators\'), \'title\'), items(\'Process_MDTI_Indicators\').title, \'\')}'
                          ThreatType_s: '@{if(contains(items(\'Process_MDTI_Indicators\'), \'title\'), items(\'Process_MDTI_Indicators\').title, \'Unknown\')}'
                          TLP_s: 'TLP:AMBER'
                          DistributionTargets_s: 'Microsoft Sentinel, Microsoft Defender XDR'
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
                          ObjectId_g: '@{guid()}'
                          IndicatorId_g: '@{guid()}'
                          ConfidenceScore_d: '@{items(\'Process_MDTI_Indicators\').confidence}'
                          SourceFeed_s: 'Microsoft Defender Threat Intelligence'
                          FirstSeen_t: '@{utcNow()}'
                          LastSeen_t: '@{utcNow()}'
                          ExpirationDateTime_t: '@{items(\'Process_MDTI_Indicators\').expirationTime}'
                          ThreatType_s: '@{if(contains(items(\'Process_MDTI_Indicators\'), \'title\'), items(\'Process_MDTI_Indicators\').title, \'Unknown\')}'
                          MalwareFamily_s: '@{if(contains(items(\'Process_MDTI_Indicators\'), \'title\'), items(\'Process_MDTI_Indicators\').title, \'Unknown\')}'
                          Description_s: '@{items(\'Process_MDTI_Indicators\').description}'
                          TLP_s: 'TLP:AMBER'
                          Action_s: '@{if(equals(items(\'Process_MDTI_Indicators\').severity, \'High\'), \'AlertAndBlock\', \'Alert\')}'
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
                          Pattern_s: ''
                          PatternType_s: 'stix'
                          Name_s: '@{if(contains(items(\'Process_MDTI_Indicators\'), \'title\'), items(\'Process_MDTI_Indicators\').title, \'File Hash Indicator\')}'
                          Description_s: '@{items(\'Process_MDTI_Indicators\').description}'
                          Action_s: '@{if(equals(items(\'Process_MDTI_Indicators\').severity, \'High\'), \'AlertAndBlock\', \'Alert\')}'
                          Confidence_d: '@{items(\'Process_MDTI_Indicators\').confidence}'
                          ValidFrom_t: '@{utcNow()}'
                          ValidUntil_t: '@{items(\'Process_MDTI_Indicators\').expirationTime}'
                          CreatedTimeUtc_t: '@{utcNow()}'
                          UpdatedTimeUtc_t: '@{utcNow()}'
                          Source_s: 'Microsoft Defender Threat Intelligence'
                          SourceRef_s: 'https://ti.defender.microsoft.com/'
                          KillChainPhases_s: ''
                          Labels_s: '@{if(contains(items(\'Process_MDTI_Indicators\'), \'title\'), items(\'Process_MDTI_Indicators\').title, \'\')}'
                          ThreatType_s: '@{if(contains(items(\'Process_MDTI_Indicators\'), \'title\'), items(\'Process_MDTI_Indicators\').title, \'Unknown\')}'
                          TLP_s: 'TLP:AMBER'
                          DistributionTargets_s: 'Microsoft Sentinel, Microsoft Defender XDR'
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
                Process_URL_Indicator: {
                  actions: {
                    Send_URL_to_Log_Analytics: {
                      runAfter: {}
                      type: 'ApiConnection'
                      inputs: {
                        body: {
                          URL_s: '@{items(\'Process_MDTI_Indicators\').indicatorValue}'
                          ObjectId_g: '@{guid()}'
                          IndicatorId_g: '@{guid()}'
                          ConfidenceScore_d: '@{items(\'Process_MDTI_Indicators\').confidence}'
                          SourceFeed_s: 'Microsoft Defender Threat Intelligence'
                          FirstSeen_t: '@{utcNow()}'
                          LastSeen_t: '@{utcNow()}'
                          ExpirationDateTime_t: '@{items(\'Process_MDTI_Indicators\').expirationTime}'
                          ThreatType_s: '@{if(contains(items(\'Process_MDTI_Indicators\'), \'title\'), items(\'Process_MDTI_Indicators\').title, \'Unknown\')}'
                          Description_s: '@{items(\'Process_MDTI_Indicators\').description}'
                          TLP_s: 'TLP:AMBER'
                          Action_s: '@{if(equals(items(\'Process_MDTI_Indicators\').severity, \'High\'), \'AlertAndBlock\', \'Alert\')}'
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
                          logType: 'CTI_URLIndicators_CL'
                        }
                      }
                    }
                    Send_to_ThreatIntelIndicator_URL: {
                      runAfter: {
                        Send_URL_to_Log_Analytics: [
                          'Succeeded'
                        ]
                      }
                      type: 'ApiConnection'
                      inputs: {
                        body: {
                          Type_s: 'url'
                          Value_s: '@{items(\'Process_MDTI_Indicators\').indicatorValue}'
                          Pattern_s: ''
                          PatternType_s: 'stix'
                          Name_s: '@{if(contains(items(\'Process_MDTI_Indicators\'), \'title\'), items(\'Process_MDTI_Indicators\').title, \'URL Indicator\')}'
                          Description_s: '@{items(\'Process_MDTI_Indicators\').description}'
                          Action_s: '@{if(equals(items(\'Process_MDTI_Indicators\').severity, \'High\'), \'AlertAndBlock\', \'Alert\')}'
                          Confidence_d: '@{items(\'Process_MDTI_Indicators\').confidence}'
                          ValidFrom_t: '@{utcNow()}'
                          ValidUntil_t: '@{items(\'Process_MDTI_Indicators\').expirationTime}'
                          CreatedTimeUtc_t: '@{utcNow()}'
                          UpdatedTimeUtc_t: '@{utcNow()}'
                          Source_s: 'Microsoft Defender Threat Intelligence'
                          SourceRef_s: 'https://ti.defender.microsoft.com/'
                          KillChainPhases_s: ''
                          Labels_s: '@{if(contains(items(\'Process_MDTI_Indicators\'), \'title\'), items(\'Process_MDTI_Indicators\').title, \'\')}'
                          ThreatType_s: '@{if(contains(items(\'Process_MDTI_Indicators\'), \'title\'), items(\'Process_MDTI_Indicators\').title, \'Unknown\')}'
                          TLP_s: 'TLP:AMBER'
                          DistributionTargets_s: 'Microsoft Sentinel, Microsoft Defender XDR'
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
                    Process_FileHash_Indicator: [
                      'Succeeded'
                    ]
                  }
                  expression: {
                    equals: [
                      '@items(\'Process_MDTI_Indicators\').indicatorType'
                      'Url'
                    ]
                  }
                  type: 'If'
                }
              }
              runAfter: {}
              type: 'Scope'
            }
          }
          runAfter: {
            Parse_MDTI_Indicators: [
              'Succeeded'
            ]
          }
          type: 'Foreach'
          runtimeConfiguration: {
            concurrency: {
              repetitions: 20
            }
          }
        }
        Log_MDTI_Feed_Update: {
          runAfter: {
            Process_MDTI_Indicators: [
              'Succeeded'
            ]
          }
          type: 'ApiConnection'
          inputs: {
            body: {
              FeedId_g: '@{guid()}'
              FeedName_s: 'Microsoft Defender Threat Intelligence'
              FeedType_s: 'MDTI'
              FeedURL_s: 'https://ti.defender.microsoft.com/'
              Status_s: 'Active'
              LastUpdated_t: '@{utcNow()}'
              UpdateFrequency_s: '1 day'
              IndicatorCount_d: '@{length(body(\'Parse_MDTI_Indicators\').value)}'
              Description_s: 'Microsoft Defender Threat Intelligence Premium Feed'
              Category_s: 'Microsoft'
              TLP_s: 'TLP:AMBER'
              ConfidenceScore_d: 80
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
        Handle_MDTI_Error: {
          actions: {
            Log_MDTI_Error: {
              runAfter: {}
              type: 'ApiConnection'
              inputs: {
                body: {
                  ErrorSource_s: 'MDTI-Connector'
                  ErrorMessage_s: 'Failed to get MDTI indicators. Error: @{outputs(\'Get_MDTI_Indicators\')}'
                  Timestamp_t: '@{utcNow()}'
                  ActionId_g: '@{guid()}'
                  CorrelationId_g: '@{guid()}'
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
    defenderEndpointConnector
  ]
}

// Microsoft Entra ID connector
resource entraIDConnector 'Microsoft.Logic/workflows@2019-05-01' = {
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
            frequency: 'Hour'
            interval: 6
          }
          type: 'Recurrence'
        }
      }
      actions: {
        Process_High_Risk_IPs: {
          runAfter: {}
          type: 'ApiConnection'
          inputs: {
            body: 'CTI_IPIndicators_CL \n| where ConfidenceScore_d >= 90 and isnotempty(IPAddress_s) \n| where not(IPAddress_s matches regex "^10\\\\.|^172\\\\.(1[6-9]|2[0-9]|3[0-1])\\\\.|^192\\\\.168\\\\.")\n| where "Microsoft Entra ID" in (split(DistributionTargets_s, ", "))\n| project IPAddress_s, ConfidenceScore_d, ThreatType_s, Description_s, IndicatorId_g\n| limit 100'
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
              timerange: 'Last 24 hours'
            }
          }
        }
        For_Each_High_Risk_IP: {
          foreach: '@body(\'Process_High_Risk_IPs\').tables[0].rows'
          actions: {
            Create_Named_Location: {
              runAfter: {}
              type: 'ApiConnection'
              inputs: {
                body: {
                  '@odata.type': '#microsoft.graph.ipNamedLocation'
                  displayName: 'CTI-BlockedIP-@{first(split(item()[0],\'.\'))}-@{skip(split(item()[0],\'.\'),1)[0]}-@{skip(split(item()[0],\'.\'),2)[0]}-@{last(split(item()[0],\'.\'))}'
                  isTrusted: false
                  ipRanges: [
                    {
                      '@odata.type': '#microsoft.graph.ipRange'
                      cidrAddress: '@{item()[0]}/32'
                    }
                  ]
                }
                host: {
                  connection: {
                    name: '@parameters(\'$connections\')[\'microsoftgraph\'][\'connectionId\']'
                  }
                }
                method: 'post'
                path: '/v1.0/identity/conditionalAccess/namedLocations'
              }
            }
            Log_Transaction_EntraID: {
              runAfter: {
                Create_Named_Location: [
                  'Succeeded'
                ]
              }
              type: 'ApiConnection'
              inputs: {
                body: {
                  IndicatorType_s: 'IP'
                  IndicatorValue_s: '@{item()[0]}'
                  Action_s: 'Block'
                  TargetSystem_s: 'Microsoft Entra ID'
                  Status_s: 'Success'
                  Timestamp_t: '@{utcNow()}'
                  ActionId_g: '@{guid()}'
                  CorrelationId_g: '@{guid()}'
                  IndicatorId_g: '@{item()[4]}'
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
            Handle_EntraID_Error: {
              actions: {
                Log_EntraID_Error: {
                  runAfter: {}
                  type: 'ApiConnection'
                  inputs: {
                    body: {
                      IndicatorType_s: 'IP'
                      IndicatorValue_s: '@{item()[0]}'
                      Action_s: 'Block'
                      TargetSystem_s: 'Microsoft Entra ID'
                      Status_s: 'Failed'
                      ErrorMessage_s: '@{outputs(\'Create_Named_Location\')}'
                      Timestamp_t: '@{utcNow()}'
                      ActionId_g: '@{guid()}'
                      CorrelationId_g: '@{guid()}'
                      IndicatorId_g: '@{item()[4]}'
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
                Create_Named_Location: [
                  'Failed'
                ]
              }
              type: 'Scope'
            }
          }
          runAfter: {
            Process_High_Risk_IPs: [
              'Succeeded'
            ]
          }
          type: 'Foreach'
          runtimeConfiguration: {
            concurrency: {
              repetitions: 5
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

// Exchange Online connector
resource exoConnector 'Microsoft.Logic/workflows@2019-05-01' = {
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
        'graphApiUrl': {
          defaultValue: graphApiUrl
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
        Process_High_Risk_Domains: {
          runAfter: {}
          type: 'ApiConnection'
          inputs: {
            body: 'CTI_DomainIndicators_CL \n| where ConfidenceScore_d >= 90 and isnotempty(Domain_s)\n| where "Microsoft Exchange Online" in (split(DistributionTargets_s, ", "))\n| project Domain_s, ConfidenceScore_d, ThreatType_s, Description_s, IndicatorId_g\n| limit 100'
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
              timerange: 'Last 24 hours'
            }
          }
        }
        For_Each_High_Risk_Domain: {
          foreach: '@body(\'Process_High_Risk_Domains\').tables[0].rows'
          actions: {
            Create_ExO_TI_Domain: {
              runAfter: {}
              type: 'ApiConnection'
              inputs: {
                body: {
                  domainName: '@{item()[0]}'
                  threatType: '@{item()[2]}'
                  expirationDateTime: '@{addDays(utcNow(), 30)}'
                }
                host: {
                  connection: {
                    name: '@parameters(\'$connections\')[\'microsoftgraph\'][\'connectionId\']'
                  }
                }
                method: 'post'
                path: '/v1.0/security/threatIntelligence/hostedDomains'
              }
            }
            Log_Transaction_ExO: {
              runAfter: {
                Create_ExO_TI_Domain: [
                  'Succeeded'
                ]
              }
              type: 'ApiConnection'
              inputs: {
                body: {
                  IndicatorType_s: 'Domain'
                  IndicatorValue_s: '@{item()[0]}'
                  Action_s: 'Block'
                  TargetSystem_s: 'Microsoft Exchange Online'
                  Status_s: 'Success'
                  Timestamp_t: '@{utcNow()}'
                  ActionId_g: '@{guid()}'
                  CorrelationId_g: '@{guid()}'
                  IndicatorId_g: '@{item()[4]}'
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
            Handle_ExO_Error: {
              actions: {
                Log_ExO_Error: {
                  runAfter: {}
                  type: 'ApiConnection'
                  inputs: {
                    body: {
                      IndicatorType_s: 'Domain'
                      IndicatorValue_s: '@{item()[0]}'
                      Action_s: 'Block'
                      TargetSystem_s: 'Microsoft Exchange Online'
                      Status_s: 'Failed'
                      ErrorMessage_s: '@{outputs(\'Create_ExO_TI_Domain\')}'
                      Timestamp_t: '@{utcNow()}'
                      ActionId_g: '@{guid()}'
                      CorrelationId_g: '@{guid()}'
                      IndicatorId_g: '@{item()[4]}'
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
                Create_ExO_TI_Domain: [
                  'Failed'
                ]
              }
              type: 'Scope'
            }
          }
          runAfter: {
            Process_High_Risk_Domains: [
              'Succeeded'
            ]
          }
          type: 'Foreach'
          runtimeConfiguration: {
            concurrency: {
              repetitions: 5
            }
          }
        }
        Process_High_Risk_Emails: {
          runAfter: {
            For_Each_High_Risk_Domain: [
              'Succeeded'
            ]
          }
          type: 'ApiConnection'
          inputs: {
            body: 'CTI_EmailIndicators_CL \n| where ConfidenceScore_d >= 90 and isnotempty(EmailAddress_s)\n| where "Microsoft Exchange Online" in (split(DistributionTargets_s, ", "))\n| project EmailAddress_s, ConfidenceScore_d, ThreatType_s, Description_s, IndicatorId_g\n| limit 100'
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
              timerange: 'Last 24 hours'
            }
          }
        }
        For_Each_High_Risk_Email: {
          foreach: '@body(\'Process_High_Risk_Emails\').tables[0].rows'
          actions: {
            Create_ExO_TI_Email: {
              runAfter: {}
              type: 'ApiConnection'
              inputs: {
                body: {
                  emailAddress: '@{item()[0]}'
                  threatType: '@{item()[2]}'
                  expirationDateTime: '@{addDays(utcNow(), 30)}'
                }
                host: {
                  connection: {
                    name: '@parameters(\'$connections\')[\'microsoftgraph\'][\'connectionId\']'
                  }
                }
                method: 'post'
                path: '/v1.0/security/threatIntelligence/emailSenders'
              }
            }
            Log_Transaction_ExO_Email: {
              runAfter: {
                Create_ExO_TI_Email: [
                  'Succeeded'
                ]
              }
              type: 'ApiConnection'
              inputs: {
                body: {
                  IndicatorType_s: 'Email'
                  IndicatorValue_s: '@{item()[0]}'
                  Action_s: 'Block'
                  TargetSystem_s: 'Microsoft Exchange Online'
                  Status_s: 'Success'
                  Timestamp_t: '@{utcNow()}'
                  ActionId_g: '@{guid()}'
                  CorrelationId_g: '@{guid()}'
                  IndicatorId_g: '@{item()[4]}'
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
            Handle_ExO_Email_Error: {
              actions: {
                Log_ExO_Email_Error: {
                  runAfter: {}
                  type: 'ApiConnection'
                  inputs: {
                    body: {
                      IndicatorType_s: 'Email'
                      IndicatorValue_s: '@{item()[0]}'
                      Action_s: 'Block'
                      TargetSystem_s: 'Microsoft Exchange Online'
                      Status_s: 'Failed'
                      ErrorMessage_s: '@{outputs(\'Create_ExO_TI_Email\')}'
                      Timestamp_t: '@{utcNow()}'
                      ActionId_g: '@{guid()}'
                      CorrelationId_g: '@{guid()}'
                      IndicatorId_g: '@{item()[4]}'
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
                Create_ExO_TI_Email: [
                  'Failed'
                ]
              }
              type: 'Scope'
            }
          }
          runAfter: {
            Process_High_Risk_Emails: [
              'Succeeded'
            ]
          }
          type: 'Foreach'
          runtimeConfiguration: {
            concurrency: {
              repetitions: 5
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
    entraIDConnector
  ]
}

// Housekeeping Logic App for handling expired indicators
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
              minutes: [
                0
              ]
            }
            timeZone: 'UTC'
          }
          type: 'Recurrence'
        }
      }
      actions: {
        Process_Expired_IP_Indicators: {
          runAfter: {}
          type: 'ApiConnection'
          inputs: {
            body: 'CTI_IPIndicators_CL \n| where ExpirationDateTime_t < now() and Active_b == true\n| project IPAddress_s, IndicatorId_g, SourceFeed_s\n| limit 1000'
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
        For_Each_Expired_IP: {
          foreach: '@body(\'Process_Expired_IP_Indicators\').tables[0].rows'
          actions: {
            Set_IP_Inactive: {
              runAfter: {}
              type: 'ApiConnection'
              inputs: {
                body: {
                  IPAddress_s: '@{item()[0]}'
                  IndicatorId_g: '@{item()[1]}'
                  SourceFeed_s: '@{item()[2]}'
                  LastSeen_t: '@{utcNow()}'
                  Active_b: false
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
            Set_ThreatIntel_IP_Inactive: {
              runAfter: {
                Set_IP_Inactive: [
                  'Succeeded'
                ]
              }
              type: 'ApiConnection'
              inputs: {
                body: {
                  IndicatorId_g: '@{item()[1]}'
                  UpdatedTimeUtc_t: '@{utcNow()}'
                  Active_b: false
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
            Log_Expiration_IP: {
              runAfter: {
                Set_ThreatIntel_IP_Inactive: [
                  'Succeeded'
                ]
              }
              type: 'ApiConnection'
              inputs: {
                body: {
                  IndicatorType_s: 'IP'
                  IndicatorValue_s: '@{item()[0]}'
                  Action_s: 'Expire'
                  TargetSystem_s: 'CTI_Solution'
                  Status_s: 'Success'
                  Timestamp_t: '@{utcNow()}'
                  ActionId_g: '@{guid()}'
                  CorrelationId_g: '@{guid()}'
                  IndicatorId_g: '@{item()[1]}'
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
            Process_Expired_IP_Indicators: [
              'Succeeded'
            ]
          }
          type: 'Foreach'
          runtimeConfiguration: {
            concurrency: {
              repetitions: 10
            }
          }
        }
        Process_Expired_Domain_Indicators: {
          runAfter: {
            For_Each_Expired_IP: [
              'Succeeded'
            ]
          }
          type: 'ApiConnection'
          inputs: {
            body: 'CTI_DomainIndicators_CL \n| where ExpirationDateTime_t < now() and Active_b == true\n| project Domain_s, IndicatorId_g, SourceFeed_s\n| limit 1000'
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
        For_Each_Expired_Domain: {
          foreach: '@body(\'Process_Expired_Domain_Indicators\').tables[0].rows'
          actions: {
            Set_Domain_Inactive: {
              runAfter: {}
              type: 'ApiConnection'
              inputs: {
                body: {
                  Domain_s: '@{item()[0]}'
                  IndicatorId_g: '@{item()[1]}'
                  SourceFeed_s: '@{item()[2]}'
                  LastSeen_t: '@{utcNow()}'
                  Active_b: false
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
            Set_ThreatIntel_Domain_Inactive: {
              runAfter: {
                Set_Domain_Inactive: [
                  'Succeeded'
                ]
              }
              type: 'ApiConnection'
              inputs: {
                body: {
                  IndicatorId_g: '@{item()[1]}'
                  UpdatedTimeUtc_t: '@{utcNow()}'
                  Active_b: false
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
            Log_Expiration_Domain: {
              runAfter: {
                Set_ThreatIntel_Domain_Inactive: [
                  'Succeeded'
                ]
              }
              type: 'ApiConnection'
              inputs: {
                body: {
                  IndicatorType_s: 'Domain'
                  IndicatorValue_s: '@{item()[0]}'
                  Action_s: 'Expire'
                  TargetSystem_s: 'CTI_Solution'
                  Status_s: 'Success'
                  Timestamp_t: '@{utcNow()}'
                  ActionId_g: '@{guid()}'
                  CorrelationId_g: '@{guid()}'
                  IndicatorId_g: '@{item()[1]}'
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
            Process_Expired_Domain_Indicators: [
              'Succeeded'
            ]
          }
          type: 'Foreach'
          runtimeConfiguration: {
            concurrency: {
              repetitions: 10
            }
          }
        }
        Process_Expired_URL_Indicators: {
          runAfter: {
            For_Each_Expired_Domain: [
              'Succeeded'
            ]
          }
          type: 'ApiConnection'
          inputs: {
            body: 'CTI_URLIndicators_CL \n| where ExpirationDateTime_t < now() and Active_b == true\n| project URL_s, IndicatorId_g, SourceFeed_s\n| limit 1000'
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
        For_Each_Expired_URL: {
          foreach: '@body(\'Process_Expired_URL_Indicators\').tables[0].rows'
          actions: {
            Set_URL_Inactive: {
              runAfter: {}
              type: 'ApiConnection'
              inputs: {
                body: {
                  URL_s: '@{item()[0]}'
                  IndicatorId_g: '@{item()[1]}'
                  SourceFeed_s: '@{item()[2]}'
                  LastSeen_t: '@{utcNow()}'
                  Active_b: false
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
            Set_ThreatIntel_URL_Inactive: {
              runAfter: {
                Set_URL_Inactive: [
                  'Succeeded'
                ]
              }
              type: 'ApiConnection'
              inputs: {
                body: {
                  IndicatorId_g: '@{item()[1]}'
                  UpdatedTimeUtc_t: '@{utcNow()}'
                  Active_b: false
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
            Log_Expiration_URL: {
              runAfter: {
                Set_ThreatIntel_URL_Inactive: [
                  'Succeeded'
                ]
              }
              type: 'ApiConnection'
              inputs: {
                body: {
                  IndicatorType_s: 'URL'
                  IndicatorValue_s: '@{item()[0]}'
                  Action_s: 'Expire'
                  TargetSystem_s: 'CTI_Solution'
                  Status_s: 'Success'
                  Timestamp_t: '@{utcNow()}'
                  ActionId_g: '@{guid()}'
                  CorrelationId_g: '@{guid()}'
                  IndicatorId_g: '@{item()[1]}'
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
            Process_Expired_URL_Indicators: [
              'Succeeded'
            ]
          }
          type: 'Foreach'
          runtimeConfiguration: {
            concurrency: {
              repetitions: 10
            }
          }
        }
        Process_Expired_FileHash_Indicators: {
          runAfter: {
            For_Each_Expired_URL: [
              'Succeeded'
            ]
          }
          type: 'ApiConnection'
          inputs: {
            body: 'CTI_FileHashIndicators_CL \n| where ExpirationDateTime_t < now() and Active_b == true\n| project SHA256_s, IndicatorId_g, SourceFeed_s\n| limit 1000'
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
        For_Each_Expired_FileHash: {
          foreach: '@body(\'Process_Expired_FileHash_Indicators\').tables[0].rows'
          actions: {
            Set_FileHash_Inactive: {
              runAfter: {}
              type: 'ApiConnection'
              inputs: {
                body: {
                  SHA256_s: '@{item()[0]}'
                  IndicatorId_g: '@{item()[1]}'
                  SourceFeed_s: '@{item()[2]}'
                  LastSeen_t: '@{utcNow()}'
                  Active_b: false
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
            Set_ThreatIntel_FileHash_Inactive: {
              runAfter: {
                Set_FileHash_Inactive: [
                  'Succeeded'
                ]
              }
              type: 'ApiConnection'
              inputs: {
                body: {
                  IndicatorId_g: '@{item()[1]}'
                  UpdatedTimeUtc_t: '@{utcNow()}'
                  Active_b: false
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
            Log_Expiration_FileHash: {
              runAfter: {
                Set_ThreatIntel_FileHash_Inactive: [
                  'Succeeded'
                ]
              }
              type: 'ApiConnection'
              inputs: {
                body: {
                  IndicatorType_s: 'FileHash'
                  IndicatorValue_s: '@{item()[0]}'
                  Action_s: 'Expire'
                  TargetSystem_s: 'CTI_Solution'
                  Status_s: 'Success'
                  Timestamp_t: '@{utcNow()}'
                  ActionId_g: '@{guid()}'
                  CorrelationId_g: '@{guid()}'
                  IndicatorId_g: '@{item()[1]}'
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
            Process_Expired_FileHash_Indicators: [
              'Succeeded'
            ]
          }
          type: 'Foreach'
          runtimeConfiguration: {
            concurrency: {
              repetitions: 10
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
    exoConnector
  ]
}

// Microsoft Sentinel integration
resource sentinelSolution 'Microsoft.OperationsManagement/solutions@2015-11-01-preview' = if (enableSentinelIntegration) {
  name: 'SecurityInsights(${ctiWorkspace.name})'
  location: location
  plan: {
    name: 'SecurityInsights(${ctiWorkspace.name})'
    publisher: 'Microsoft'
    product: 'OMSGallery/SecurityInsights'
    promotionCode: ''
  }
  properties: {
    workspaceResourceId: ctiWorkspace.id
  }
}

// Security Copilot integration (if enabled)
resource dceForCopilot 'Microsoft.Insights/dataCollectionEndpoints@2021-04-01' = if (enableSecurityCopilot) {
  name: dceNameForCopilot
  location: location
  properties: {
    networkAcls: {
      publicNetworkAccess: 'Enabled'
    }
  }
  tags: tags
}

resource securityCopilotConnectorLogicApp 'Microsoft.Logic/workflows@2019-05-01' = if (enableSecurityCopilot) {
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
        'dceEndpointId': {
          defaultValue: enableSecurityCopilot ? dceForCopilot.id : ''
          type: 'String'
        }
      }
      triggers: {
        Recurrence: {
          recurrence: {
            frequency: 'Hour'
            interval: 24
          }
          type: 'Recurrence'
        }
      }
      actions: {
        Log_Copilot_Integration: {
          runAfter: {}
          type: 'ApiConnection'
          inputs: {
            body: {
              IntegrationName_s: 'Security Copilot'
              DCEName_s: enableSecurityCopilot ? dceForCopilot.name : ''
              Status_s: 'Active'
              Timestamp_t: '@{utcNow()}'
              Action_s: 'Configure'
              TargetSystem_s: 'Microsoft Security Copilot'
              ActionId_g: '@{guid()}'
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
        }
      }
    }
  }
  dependsOn: [
    housekeepingLogicApp
  ]
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

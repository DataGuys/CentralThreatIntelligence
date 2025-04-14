// Central Threat Intelligence (CTI) Solution - Enhanced Version
// This template deploys a comprehensive threat intelligence platform that integrates with Microsoft Security solutions

@description('Location for all resources.')
param location string = resourceGroup().location

@description('Name of the Log Analytics workspace for CTI')
param ctiWorkspaceName string = 'CTI-Workspace'

@description('Retention period in days for the CTI workspace')
@minValue(30)
@maxValue(730)
param ctiWorkspaceRetentionInDays int = 90

@description('Daily quota for Log Analytics workspace in GB')
param ctiWorkspaceDailyQuotaGb int = 5

@description('SKU for Log Analytics workspace')
@allowed([
  'PerGB2018'
  'Free'
  'PerNode'
  'Standard'
  'Standalone'
  'Premium'
])
param ctiWorkspaceSku string = 'PerGB2018'

@description('Enable Microsoft Sentinel integration with the CTI workspace')
param enableSentinelIntegration bool = true

@description('Resource ID of the existing Sentinel workspace (if you want to integrate with an existing Sentinel)')
param existingSentinelWorkspaceId string = ''

@description('Enable Microsoft Defender Threat Intelligence integration')
param enableMDTI bool = true

@description('Microsoft Entra App ID for API authentication')
param appClientId string = ''

@description('Microsoft Entra Tenant ID')
param tenantId string = subscription().tenantId

@description('URI for Microsoft Graph API')
param graphApiUrl string = 'https://graph.microsoft.com'

// Define Log Analytics workspace for CTI
resource ctiWorkspace 'Microsoft.OperationalInsights/workspaces@2022-10-01' = {
  name: ctiWorkspaceName
  location: location
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
  }
}

// Custom tables aligned with Microsoft's new schema
// Legacy tables for backward compatibility
resource ctiIpIndicatorsTable 'Microsoft.OperationalInsights/workspaces/tables@2022-10-01' = {
  parent: ctiWorkspace
  name: 'CTI_IPIndicators_CL'
  properties: {
    schema: {
      name: 'CTI_IPIndicators_CL'
      columns: [
        {
          name: 'IPAddress_s'
          type: 'string'
        }
        {
          name: 'ConfidenceScore_d'
          type: 'double'
        }
        {
          name: 'SourceFeed_s'
          type: 'string'
        }
        {
          name: 'FirstSeen_t'
          type: 'datetime'
        }
        {
          name: 'LastSeen_t'
          type: 'datetime'
        }
        {
          name: 'ExpirationDateTime_t'
          type: 'datetime'
        }
        {
          name: 'ThreatType_s'
          type: 'string'
        }
        {
          name: 'ThreatCategory_s'
          type: 'string'
        }
        {
          name: 'TLP_s'
          type: 'string'
        }
        {
          name: 'GeoLocation_s'
          type: 'string'
        }
        {
          name: 'ASN_s'
          type: 'string'
        }
        {
          name: 'Tags_s'
          type: 'string'
        }
        {
          name: 'Description_s'
          type: 'string'
        }
        {
          name: 'Action_s'
          type: 'string'
        }
        {
          name: 'ReportedBy_s'
          type: 'string'
        }
        {
          name: 'Active_b'
          type: 'bool'
        }
      ]
    }
  }
}

resource ctiFileHashIndicatorsTable 'Microsoft.OperationalInsights/workspaces/tables@2022-10-01' = {
  parent: ctiWorkspace
  name: 'CTI_FileHashIndicators_CL'
  properties: {
    schema: {
      name: 'CTI_FileHashIndicators_CL'
      columns: [
        {
          name: 'SHA256_s'
          type: 'string'
        }
        {
          name: 'MD5_s'
          type: 'string'
        }
        {
          name: 'SHA1_s'
          type: 'string'
        }
        {
          name: 'ConfidenceScore_d'
          type: 'double'
        }
        {
          name: 'SourceFeed_s'
          type: 'string'
        }
        {
          name: 'FirstSeen_t'
          type: 'datetime'
        }
        {
          name: 'LastSeen_t'
          type: 'datetime'
        }
        {
          name: 'ExpirationDateTime_t'
          type: 'datetime'
        }
        {
          name: 'MalwareFamily_s'
          type: 'string'
        }
        {
          name: 'ThreatType_s'
          type: 'string'
        }
        {
          name: 'ThreatCategory_s'
          type: 'string'
        }
        {
          name: 'TLP_s'
          type: 'string'
        }
        {
          name: 'Tags_s'
          type: 'string'
        }
        {
          name: 'Description_s'
          type: 'string'
        }
        {
          name: 'Action_s'
          type: 'string'
        }
        {
          name: 'ReportedBy_s'
          type: 'string'
        }
        {
          name: 'Active_b'
          type: 'bool'
        }
      ]
    }
  }
}

resource ctiDomainIndicatorsTable 'Microsoft.OperationalInsights/workspaces/tables@2022-10-01' = {
  parent: ctiWorkspace
  name: 'CTI_DomainIndicators_CL'
  properties: {
    schema: {
      name: 'CTI_DomainIndicators_CL'
      columns: [
        {
          name: 'Domain_s'
          type: 'string'
        }
        {
          name: 'ConfidenceScore_d'
          type: 'double'
        }
        {
          name: 'SourceFeed_s'
          type: 'string'
        }
        {
          name: 'FirstSeen_t'
          type: 'datetime'
        }
        {
          name: 'LastSeen_t'
          type: 'datetime'
        }
        {
          name: 'ExpirationDateTime_t'
          type: 'datetime'
        }
        {
          name: 'ThreatType_s'
          type: 'string'
        }
        {
          name: 'ThreatCategory_s'
          type: 'string'
        }
        {
          name: 'TLP_s'
          type: 'string'
        }
        {
          name: 'Tags_s'
          type: 'string'
        }
        {
          name: 'Description_s'
          type: 'string'
        }
        {
          name: 'Action_s'
          type: 'string'
        }
        {
          name: 'ReportedBy_s'
          type: 'string'
        }
        {
          name: 'Active_b'
          type: 'bool'
        }
      ]
    }
  }
}

resource ctiUrlIndicatorsTable 'Microsoft.OperationalInsights/workspaces/tables@2022-10-01' = {
  parent: ctiWorkspace
  name: 'CTI_URLIndicators_CL'
  properties: {
    schema: {
      name: 'CTI_URLIndicators_CL'
      columns: [
        {
          name: 'URL_s'
          type: 'string'
        }
        {
          name: 'ConfidenceScore_d'
          type: 'double'
        }
        {
          name: 'SourceFeed_s'
          type: 'string'
        }
        {
          name: 'FirstSeen_t'
          type: 'datetime'
        }
        {
          name: 'LastSeen_t'
          type: 'datetime'
        }
        {
          name: 'ExpirationDateTime_t'
          type: 'datetime'
        }
        {
          name: 'ThreatType_s'
          type: 'string'
        }
        {
          name: 'ThreatCategory_s'
          type: 'string'
        }
        {
          name: 'TLP_s'
          type: 'string'
        }
        {
          name: 'Tags_s'
          type: 'string'
        }
        {
          name: 'Description_s'
          type: 'string'
        }
        {
          name: 'Action_s'
          type: 'string'
        }
        {
          name: 'ReportedBy_s'
          type: 'string'
        }
        {
          name: 'Active_b'
          type: 'bool'
        }
      ]
    }
  }
}

// New STIX-compatible tables aligned with Microsoft's new schema
resource ctiThreatIntelIndicatorTable 'Microsoft.OperationalInsights/workspaces/tables@2022-10-01' = {
  parent: ctiWorkspace
  name: 'CTI_ThreatIntelIndicator_CL'
  properties: {
    schema: {
      name: 'CTI_ThreatIntelIndicator_CL'
      columns: [
        {
          name: 'Type_s'
          type: 'string'
        }
        {
          name: 'Value_s'
          type: 'string'
        }
        {
          name: 'Pattern_s'
          type: 'string'
        }
        {
          name: 'PatternType_s'
          type: 'string'
        }
        {
          name: 'Name_s'
          type: 'string'
        }
        {
          name: 'Description_s'
          type: 'string'
        }
        {
          name: 'Action_s'
          type: 'string'
        }
        {
          name: 'Confidence_d'
          type: 'double'
        }
        {
          name: 'ValidFrom_t'
          type: 'datetime'
        }
        {
          name: 'ValidUntil_t'
          type: 'datetime'
        }
        {
          name: 'CreatedTimeUtc_t'
          type: 'datetime'
        }
        {
          name: 'UpdatedTimeUtc_t'
          type: 'datetime'
        }
        {
          name: 'Source_s'
          type: 'string'
        }
        {
          name: 'SourceRef_s'
          type: 'string'
        }
        {
          name: 'KillChainPhases_s'
          type: 'string'
        }
        {
          name: 'Labels_s'
          type: 'string'
        }
        {
          name: 'ThreatType_s'
          type: 'string'
        }
        {
          name: 'TLP_s'
          type: 'string'
        }
        {
          name: 'Active_b'
          type: 'bool'
        }
        {
          name: 'ObjectId_g'
          type: 'guid'
        }
        {
          name: 'IndicatorId_g'
          type: 'guid'
        }
      ]
    }
  }
}

resource ctiThreatIntelObjectsTable 'Microsoft.OperationalInsights/workspaces/tables@2022-10-01' = {
  parent: ctiWorkspace
  name: 'CTI_ThreatIntelObjects_CL'
  properties: {
    schema: {
      name: 'CTI_ThreatIntelObjects_CL'
      columns: [
        {
          name: 'ObjectId_g'
          type: 'guid'
        }
        {
          name: 'Type_s'
          type: 'string'
        }
        {
          name: 'CreatedTimeUtc_t'
          type: 'datetime'
        }
        {
          name: 'UpdatedTimeUtc_t'
          type: 'datetime'
        }
        {
          name: 'SourceId_s'
          type: 'string'
        }
        {
          name: 'Source_s'
          type: 'string'
        }
        {
          name: 'Name_s'
          type: 'string'
        }
        {
          name: 'Description_s'
          type: 'string'
        }
        {
          name: 'JsonData_s'
          type: 'string'
        }
        {
          name: 'Relations_s'
          type: 'string'
        }
        {
          name: 'TLP_s'
          type: 'string'
        }
        {
          name: 'Active_b'
          type: 'bool'
        }
      ]
    }
  }
}

// Transaction and audit log table
resource ctiTransactionLogTable 'Microsoft.OperationalInsights/workspaces/tables@2022-10-01' = {
  parent: ctiWorkspace
  name: 'CTI_TransactionLog_CL'
  properties: {
    schema: {
      name: 'CTI_TransactionLog_CL'
      columns: [
        {
          name: 'IndicatorType_s'
          type: 'string'
        }
        {
          name: 'IndicatorValue_s'
          type: 'string'
        }
        {
          name: 'Action_s'
          type: 'string'
        }
        {
          name: 'TargetSystem_s'
          type: 'string'
        }
        {
          name: 'Status_s'
          type: 'string'
        }
        {
          name: 'ErrorMessage_s'
          type: 'string'
        }
        {
          name: 'Timestamp_t'
          type: 'datetime'
        }
        {
          name: 'ActionId_g'
          type: 'guid'
        }
        {
          name: 'CorrelationId_g'
          type: 'guid'
        }
        {
          name: 'IndicatorId_g'
          type: 'guid'
        }
        {
          name: 'RunbookName_s'
          type: 'string'
        }
        {
          name: 'TriggerSource_s'
          type: 'string'
        }
      ]
    }
  }
}

// Intelligence feeds metadata table
resource ctiIntelligenceFeedsTable 'Microsoft.OperationalInsights/workspaces/tables@2022-10-01' = {
  parent: ctiWorkspace
  name: 'CTI_IntelligenceFeeds_CL'
  properties: {
    schema: {
      name: 'CTI_IntelligenceFeeds_CL'
      columns: [
        {
          name: 'FeedId_g'
          type: 'guid'
        }
        {
          name: 'FeedName_s'
          type: 'string'
        }
        {
          name: 'FeedType_s'
          type: 'string'
        }
        {
          name: 'FeedURL_s'
          type: 'string'
        }
        {
          name: 'Description_s'
          type: 'string'
        }
        {
          name: 'Category_s'
          type: 'string'
        }
        {
          name: 'TLP_s'
          type: 'string'
        }
        {
          name: 'ConfidenceScore_d'
          type: 'double'
        }
        {
          name: 'LastUpdated_t'
          type: 'datetime'
        }
        {
          name: 'UpdateFrequency_s'
          type: 'string'
        }
        {
          name: 'Status_s'
          type: 'string'
        }
        {
          name: 'IndicatorCount_d'
          type: 'double'
        }
        {
          name: 'Active_b'
          type: 'bool'
        }
      ]
    }
  }
}

// Analytics feedback table for tracking matches and false positives
resource ctiAnalyticsFeedbackTable 'Microsoft.OperationalInsights/workspaces/tables@2022-10-01' = {
  parent: ctiWorkspace
  name: 'CTI_AnalyticsFeedback_CL'
  properties: {
    schema: {
      name: 'CTI_AnalyticsFeedback_CL'
      columns: [
        {
          name: 'FeedbackId_g'
          type: 'guid'
        }
        {
          name: 'IndicatorId_g'
          type: 'guid'
        }
        {
          name: 'IndicatorValue_s'
          type: 'string'
        }
        {
          name: 'IndicatorType_s'
          type: 'string'
        }
        {
          name: 'MatchType_s'
          type: 'string'
        }
        {
          name: 'MatchedValue_s'
          type: 'string'
        }
        {
          name: 'IncidentId_s'
          type: 'string'
        }
        {
          name: 'AlertId_s'
          type: 'string'
        }
        {
          name: 'SourceSystem_s'
          type: 'string'
        }
        {
          name: 'Timestamp_t'
          type: 'datetime'
        }
        {
          name: 'FeedbackType_s'
          type: 'string'
        }
        {
          name: 'Comments_s'
          type: 'string'
        }
        {
          name: 'SubmittedBy_s'
          type: 'string'
        }
        {
          name: 'ConfidenceAdjustment_d'
          type: 'double'
        }
      ]
    }
  }
}

// MITRE ATT&CK mapping table
resource ctiTacticsTechniquesTable 'Microsoft.OperationalInsights/workspaces/tables@2022-10-01' = {
  parent: ctiWorkspace
  name: 'CTI_TacticsTechniques_CL'
  properties: {
    schema: {
      name: 'CTI_TacticsTechniques_CL'
      columns: [
        {
          name: 'IndicatorId_g'
          type: 'guid'
        }
        {
          name: 'IndicatorValue_s'
          type: 'string'
        }
        {
          name: 'TacticId_s'
          type: 'string'
        }
        {
          name: 'TacticName_s'
          type: 'string'
        }
        {
          name: 'TechniqueId_s'
          type: 'string'
        }
        {
          name: 'TechniqueName_s'
          type: 'string'
        }
        {
          name: 'SubTechniqueId_s'
          type: 'string'
        }
        {
          name: 'SubTechniqueName_s'
          type: 'string'
        }
        {
          name: 'TacticURL_s'
          type: 'string'
        }
        {
          name: 'TechniqueURL_s'
          type: 'string'
        }
        {
          name: 'Timestamp_t'
          type: 'datetime'
        }
      ]
    }
  }
}

// Workbooks for threat intelligence dashboards
resource iocOverviewWorkbook 'Microsoft.Insights/workbooks@2021-08-01' = {
  name: guid('IOCOverviewWorkbook', ctiWorkspace.id)
  location: location
  kind: 'shared'
  properties: {
    displayName: 'CTI - IOC Overview'
    serializedData: loadTextContent('workbooks/ioc-overview.json')
    version: '1.0'
    sourceId: ctiWorkspace.id
    category: 'workbook'
  }
}

resource feedHealthWorkbook 'Microsoft.Insights/workbooks@2021-08-01' = {
  name: guid('FeedHealthWorkbook', ctiWorkspace.id)
  location: location
  kind: 'shared'
  properties: {
    displayName: 'CTI - Feed Health'
    serializedData: loadTextContent('workbooks/feed-health.json')
    version: '1.0'
    sourceId: ctiWorkspace.id
    category: 'workbook'
  }
}

resource iocLifecycleWorkbook 'Microsoft.Insights/workbooks@2021-08-01' = {
  name: guid('IOCLifecycleWorkbook', ctiWorkspace.id)
  location: location
  kind: 'shared'
  properties: {
    displayName: 'CTI - IOC Lifecycle'
    serializedData: loadTextContent('workbooks/ioc-lifecycle.json')
    version: '1.0'
    sourceId: ctiWorkspace.id
    category: 'workbook'
  }
}

resource iocDisseminationWorkbook 'Microsoft.Insights/workbooks@2021-08-01' = {
  name: guid('IOCDisseminationWorkbook', ctiWorkspace.id)
  location: location
  kind: 'shared'
  properties: {
    displayName: 'CTI - IOC Dissemination'
    serializedData: loadTextContent('workbooks/ioc-dissemination.json')
    version: '1.0'
    sourceId: ctiWorkspace.id
    category: 'workbook'
  }
}

resource mitreMappingWorkbook 'Microsoft.Insights/workbooks@2021-08-01' = {
  name: guid('MITREMappingWorkbook', ctiWorkspace.id)
  location: location
  kind: 'shared'
  properties: {
    displayName: 'CTI - MITRE ATT&CK Coverage'
    serializedData: loadTextContent('workbooks/mitre-mapping.json')
    version: '1.0'
    sourceId: ctiWorkspace.id
    category: 'workbook'
  }
}

resource threatActorWorkbook 'Microsoft.Insights/workbooks@2021-08-01' = {
  name: guid('ThreatActorWorkbook', ctiWorkspace.id)
  location: location
  kind: 'shared'
  properties: {
    displayName: 'CTI - Threat Actor Tracking'
    serializedData: loadTextContent('workbooks/threat-actor.json')
    version: '1.0'
    sourceId: ctiWorkspace.id
    category: 'workbook'
  }
}

resource falsePositiveWorkbook 'Microsoft.Insights/workbooks@2021-08-01' = {
  name: guid('FalsePositiveWorkbook', ctiWorkspace.id)
  location: location
  kind: 'shared'
  properties: {
    displayName: 'CTI - False Positive Analysis'
    serializedData: loadTextContent('workbooks/false-positive.json')
    version: '1.0'
    sourceId: ctiWorkspace.id
    category: 'workbook'
  }
}

// User-assigned managed identity for Logic Apps
resource managedIdentity 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' = {
  name: 'id-cti-automation'
  location: location
}

// Logic App Service Plan (Premium for reliable execution)
resource logicAppServicePlan 'Microsoft.Web/serverfarms@2022-03-01' = {
  name: 'CTI-LogicApp-ServicePlan'
  location: location
  sku: {
    name: 'WS1'
    tier: 'WorkflowStandard'
  }
  properties: {}
}

// Logic App for TAXII feed ingestion
resource taxiiConnectorLogicApp 'Microsoft.Logic/workflows@2019-05-01' = {
  name: 'CTI-TAXII2-Connector'
  location: location
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
      }
      triggers: {
        Recurrence: {
          recurrence: {
            frequency: 'Hour'
            interval: 6
          },
          type: 'Recurrence'
        }
      },
      actions: {
        For_each_TAXII_feed: {
          foreach: '@body(\'Get_TAXII_feeds\')',
          actions: {
            Get_TAXII_objects: {
              runAfter: {},
              type: 'Http',
              inputs: {
                method: 'GET',
                uri: '@{items(\'For_each_TAXII_feed\').FeedURL_s}/collections/@{items(\'For_each_TAXII_feed\').CollectionId_s}/objects',
                headers: {
                  Accept: 'application/vnd.oasis.stix+json; version=2.1',
                  'Content-Type': 'application/json',
                  Authorization: 'Basic @{items(\'For_each_TAXII_feed\').EncodedCredentials_s}'
                }
              }
            },
            Parse_STIX_response: {
              runAfter: {
                Get_TAXII_objects: [
                  'Succeeded'
                ]
              },
              type: 'ParseJson',
              inputs: {
                content: '@body(\'Get_TAXII_objects\')',
                schema: {
                  type: 'object',
                  properties: {
                    more: {
                      type: 'boolean'
                    },
                    objects: {
                      type: 'array',
                      items: {
                        type: 'object',
                        properties: {}
                      }
                    }
                  }
                }
              }
            },
            Process_STIX_objects: {
              foreach: '@body(\'Parse_STIX_response\').objects',
              actions: {
                Condition_-_Check_Object_Type: {
                  actions: {
                    'Process_Indicator_-_IP': {
                      actions: {
                        Parse_IP_Indicator: {
                          runAfter: {},
                          type: 'Compose',
                          inputs: '@items(\'Process_STIX_objects\').pattern'
                        },
                        Send_IP_to_Log_Analytics: {
                          runAfter: {
                            Parse_IP_Indicator: [
                              'Succeeded'
                            ]
                          },
                          type: 'ApiConnection',
                          inputs: {
                            body: {
                              IPAddress_s: '@replace(replace(outputs(\'Parse_IP_Indicator\'),\'ipv4-addr:value = \\\'\',\'\'),\'\\\'\',\'\')',
                              ObjectId_g: '@{items(\'Process_STIX_objects\').id}',
                              IndicatorId_g: '@{guid()}',
                              ConfidenceScore_d: '@if(equals(items(\'Process_STIX_objects\')?[\'confidence\'], null), 50, items(\'Process_STIX_objects\').confidence)',
                              SourceFeed_s: '@{items(\'For_each_TAXII_feed\').FeedName_s}',
                              FirstSeen_t: '@{items(\'Process_STIX_objects\').created}',
                              LastSeen_t: '@{items(\'Process_STIX_objects\').modified}',
                              ExpirationDateTime_t: '@{items(\'Process_STIX_objects\').valid_until}',
                              ThreatType_s: '@{if(contains(items(\'Process_STIX_objects\'), \'labels\'), join(items(\'Process_STIX_objects\').labels, \', \'), \'Unknown\')}',
                              Description_s: '@{items(\'Process_STIX_objects\').description}',
                              TLP_s: '@{if(contains(items(\'Process_STIX_objects\').object_marking_refs[0], \'tlp\'), last(split(items(\'Process_STIX_objects\').object_marking_refs[0], \':\' )), \'TLP:AMBER\')}',
                              Active_b: '@{if(equals(items(\'Process_STIX_objects\')?[\'revoked\'], true), false, true)}'
                            },
                            host: {
                              connection: {
                                name: '@parameters(\'$connections\')[\'azureloganalyticsdatacollector\'][\'connectionId\']'
                              }
                            },
                            method: 'post',
                            path: '/api/logs',
                            queries: {
                              logType: 'CTI_IPIndicators_CL'
                            }
                          }
                        },
                        Send_to_ThreatIntelIndicator: {
                          runAfter: {
                            Parse_IP_Indicator: [
                              'Succeeded'
                            ]
                          },
                          type: 'ApiConnection',
                          inputs: {
                            body: {
                              Type_s: 'ipv4-addr',
                              Value_s: '@replace(replace(outputs(\'Parse_IP_Indicator\'),\'ipv4-addr:value = \\\'\',\'\'),\'\\\'\',\'\')',
                              Pattern_s: '@{items(\'Process_STIX_objects\').pattern}',
                              PatternType_s: '@{items(\'Process_STIX_objects\').pattern_type}',
                              Name_s: '@{if(contains(items(\'Process_STIX_objects\'), \'name\'), items(\'Process_STIX_objects\').name, \'IP Indicator\')}',
                              Description_s: '@{items(\'Process_STIX_objects\').description}',
                              Action_s: 'alert',
                              Confidence_d: '@if(equals(items(\'Process_STIX_objects\')?[\'confidence\'], null), 50, items(\'Process_STIX_objects\').confidence)',
                              ValidFrom_t: '@{items(\'Process_STIX_objects\').valid_from}',
                              ValidUntil_t: '@{items(\'Process_STIX_objects\').valid_until}',
                              CreatedTimeUtc_t: '@{items(\'Process_STIX_objects\').created}',
                              UpdatedTimeUtc_t: '@{items(\'Process_STIX_objects\').modified}',
                              Source_s: '@{items(\'For_each_TAXII_feed\').FeedName_s}',
                              SourceRef_s: '@{items(\'For_each_TAXII_feed\').FeedURL_s}',
                              KillChainPhases_s: '@{if(contains(items(\'Process_STIX_objects\'), \'kill_chain_phases\'), string(items(\'Process_STIX_objects\').kill_chain_phases), \'\')}',
                              Labels_s: '@{if(contains(items(\'Process_STIX_objects\'), \'labels\'), join(items(\'Process_STIX_objects\').labels, \', \'), \'\')}',
                              ThreatType_s: '@{if(contains(items(\'Process_STIX_objects\'), \'labels\'), join(items(\'Process_STIX_objects\').labels, \', \'), \'Unknown\')}',
                              TLP_s: '@{if(contains(items(\'Process_STIX_objects\').object_marking_refs[0], \'tlp\'), last(split(items(\'Process_STIX_objects\').object_marking_refs[0], \':\' )), \'TLP:AMBER\')}',
                              Active_b: '@{if(equals(items(\'Process_STIX_objects\')?[\'revoked\'], true), false, true)}',
                              ObjectId_g: '@{items(\'Process_STIX_objects\').id}',
                              IndicatorId_g: '@{guid()}'
                            },
                            host: {
                              connection: {
                                name: '@parameters(\'$connections\')[\'azureloganalyticsdatacollector\'][\'connectionId\']'
                              }
                            },
                            method: 'post',
                            path: '/api/logs',
                            queries: {
                              logType: 'CTI_ThreatIntelIndicator_CL'
                            }
                          }
                        }
                      },
                      runAfter: {},
                      expression: {
                        and: [
                          {
                            equals: [
                              '@items(\'Process_STIX_objects\').type',
                              'indicator'
                            ]
                          },
                          {
                            contains: [
                              '@items(\'Process_STIX_objects\').pattern',
                              'ipv4-addr'
                            ]
                          }
                        ]
                      },
                      type: 'If'
                    },
                    'Process_Indicator_-_Domain': {
                      actions: {
                        Parse_Domain_Indicator: {
                          runAfter: {},
                          type: 'Compose',
                          inputs: '@items(\'Process_STIX_objects\').pattern'
                        },
                        Send_Domain_to_Log_Analytics: {
                          runAfter: {
                            Parse_Domain_Indicator: [
                              'Succeeded'
                            ]
                          },
                          type: 'ApiConnection',
                          inputs: {
                            body: {
                              Domain_s: '@replace(replace(outputs(\'Parse_Domain_Indicator\'),\'domain-name:value = \\\'\',\'\'),\'\\\'\',\'\')',
                              ObjectId_g: '@{items(\'Process_STIX_objects\').id}',
                              IndicatorId_g: '@{guid()}',
                              ConfidenceScore_d: '@if(equals(items(\'Process_STIX_objects\')?[\'confidence\'], null), 50, items(\'Process_STIX_objects\').confidence)',
                              SourceFeed_s: '@{items(\'For_each_TAXII_feed\').FeedName_s}',
                              FirstSeen_t: '@{items(\'Process_STIX_objects\').created}',
                              LastSeen_t: '@{items(\'Process_STIX_objects\').modified}',
                              ExpirationDateTime_t: '@{items(\'Process_STIX_objects\').valid_until}',
                              ThreatType_s: '@{if(contains(items(\'Process_STIX_objects\'), \'labels\'), join(items(\'Process_STIX_objects\').labels, \', \'), \'Unknown\')}',
                              Description_s: '@{items(\'Process_STIX_objects\').description}',
                              TLP_s: '@{if(contains(items(\'Process_STIX_objects\').object_marking_refs[0], \'tlp\'), last(split(items(\'Process_STIX_objects\').object_marking_refs[0], \':\' )), \'TLP:AMBER\')}',
                              Active_b: '@{if(equals(items(\'Process_STIX_objects\')?[\'revoked\'], true), false, true)}'
                            },
                            host: {
                              connection: {
                                name: '@parameters(\'$connections\')[\'azureloganalyticsdatacollector\'][\'connectionId\']'
                              }
                            },
                            method: 'post',
                            path: '/api/logs',
                            queries: {
                              logType: 'CTI_DomainIndicators_CL'
                            }
                          }
                        },
                        Send_to_ThreatIntelIndicator_Domain: {
                          runAfter: {
                            Parse_Domain_Indicator: [
                              'Succeeded'
                            ]
                          },
                          type: 'ApiConnection',
                          inputs: {
                            body: {
                              Type_s: 'domain-name',
                              Value_s: '@replace(replace(outputs(\'Parse_Domain_Indicator\'),\'domain-name:value = \\\'\',\'\'),\'\\\'\',\'\')',
                              Pattern_s: '@{items(\'Process_STIX_objects\').pattern}',
                              PatternType_s: '@{items(\'Process_STIX_objects\').pattern_type}',
                              Name_s: '@{if(contains(items(\'Process_STIX_objects\'), \'name\'), items(\'Process_STIX_objects\').name, \'Domain Indicator\')}',
                              Description_s: '@{items(\'Process_STIX_objects\').description}',
                              Action_s: 'alert',
                              Confidence_d: '@if(equals(items(\'Process_STIX_objects\')?[\'confidence\'], null), 50, items(\'Process_STIX_objects\').confidence)',
                              ValidFrom_t: '@{items(\'Process_STIX_objects\').valid_from}',
                              ValidUntil_t: '@{items(\'Process_STIX_objects\').valid_until}',
                              CreatedTimeUtc_t: '@{items(\'Process_STIX_objects\').created}',
                              UpdatedTimeUtc_t: '@{items(\'Process_STIX_objects\').modified}',
                              Source_s: '@{items(\'For_each_TAXII_feed\').FeedName_s}',
                              SourceRef_s: '@{items(\'For_each_TAXII_feed\').FeedURL_s}',
                              KillChainPhases_s: '@{if(contains(items(\'Process_STIX_objects\'), \'kill_chain_phases\'), string(items(\'Process_STIX_objects\').kill_chain_phases), \'\')}',
                              Labels_s: '@{if(contains(items(\'Process_STIX_objects\'), \'labels\'), join(items(\'Process_STIX_objects\').labels, \', \'), \'\')}',
                              ThreatType_s: '@{if(contains(items(\'Process_STIX_objects\'), \'labels\'), join(items(\'Process_STIX_objects\').labels, \', \'), \'Unknown\')}',
                              TLP_s: '@{if(contains(items(\'Process_STIX_objects\').object_marking_refs[0], \'tlp\'), last(split(items(\'Process_STIX_objects\').object_marking_refs[0], \':\' )), \'TLP:AMBER\')}',
                              Active_b: '@{if(equals(items(\'Process_STIX_objects\')?[\'revoked\'], true), false, true)}',
                              ObjectId_g: '@{items(\'Process_STIX_objects\').id}',
                              IndicatorId_g: '@{guid()}'
                            },
                            host: {
                              connection: {
                                name: '@parameters(\'$connections\')[\'azureloganalyticsdatacollector\'][\'connectionId\']'
                              }
                            },
                            method: 'post',
                            path: '/api/logs',
                            queries: {
                              logType: 'CTI_ThreatIntelIndicator_CL'
                            }
                          }
                        }
                      },
                      runAfter: {
                        'Process_Indicator_-_IP': [
                          'Succeeded'
                        ]
                      },
                      expression: {
                        and: [
                          {
                            equals: [
                              '@items(\'Process_STIX_objects\').type',
                              'indicator'
                            ]
                          },
                          {
                            contains: [
                              '@items(\'Process_STIX_objects\').pattern',
                              'domain-name'
                            ]
                          }
                        ]
                      },
                      type: 'If'
                    },
                    'Process_Indicator_-_URL': {
                      actions: {
                        Parse_URL_Indicator: {
                          runAfter: {},
                          type: 'Compose',
                          inputs: '@items(\'Process_STIX_objects\').pattern'
                        },
                        Send_URL_to_Log_Analytics: {
                          runAfter: {
                            Parse_URL_Indicator: [
                              'Succeeded'
                            ]
                          },
                          type: 'ApiConnection',
                          inputs: {
                            body: {
                              URL_s: '@replace(replace(outputs(\'Parse_URL_Indicator\'),\'url:value = \\\'\',\'\'),\'\\\'\',\'\')',
                              ObjectId_g: '@{items(\'Process_STIX_objects\').id}',
                              IndicatorId_g: '@{guid()}',
                              ConfidenceScore_d: '@if(equals(items(\'Process_STIX_objects\')?[\'confidence\'], null), 50, items(\'Process_STIX_objects\').confidence)',
                              SourceFeed_s: '@{items(\'For_each_TAXII_feed\').FeedName_s}',
                              FirstSeen_t: '@{items(\'Process_STIX_objects\').created}',
                              LastSeen_t: '@{items(\'Process_STIX_objects\').modified}',
                              ExpirationDateTime_t: '@{items(\'Process_STIX_objects\').valid_until}',
                              ThreatType_s: '@{if(contains(items(\'Process_STIX_objects\'), \'labels\'), join(items(\'Process_STIX_objects\').labels, \', \'), \'Unknown\')}',
                              Description_s: '@{items(\'Process_STIX_objects\').description}',
                              TLP_s: '@{if(contains(items(\'Process_STIX_objects\').object_marking_refs[0], \'tlp\'), last(split(items(\'Process_STIX_objects\').object_marking_refs[0], \':\' )), \'TLP:AMBER\')}',
                              Active_b: '@{if(equals(items(\'Process_STIX_objects\')?[\'revoked\'], true), false, true)}'
                            },
                            host: {
                              connection: {
                                name: '@parameters(\'$connections\')[\'azureloganalyticsdatacollector\'][\'connectionId\']'
                              }
                            },
                            method: 'post',
                            path: '/api/logs',
                            queries: {
                              logType: 'CTI_URLIndicators_CL'
                            }
                          }
                        },
                        Send_to_ThreatIntelIndicator_URL: {
                          runAfter: {
                            Parse_URL_Indicator: [
                              'Succeeded'
                            ]
                          },
                          type: 'ApiConnection',
                          inputs: {
                            body: {
                              Type_s: 'url',
                              Value_s: '@replace(replace(outputs(\'Parse_URL_Indicator\'),\'url:value = \\\'\',\'\'),\'\\\'\',\'\')',
                              Pattern_s: '@{items(\'Process_STIX_objects\').pattern}',
                              PatternType_s: '@{items(\'Process_STIX_objects\').pattern_type}',
                              Name_s: '@{if(contains(items(\'Process_STIX_objects\'), \'name\'), items(\'Process_STIX_objects\').name, \'URL Indicator\')}',
                              Description_s: '@{items(\'Process_STIX_objects\').description}',
                              Action_s: 'alert',
                              Confidence_d: '@if(equals(items(\'Process_STIX_objects\')?[\'confidence\'], null), 50, items(\'Process_STIX_objects\').confidence)',
                              ValidFrom_t: '@{items(\'Process_STIX_objects\').valid_from}',
                              ValidUntil_t: '@{items(\'Process_STIX_objects\').valid_until}',
                              CreatedTimeUtc_t: '@{items(\'Process_STIX_objects\').created}',
                              UpdatedTimeUtc_t: '@{items(\'Process_STIX_objects\').modified}',
                              Source_s: '@{items(\'For_each_TAXII_feed\').FeedName_s}',
                              SourceRef_s: '@{items(\'For_each_TAXII_feed\').FeedURL_s}',
                              KillChainPhases_s: '@{if(contains(items(\'Process_STIX_objects\'), \'kill_chain_phases\'), string(items(\'Process_STIX_objects\').kill_chain_phases), \'\')}',
                              Labels_s: '@{if(contains(items(\'Process_STIX_objects\'), \'labels\'), join(items(\'Process_STIX_objects\').labels, \', \'), \'\')}',
                              ThreatType_s: '@{if(contains(items(\'Process_STIX_objects\'), \'labels\'), join(items(\'Process_STIX_objects\').labels, \', \'), \'Unknown\')}',
                              TLP_s: '@{if(contains(items(\'Process_STIX_objects\').object_marking_refs[0], \'tlp\'), last(split(items(\'Process_STIX_objects\').object_marking_refs[0], \':\' )), \'TLP:AMBER\')}',
                              Active_b: '@{if(equals(items(\'Process_STIX_objects\')?[\'revoked\'], true), false, true)}',
                              ObjectId_g: '@{items(\'Process_STIX_objects\').id}',
                              IndicatorId_g: '@{guid()}'
                            },
                            host: {
                              connection: {
                                name: '@parameters(\'$connections\')[\'azureloganalyticsdatacollector\'][\'connectionId\']'
                              }
                            },
                            method: 'post',
                            path: '/api/logs',
                            queries: {
                              logType: 'CTI_ThreatIntelIndicator_CL'
                            }
                          }
                        }
                      },
                      runAfter: {
                        'Process_Indicator_-_Domain': [
                          'Succeeded'
                        ]
                      },
                      expression: {
                        and: [
                          {
                            equals: [
                              '@items(\'Process_STIX_objects\').type',
                              'indicator'
                            ]
                          },
                          {
                            contains: [
                              '@items(\'Process_STIX_objects\').pattern',
                              'url'
                            ]
                          }
                        ]
                      },
                      type: 'If'
                    },
                    'Process_Indicator_-_File_Hash': {
                      actions: {
                        Parse_File_Hash_Indicator: {
                          runAfter: {},
                          type: 'Compose',
                          inputs: '@items(\'Process_STIX_objects\').pattern'
                        },
                        Condition_for_Hash_Type: {
                          actions: {
                            Parse_SHA256: {
                              runAfter: {},
                              type: 'Compose',
                              inputs: '@replace(replace(outputs(\'Parse_File_Hash_Indicator\'),\'file:hashes.sha256 = \\\'\',\'\'),\'\\\'\',\'\')'
                            },
                            Send_FileHash_to_Log_Analytics: {
                              runAfter: {
                                Parse_SHA256: [
                                  'Succeeded'
                                ]
                              },
                              type: 'ApiConnection',
                              inputs: {
                                body: {
                                  SHA256_s: '@{outputs(\'Parse_SHA256\')}',
                                  ObjectId_g: '@{items(\'Process_STIX_objects\').id}',
                                  IndicatorId_g: '@{guid()}',
                                  ConfidenceScore_d: '@if(equals(items(\'Process_STIX_objects\')?[\'confidence\'], null), 50, items(\'Process_STIX_objects\').confidence)',
                                  SourceFeed_s: '@{items(\'For_each_TAXII_feed\').FeedName_s}',
                                  FirstSeen_t: '@{items(\'Process_STIX_objects\').created}',
                                  LastSeen_t: '@{items(\'Process_STIX_objects\').modified}',
                                  ExpirationDateTime_t: '@{items(\'Process_STIX_objects\').valid_until}',
                                  ThreatType_s: '@{if(contains(items(\'Process_STIX_objects\'), \'labels\'), join(items(\'Process_STIX_objects\').labels, \', \'), \'Unknown\')}',
                                  MalwareFamily_s: '@{if(contains(items(\'Process_STIX_objects\'), \'labels\'), first(items(\'Process_STIX_objects\').labels), \'Unknown\')}',
                                  Description_s: '@{items(\'Process_STIX_objects\').description}',
                                  TLP_s: '@{if(contains(items(\'Process_STIX_objects\').object_marking_refs[0], \'tlp\'), last(split(items(\'Process_STIX_objects\').object_marking_refs[0], \':\' )), \'TLP:AMBER\')}',
                                  Active_b: '@{if(equals(items(\'Process_STIX_objects\')?[\'revoked\'], true), false, true)}'
                                },
                                host: {
                                  connection: {
                                    name: '@parameters(\'$connections\')[\'azureloganalyticsdatacollector\'][\'connectionId\']'
                                  }
                                },
                                method: 'post',
                                path: '/api/logs',
                                queries: {
                                  logType: 'CTI_FileHashIndicators_CL'
                                }
                              }
                            },
                            Send_to_ThreatIntelIndicator_Hash: {
                              runAfter: {
                                Parse_SHA256: [
                                  'Succeeded'
                                ]
                              },
                              type: 'ApiConnection',
                              inputs: {
                                body: {
                                  Type_s: 'file-hash-sha256',
                                  Value_s: '@{outputs(\'Parse_SHA256\')}',
                                  Pattern_s: '@{items(\'Process_STIX_objects\').pattern}',
                                  PatternType_s: '@{items(\'Process_STIX_objects\').pattern_type}',
                                  Name_s: '@{if(contains(items(\'Process_STIX_objects\'), \'name\'), items(\'Process_STIX_objects\').name, \'File Hash Indicator\')}',
                                  Description_s: '@{items(\'Process_STIX_objects\').description}',
                                  Action_s: 'alert',
                                  Confidence_d: '@if(equals(items(\'Process_STIX_objects\')?[\'confidence\'], null), 50, items(\'Process_STIX_objects\').confidence)',
                                  ValidFrom_t: '@{items(\'Process_STIX_objects\').valid_from}',
                                  ValidUntil_t: '@{items(\'Process_STIX_objects\').valid_until}',
                                  CreatedTimeUtc_t: '@{items(\'Process_STIX_objects\').created}',
                                  UpdatedTimeUtc_t: '@{items(\'Process_STIX_objects\').modified}',
                                  Source_s: '@{items(\'For_each_TAXII_feed\').FeedName_s}',
                                  SourceRef_s: '@{items(\'For_each_TAXII_feed\').FeedURL_s}',
                                  KillChainPhases_s: '@{if(contains(items(\'Process_STIX_objects\'), \'kill_chain_phases\'), string(items(\'Process_STIX_objects\').kill_chain_phases), \'\')}',
                                  Labels_s: '@{if(contains(items(\'Process_STIX_objects\'), \'labels\'), join(items(\'Process_STIX_objects\').labels, \', \'), \'\')}',
                                  ThreatType_s: '@{if(contains(items(\'Process_STIX_objects\'), \'labels\'), join(items(\'Process_STIX_objects\').labels, \', \'), \'Unknown\')}',
                                  TLP_s: '@{if(contains(items(\'Process_STIX_objects\').object_marking_refs[0], \'tlp\'), last(split(items(\'Process_STIX_objects\').object_marking_refs[0], \':\' )), \'TLP:AMBER\')}',
                                  Active_b: '@{if(equals(items(\'Process_STIX_objects\')?[\'revoked\'], true), false, true)}',
                                  ObjectId_g: '@{items(\'Process_STIX_objects\').id}',
                                  IndicatorId_g: '@{guid()}'
                                },
                                host: {
                                  connection: {
                                    name: '@parameters(\'$connections\')[\'azureloganalyticsdatacollector\'][\'connectionId\']'
                                  }
                                },
                                method: 'post',
                                path: '/api/logs',
                                queries: {
                                  logType: 'CTI_ThreatIntelIndicator_CL'
                                }
                              }
                            }
                          },
                          runAfter: {
                            Parse_File_Hash_Indicator: [
                              'Succeeded'
                            ]
                          },
                          expression: {
                            contains: [
                              '@outputs(\'Parse_File_Hash_Indicator\')',
                              'sha256'
                            ]
                          },
                          type: 'If'
                        }
                      },
                      runAfter: {
                        'Process_Indicator_-_URL': [
                          'Succeeded'
                        ]
                      },
                      expression: {
                        and: [
                          {
                            equals: [
                              '@items(\'Process_STIX_objects\').type',
                              'indicator'
                            ]
                          },
                          {
                            contains: [
                              '@items(\'Process_STIX_objects\').pattern',
                              'file:hashes'
                            ]
                          }
                        ]
                      },
                      type: 'If'
                    },
                    Store_STIX_Object: {
                      runAfter: {
                        'Process_Indicator_-_File_Hash': [
                          'Succeeded'
                        ]
                      },
                      type: 'ApiConnection',
                      inputs: {
                        body: {
                          ObjectId_g: '@{items(\'Process_STIX_objects\').id}',
                          Type_s: '@{items(\'Process_STIX_objects\').type}',
                          CreatedTimeUtc_t: '@{items(\'Process_STIX_objects\').created}',
                          UpdatedTimeUtc_t: '@{items(\'Process_STIX_objects\').modified}',
                          SourceId_s: '@{items(\'For_each_TAXII_feed\').FeedId_g}',
                          Source_s: '@{items(\'For_each_TAXII_feed\').FeedName_s}',
                          Name_s: '@{if(contains(items(\'Process_STIX_objects\'), \'name\'), items(\'Process_STIX_objects\').name, items(\'Process_STIX_objects\').type)}',
                          Description_s: '@{items(\'Process_STIX_objects\').description}',
                          JsonData_s: '@{string(items(\'Process_STIX_objects\'))}',
                          Relations_s: '@{if(contains(items(\'Process_STIX_objects\'), \'object_refs\'), string(items(\'Process_STIX_objects\').object_refs), \'\')}',
                          TLP_s: '@{if(contains(items(\'Process_STIX_objects\'), \'object_marking_refs\') && contains(first(items(\'Process_STIX_objects\').object_marking_refs), \'tlp\'), last(split(first(items(\'Process_STIX_objects\').object_marking_refs), \':\' )), \'TLP:AMBER\')}',
                          Active_b: '@{if(equals(items(\'Process_STIX_objects\')?[\'revoked\'], true), false, true)}'
                        },
                        host: {
                          connection: {
                            name: '@parameters(\'$connections\')[\'azureloganalyticsdatacollector\'][\'connectionId\']'
                          }
                        },
                        method: 'post',
                        path: '/api/logs',
                        queries: {
                          logType: 'CTI_ThreatIntelObjects_CL'
                        }
                      }
                    }
                  },
                  runAfter: {
                    Parse_STIX_response: [
                      'Succeeded'
                    ]
                  },
                  type: 'Foreach',
                  runtimeConfiguration: {
                    concurrency: {
                      repetitions: 10
                    }
                  }
                },
                Log_feed_update: {
                  runAfter: {
                    Process_STIX_objects: [
                      'Succeeded'
                    ]
                  },
                  type: 'ApiConnection',
                  inputs: {
                    body: {
                      FeedId_g: '@{items(\'For_each_TAXII_feed\').FeedId_g}',
                      FeedName_s: '@{items(\'For_each_TAXII_feed\').FeedName_s}',
                      FeedType_s: 'TAXII',
                      FeedURL_s: '@{items(\'For_each_TAXII_feed\').FeedURL_s}',
                      Status_s: 'Active',
                      LastUpdated_t: '@{utcNow()}',
                      UpdateFrequency_s: '6 hours',
                      IndicatorCount_d: '@{length(body(\'Parse_STIX_response\').objects)}',
                      Description_s: '@{items(\'For_each_TAXII_feed\').Description_s}',
                      Category_s: '@{items(\'For_each_TAXII_feed\').Category_s}',
                      TLP_s: '@{items(\'For_each_TAXII_feed\').TLP_s}',
                      ConfidenceScore_d: '@{items(\'For_each_TAXII_feed\').ConfidenceScore_d}',
                      Active_b: true
                    },
                    host: {
                      connection: {
                        name: '@parameters(\'$connections\')[\'azureloganalyticsdatacollector\'][\'connectionId\']'
                      }
                    },
                    method: 'post',
                    path: '/api/logs',
                    queries: {
                      logType: 'CTI_IntelligenceFeeds_CL'
                    }
                  }
                }
              },
              runAfter: {
                Get_TAXII_feeds: [
                  'Succeeded'
                ]
              },
              type: 'Foreach',
              runtimeConfiguration: {
                concurrency: {
                  repetitions: 1
                }
              }
            },
            Get_TAXII_feeds: {
              runAfter: {},
              type: 'ApiConnection',
              inputs: {
                body: 'CTI_IntelligenceFeeds_CL | where FeedType_s == "TAXII" and Active_b == true',
                host: {
                  connection: {
                    name: '@parameters(\'$connections\')[\'azuremonitorlogs\'][\'connectionId\']'
                  }
                },
                method: 'post',
                path: '/queryData',
                queries: {
                  resourcegroups: '@resourceGroup().name',
                  resourcename: '@{parameters(\'ctiWorkspaceName\')}',
                  resourcetype: 'Log Analytics Workspace',
                  subscriptions: '@{subscription().subscriptionId}',
                  timerange: 'Last 7 days'
                }
              }
            }
          },
          outputs: {}
        },
        parameters: {
          '$connections': {
            value: {
              azureloganalyticsdatacollector: {
                connectionId: '[resourceId(\'Microsoft.Web/connections\', \'azureloganalyticsdatacollector\')]',
                connectionName: 'azureloganalyticsdatacollector',
                id: '[concat(\'/subscriptions/\', subscription().subscriptionId, \'/providers/Microsoft.Web/locations/\', resourceGroup().location, \'/managedApis/azureloganalyticsdatacollector\')]'
              },
              azuremonitorlogs: {
                connectionId: '[resourceId(\'Microsoft.Web/connections\', \'azuremonitorlogs\')]',
                connectionName: 'azuremonitorlogs',
                id: '[concat(\'/subscriptions/\', subscription().subscriptionId, \'/providers/Microsoft.Web/locations/\', resourceGroup().location, \'/managedApis/azuremonitorlogs\')]'
              }
            }
          }
        }
      }
    }

// Defender for Endpoint API connector
resource defenderEndpointConnector 'Microsoft.Logic/workflows@2019-05-01' = {
  name: 'CTI-DefenderXDR-Connector'
  location: location
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
        },
        'tenantId': {
          defaultValue: '[parameters(\'tenantId\')]',
          type: 'String'
        },
        'clientId': {
          defaultValue: '[parameters(\'appClientId\')]',
          type: 'String'
        }
      },
      triggers: {
        Recurrence: {
          recurrence: {
            frequency: 'Hour',
            interval: 1
          },
          type: 'Recurrence'
        }
      },
      actions: {
        Get_Authentication_Token: {
          runAfter: {},
          type: 'Http',
          inputs: {
            method: 'POST',
            uri: 'https://login.microsoftonline.com/@{parameters(\'tenantId\')}/oauth2/token',
            headers: {
              'Content-Type': 'application/x-www-form-urlencoded'
            },
            body: 'grant_type=client_credentials&client_id=@{parameters(\'clientId\')}&client_secret=@{listSecrets(resourceId(\'Microsoft.KeyVault/vaults/secrets\', \'kv-cti-secrets\', \'clientSecret\'), \'2019-09-01\').value}&resource=https://api.securitycenter.microsoft.com'
          }
        },
        Process_High_Confidence_IPs: {
          runAfter: {
            Get_Authentication_Token: [
              'Succeeded'
            ]
          },
          type: 'ApiConnection',
          inputs: {
            body: 'CTI_IPIndicators_CL \n| where ConfidenceScore_d >= 80 and TimeGenerated > ago(1h) and isnotempty(IPAddress_s) \n| where not(IPAddress_s matches regex "^10\\\\.|^172\\\\.(1[6-9]|2[0-9]|3[0-1])\\\\.|^192\\\\.168\\\\.")\n| project IPAddress_s, ConfidenceScore_d, ThreatType_s, Description_s, IndicatorId_g\n| limit 500',
            host: {
              connection: {
                name: '@parameters(\'$connections\')[\'azuremonitorlogs\'][\'connectionId\']'
              }
            },
            method: 'post',
            path: '/queryData',
            queries: {
              resourcegroups: '@resourceGroup().name',
              resourcename: '@{parameters(\'ctiWorkspaceName\')}',
              resourcetype: 'Log Analytics Workspace',
              subscriptions: '@{subscription().subscriptionId}',
              timerange: 'Last hour'
            }
          }
        },
        For_Each_IP_Indicator: {
          foreach: '@body(\'Process_High_Confidence_IPs\').tables[0].rows',
          actions: {
            Submit_IP_Indicator: {
              runAfter: {},
              type: 'Http',
              inputs: {
                method: 'POST',
                uri: 'https://api.securitycenter.microsoft.com/api/indicators',
                headers: {
                  'Content-Type': 'application/json',
                  Authorization: 'Bearer @{body(\'Get_Authentication_Token\').access_token}'
                },
                body: {
                  indicatorValue: '@{item()[0]}', // IPAddress_s
                  indicatorType: 'IpAddress',
                  action: 'Block',
                  title: 'CTI Auto-Block: @{item()[2]}', // ThreatType_s
                  description: '@{if(equals(item()[3], \'\'), concat(\'High confidence malicious IP from threat feed. Confidence: \', item()[1]), item()[3])}',
                  severity: 'High',
                  recommendedActions: 'Block this IP address',
                  rbacGroupNames: [],
                  generateAlert: true
                },
                retryPolicy: {
                  type: 'fixed',
                  count: 3,
                  interval: 'PT30S'
                }
              }
            },
            Log_Transaction: {
              runAfter: {
                Submit_IP_Indicator: [
                  'Succeeded'
                ]
              },
              type: 'ApiConnection',
              inputs: {
                body: {
                  IndicatorType_s: 'IP',
                  IndicatorValue_s: '@{item()[0]}',
                  Action_s: 'Block',
                  TargetSystem_s: 'Microsoft Defender XDR',
                  Status_s: 'Success',
                  Timestamp_t: '@{utcNow()}',
                  ActionId_g: '@{guid()}',
                  CorrelationId_g: '@{guid()}',
                  IndicatorId_g: '@{item()[4]}',
                  RunbookName_s: 'CTI-DefenderXDR-Connector',
                  TriggerSource_s: 'Scheduled'
                },
                host: {
                  connection: {
                    name: '@parameters(\'$connections\')[\'azureloganalyticsdatacollector\'][\'connectionId\']'
                  }
                },
                method: 'post',
                path: '/api/logs',
                queries: {
                  logType: 'CTI_TransactionLog_CL'
                }
              }
            },
            Handle_Error: {
              actions: {
                Log_Error: {
                  runAfter: {},
                  type: 'ApiConnection',
                  inputs: {
                    body: {
                      IndicatorType_s: 'IP',
                      IndicatorValue_s: '@{item()[0]}',
                      Action_s: 'Block',
                      TargetSystem_s: 'Microsoft Defender XDR',
                      Status_s: 'Failed',
                      ErrorMessage_s: '@{outputs(\'Submit_IP_Indicator\')[\'body\']}',
                      Timestamp_t: '@{utcNow()}',
                      ActionId_g: '@{guid()}',
                      CorrelationId_g: '@{guid()}',
                      IndicatorId_g: '@{item()[4]}',
                      RunbookName_s: 'CTI-DefenderXDR-Connector',
                      TriggerSource_s: 'Scheduled'
                    },
                    host: {
                      connection: {
                        name: '@parameters(\'$connections\')[\'azureloganalyticsdatacollector\'][\'connectionId\']'
                      }
                    },
                    method: 'post',
                    path: '/api/logs',
                    queries: {
                      logType: 'CTI_TransactionLog_CL'
                    }
                  }
                }
              },
              runAfter: {
                Submit_IP_Indicator: [
                  'Failed'
                ]
              },
              type: 'Scope'
            }
          },
          runAfter: {
            Process_High_Confidence_IPs: [
              'Succeeded'
            ]
          },
          type: 'Foreach',
          runtimeConfiguration: {
            concurrency: {
              repetitions: 10
            }
          }
        },
        Process_High_Confidence_FileHashes: {
          runAfter: {
            For_Each_IP_Indicator: [
              'Succeeded'
            ]
          },
          type: 'ApiConnection',
          inputs: {
            body: 'CTI_FileHashIndicators_CL \n| where ConfidenceScore_d >= 80 and TimeGenerated > ago(1h) and isnotempty(SHA256_s)\n| project SHA256_s, ConfidenceScore_d, ThreatType_s, MalwareFamily_s, Description_s, IndicatorId_g\n| limit 500',
            host: {
              connection: {
                name: '@parameters(\'$connections\')[\'azuremonitorlogs\'][\'connectionId\']'
              }
            },
            method: 'post',
            path: '/queryData',
            queries: {
              resourcegroups: '@resourceGroup().name',
              resourcename: '@{parameters(\'ctiWorkspaceName\')}',
              resourcetype: 'Log Analytics Workspace',
              subscriptions: '@{subscription().subscriptionId}',
              timerange: 'Last hour'
            }
          }
        },
        For_Each_FileHash_Indicator: {
          foreach: '@body(\'Process_High_Confidence_FileHashes\').tables[0].rows',
          actions: {
            Submit_FileHash_Indicator: {
              runAfter: {},
              type: 'Http',
              inputs: {
                method: 'POST',
                uri: 'https://api.securitycenter.microsoft.com/api/indicators',
                headers: {
                  'Content-Type': 'application/json',
                  Authorization: 'Bearer @{body(\'Get_Authentication_Token\').access_token}'
                },
                body: {
                  indicatorValue: '@{item()[0]}', // SHA256_s
                  indicatorType: 'FileSha256',
                  action: 'Block',
                  title: 'CTI Auto-Block: @{if(not(empty(item()[3])), concat(item()[3], \' malware\'), concat(item()[2], \' threat\'))}',
                  description: '@{if(equals(item()[4], \'\'), concat(\'High confidence malicious file hash from threat feed. Confidence: \', item()[1]), item()[4])}',
                  severity: 'High',
                  recommendedActions: 'Block this file hash',
                  rbacGroupNames: [],
                  generateAlert: true
                },
                retryPolicy: {
                  type: 'fixed',
                  count: 3,
                  interval: 'PT30S'
                }
              }
            },
            Log_Transaction_FileHash: {
              runAfter: {
                Submit_FileHash_Indicator: [
                  'Succeeded'
                ]
              },
              type: 'ApiConnection',
              inputs: {
                body: {
                  IndicatorType_s: 'FileHash',
                  IndicatorValue_s: '@{item()[0]}',
                  Action_s: 'Block',
                  TargetSystem_s: 'Microsoft Defender XDR',
                  Status_s: 'Success',
                  Timestamp_t: '@{utcNow()}',
                  ActionId_g: '@{guid()}',
                  CorrelationId_g: '@{guid()}',
                  IndicatorId_g: '@{item()[5]}',
                  RunbookName_s: 'CTI-DefenderXDR-Connector',
                  TriggerSource_s: 'Scheduled'
                },
                host: {
                  connection: {
                    name: '@parameters(\'$connections\')[\'azureloganalyticsdatacollector\'][\'connectionId\']'
                  }
                },
                method: 'post',
                path: '/api/logs',
                queries: {
                  logType: 'CTI_TransactionLog_CL'
                }
              }
            },
            Handle_FileHash_Error: {
              actions: {
                Log_Error_FileHash: {
                  runAfter: {},
                  type: 'ApiConnection',
                  inputs: {
                    body: {
                      IndicatorType_s: 'FileHash',
                      IndicatorValue_s: '@{item()[0]}',
                      Action_s: 'Block',
                      TargetSystem_s: 'Microsoft Defender XDR',
                      Status_s: 'Failed',
                      ErrorMessage_s: '@{outputs(\'Submit_FileHash_Indicator\')[\'body\']}',
                      Timestamp_t: '@{utcNow()}',
                      ActionId_g: '@{guid()}',
                      CorrelationId_g: '@{guid()}',
                      IndicatorId_g: '@{item()[5]}',
                      RunbookName_s: 'CTI-DefenderXDR-Connector',
                      TriggerSource_s: 'Scheduled'
                    },
                    host: {
                      connection: {
                        name: '@parameters(\'$connections\')[\'azureloganalyticsdatacollector\'][\'connectionId\']'
                      }
                    },
                    method: 'post',
                    path: '/api/logs',
                    queries: {
                      logType: 'CTI_TransactionLog_CL'
                    }
                  }
                }
              },
              runAfter: {
                Submit_FileHash_Indicator: [
                  'Failed'
                ]
              },
              type: 'Scope'
            }
          },
          runAfter: {
            Process_High_Confidence_FileHashes: [
              'Succeeded'
            ]
          },
          type: 'Foreach',
          runtimeConfiguration: {
            concurrency: {
              repetitions: 10
            }
          }
        }
      },
      outputs: {}
    },
    parameters: {
      '$connections': {
        value: {
          azureloganalyticsdatacollector: {
            connectionId: '[resourceId(\'Microsoft.Web/connections\', \'azureloganalyticsdatacollector\')]',
            connectionName: 'azureloganalyticsdatacollector',
            id: '[concat(\'/subscriptions/\', subscription().subscriptionId, \'/providers/Microsoft.Web/locations/\', resourceGroup().location, \'/managedApis/azureloganalyticsdatacollector\')]'
          },
          azuremonitorlogs: {
            connectionId: '[resourceId(\'Microsoft.Web/connections\', \'azuremonitorlogs\')]',
            connectionName: 'azuremonitorlogs',
            id: '[concat(\'/subscriptions/\', subscription().subscriptionId, \'/providers/Microsoft.Web/locations/\', resourceGroup().location, \'/managedApis/azuremonitorlogs\')]'
          }
        }
      }
    }
  }
}

// Microsoft Defender Threat Intelligence connector
resource mdtiConnectorLogicApp 'Microsoft.Logic/workflows@2019-05-01' = if(enableMDTI) {
  name: 'CTI-MDTI-Connector'
  location: location
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
          defaultValue: {},
          type: 'Object'
        },
        'tenantId': {
          defaultValue: '[parameters(\'tenantId\')]',
          type: 'String'
        },
        'clientId': {
          defaultValue: '[parameters(\'appClientId\')]',
          type: 'String'
        }
      },
      triggers: {
        Recurrence: {
          recurrence: {
            frequency: 'Day',
            interval: 1
          },
          type: 'Recurrence'
        }
      },
      actions: {
        Get_Authentication_Token: {
          runAfter: {},
          type: 'Http',
          inputs: {
            method: 'POST',
            uri: 'https://login.microsoftonline.com/@{parameters(\'tenantId\')}/oauth2/token',
            headers: {
              'Content-Type': 'application/x-www-form-urlencoded'
            },
            body: 'grant_type=client_credentials&client_id=@{parameters(\'clientId\')}&client_secret=@{listSecrets(resourceId(\'Microsoft.KeyVault/vaults/secrets\', \'kv-cti-secrets\', \'clientSecret\'), \'2019-09-01\').value}&resource=https://api.securitycenter.windows.com/'
          }
        },
        Get_MDTI_Indicators: {
          runAfter: {
            Get_Authentication_Token: [
              'Succeeded'
            ]
          },
          type: 'Http',
          inputs: {
            method: 'GET',
            uri: 'https://api.securitycenter.windows.com/api/indicators?$filter=confidenceLevel ge 50&$top=100',
            headers: {
              Accept: 'application/json',
              Authorization: 'Bearer @{body(\'Get_Authentication_Token\').access_token}'
            }
          }
        },
        Parse_MDTI_Indicators: {
          runAfter: {
            Get_MDTI_Indicators: [
              'Succeeded'
            ]
          },
          type: 'ParseJson',
          inputs: {
            content: '@body(\'Get_MDTI_Indicators\')',
            schema: {
              type: 'object',
              properties: {
                value: {
                  type: 'array',
                  items: {
                    type: 'object',
                    properties: {
                      indicatorValue: {
                        type: 'string'
                      },
                      indicatorType: {
                        type: 'string'
                      },
                      title: {
                        type: 'string'
                      },
                      description: {
                        type: 'string'
                      },
                      expirationTime: {
                        type: 'string'
                      },
                      confidence: {
                        type: 'integer'
                      }
                    }
                  }
                }
              }
            }
          }
        },
        Process_MDTI_Indicators: {
          foreach: '@body(\'Parse_MDTI_Indicators\').value',
          actions: {
            Determine_Indicator_Type: {
              actions: {
                Process_IP_Indicator: {
                  actions: {
                    Send_IP_to_Log_Analytics: {
                      runAfter: {},
                      type: 'ApiConnection',
                      inputs: {
                        body: {
                          IPAddress_s: '@{items(\'Process_MDTI_Indicators\').indicatorValue}',
                          ObjectId_g: '@{guid()}',
                          IndicatorId_g: '@{guid()}',
                          ConfidenceScore_d: '@{items(\'Process_MDTI_Indicators\').confidence}',
                          SourceFeed_s: 'Microsoft Defender Threat Intelligence',
                          FirstSeen_t: '@{utcNow()}',
                          LastSeen_t: '@{utcNow()}',
                          ExpirationDateTime_t: '@{items(\'Process_MDTI_Indicators\').expirationTime}',
                          ThreatType_s: '@{if(contains(items(\'Process_MDTI_Indicators\'), \'title\'), items(\'Process_MDTI_Indicators\').title, \'Unknown\')}',
                          Description_s: '@{items(\'Process_MDTI_Indicators\').description}',
                          TLP_s: 'TLP:AMBER',
                          Active_b: true
                        },
                        host: {
                          connection: {
                            name: '@parameters(\'$connections\')[\'azureloganalyticsdatacollector\'][\'connectionId\']'
                          }
                        },
                        method: 'post',
                        path: '/api/logs',
                        queries: {
                          logType: 'CTI_IPIndicators_CL'
                        }
                      }
                    },
                    Send_to_ThreatIntelIndicator_IP: {
                      runAfter: {
                        Send_IP_to_Log_Analytics: [
                          'Succeeded'
                        ]
                      },
                      type: 'ApiConnection',
                      inputs: {
                        body: {
                          Type_s: 'ipv4-addr',
                          Value_s: '@{items(\'Process_MDTI_Indicators\').indicatorValue}',
                          Pattern_s: '',
                          PatternType_s: 'stix',
                          Name_s: '@{if(contains(items(\'Process_MDTI_Indicators\'), \'title\'), items(\'Process_MDTI_Indicators\').title, \'IP Indicator\')}',
                          Description_s: '@{items(\'Process_MDTI_Indicators\').description}',
                          Action_s: 'alert',
                          Confidence_d: '@{items(\'Process_MDTI_Indicators\').confidence}',
                          ValidFrom_t: '@{utcNow()}',
                          ValidUntil_t: '@{items(\'Process_MDTI_Indicators\').expirationTime}',
                          CreatedTimeUtc_t: '@{utcNow()}',
                          UpdatedTimeUtc_t: '@{utcNow()}',
                          Source_s: 'Microsoft Defender Threat Intelligence',
                          SourceRef_s: 'https://ti.defender.microsoft.com/',
                          KillChainPhases_s: '',
                          Labels_s: '@{if(contains(items(\'Process_MDTI_Indicators\'), \'title\'), items(\'Process_MDTI_Indicators\').title, \'\')}',
                          ThreatType_s: '@{if(contains(items(\'Process_MDTI_Indicators\'), \'title\'), items(\'Process_MDTI_Indicators\').title, \'Unknown\')}',
                          TLP_s: 'TLP:AMBER',
                          Active_b: true,
                          ObjectId_g: '@{guid()}',
                          IndicatorId_g: '@{guid()}'
                        },
                        host: {
                          connection: {
                            name: '@parameters(\'$connections\')[\'azureloganalyticsdatacollector\'][\'connectionId\']'
                          }
                        },
                        method: 'post',
                        path: '/api/logs',
                        queries: {
                          logType: 'CTI_ThreatIntelIndicator_CL'
                        }
                      }
                    }
                  },
                  runAfter: {},
                  expression: {
                    equals: [
                      '@items(\'Process_MDTI_Indicators\').indicatorType',
                      'IpAddress'
                    ]
                  },
                  type: 'If'
                },
                Process_Domain_Indicator: {
                  actions: {
                    Send_Domain_to_Log_Analytics: {
                      runAfter: {},
                      type: 'ApiConnection',
                      inputs: {
                        body: {
                          Domain_s: '@{items(\'Process_MDTI_Indicators\').indicatorValue}',
                          ObjectId_g: '@{guid()}',
                          IndicatorId_g: '@{guid()}',
                          ConfidenceScore_d: '@{items(\'Process_MDTI_Indicators\').confidence}',
                          SourceFeed_s: 'Microsoft Defender Threat Intelligence',
                          FirstSeen_t: '@{utcNow()}',
                          LastSeen_t: '@{utcNow()}',
                          ExpirationDateTime_t: '@{items(\'Process_MDTI_Indicators\').expirationTime}',
                          ThreatType_s: '@{if(contains(items(\'Process_MDTI_Indicators\'), \'title\'), items(\'Process_MDTI_Indicators\').title, \'Unknown\')}',
                          Description_s: '@{items(\'Process_MDTI_Indicators\').description}',
                          TLP_s: 'TLP:AMBER',
                          Active_b: true
                        },
                        host: {
                          connection: {
                            name: '@parameters(\'$connections\')[\'azureloganalyticsdatacollector\'][\'connectionId\']'
                          }
                        },
                        method: 'post',
                        path: '/api/logs',
                        queries: {
                          logType: 'CTI_DomainIndicators_CL'
                        }
                      }
                    }
                  },
                  runAfter: {
                    Process_IP_Indicator: [
                      'Succeeded'
                    ]
                  },
                  expression: {
                    equals: [
                      '@items(\'Process_MDTI_Indicators\').indicatorType',
                      'DomainName'
                    ]
                  },
                  type: 'If'
                },
                Process_FileHash_Indicator: {
                  actions: {
                    Send_FileHash_to_Log_Analytics: {
                      runAfter: {},
                      type: 'ApiConnection',
                      inputs: {
                        body: {
                          SHA256_s: '@{items(\'Process_MDTI_Indicators\').indicatorValue}',
                          ObjectId_g: '@{guid()}',
                          IndicatorId_g: '@{guid()}',
                          ConfidenceScore_d: '@{items(\'Process_MDTI_Indicators\').confidence}',
                          SourceFeed_s: 'Microsoft Defender Threat Intelligence',
                          FirstSeen_t: '@{utcNow()}',
                          LastSeen_t: '@{utcNow()}',
                          ExpirationDateTime_t: '@{items(\'Process_MDTI_Indicators\').expirationTime}',
                          ThreatType_s: '@{if(contains(items(\'Process_MDTI_Indicators\'), \'title\'), items(\'Process_MDTI_Indicators\').title, \'Unknown\')}',
                          MalwareFamily_s: '@{if(contains(items(\'Process_MDTI_Indicators\'), \'title\'), items(\'Process_MDTI_Indicators\').title, \'Unknown\')}',
                          Description_s: '@{items(\'Process_MDTI_Indicators\').description}',
                          TLP_s: 'TLP:AMBER',
                          Active_b: true
                        },
                        host: {
                          connection: {
                            name: '@parameters(\'$connections\')[\'azureloganalyticsdatacollector\'][\'connectionId\']'
                          }
                        },
                        method: 'post',
                        path: '/api/logs',
                        queries: {
                          logType: 'CTI_FileHashIndicators_CL'
                        }
                      }
                    }
                  },
                  runAfter: {
                    Process_Domain_Indicator: [
                      'Succeeded'
                    ]
                  },
                  expression: {
                    or: [
                      {
                        equals: [
                          '@items(\'Process_MDTI_Indicators\').indicatorType',
                          'FileSha256'
                        ]
                      },
                      {
                        equals: [
                          '@items(\'Process_MDTI_Indicators\').indicatorType',
                          'FileSha1'
                        ]
                      },
                      {
                        equals: [
                          '@items(\'Process_MDTI_Indicators\').indicatorType',
                          'FileMd5'
                        ]
                      }
                    ]
                  },
                  type: 'If'
                },
                Process_URL_Indicator: {
                  actions: {
                    Send_URL_to_Log_Analytics: {
                      runAfter: {},
                      type: 'ApiConnection',
                      inputs: {
                        body: {
                          URL_s: '@{items(\'Process_MDTI_Indicators\').indicatorValue}',
                          ObjectId_g: '@{guid()}',
                          IndicatorId_g: '@{guid()}',
                          ConfidenceScore_d: '@{items(\'Process_MDTI_Indicators\').confidence}',
                          SourceFeed_s: 'Microsoft Defender Threat Intelligence',
                          FirstSeen_t: '@{utcNow()}',
                          LastSeen_t: '@{utcNow()}',
                          ExpirationDateTime_t: '@{items(\'Process_MDTI_Indicators\').expirationTime}',
                          ThreatType_s: '@{if(contains(items(\'Process_MDTI_Indicators\'), \'title\'), items(\'Process_MDTI_Indicators\').title, \'Unknown\')}',
                          Description_s: '@{items(\'Process_MDTI_Indicators\').description}',
                          TLP_s: 'TLP:AMBER',
                          Active_b: true
                        },
                        host: {
                          connection: {
                            name: '@parameters(\'$connections\')[\'azureloganalyticsdatacollector\'][\'connectionId\']'
                          }
                        },
                        method: 'post',
                        path: '/api/logs',
                        queries: {
                          logType: 'CTI_URLIndicators_CL'
                        }
                      }
                    }
                  },
                  runAfter: {
                    Process_FileHash_Indicator: [
                      'Succeeded'
                    ]
                  },
                  expression: {
                    equals: [
                      '@items(\'Process_MDTI_Indicators\').indicatorType',
                      'Url'
                    ]
                  },
                  type: 'If'
                }
              },
              runAfter: {},
              type: 'Scope'
            }
          },
          runAfter: {
            Parse_MDTI_Indicators: [
              'Succeeded'
            ]
          },
          type: 'Foreach',
          runtimeConfiguration: {
            concurrency: {
              repetitions: 20
            }
          }
        },
        Log_Feed_Update: {
          runAfter: {
            Process_MDTI_Indicators: [
              'Succeeded'
            ]
          },
          type: 'ApiConnection',
          inputs: {
            body: {
              FeedId_g: 'MDTI',
              FeedName_s: 'Microsoft Defender Threat Intelligence',
              FeedType_s: 'API',
              FeedURL_s: 'https://ti.defender.microsoft.com/',
              Status_s: 'Active',
              LastUpdated_t: '@{utcNow()}',
              UpdateFrequency_s: '24 hours',
              IndicatorCount_d: '@{length(body(\'Parse_MDTI_Indicators\').value)}',
              Description_s: 'Microsoft Defender Threat Intelligence Feed',
              Category_s: 'Microsoft',
              TLP_s: 'TLP:AMBER',
              ConfidenceScore_d: 80,
              Active_b: true
            },
            host: {
              connection: {
                name: '@parameters(\'$connections\')[\'azureloganalyticsdatacollector\'][\'connectionId\']'
              }
            },
            method: 'post',
            path: '/api/logs',
            queries: {
              logType: 'CTI_IntelligenceFeeds_CL'
            }
          }
        }
      },
      outputs: {}
    },
    parameters: {
      '$connections': {
        value: {
          azureloganalyticsdatacollector: {
            connectionId: '[resourceId(\'Microsoft.Web/connections\', \'azureloganalyticsdatacollector\')]',
            connectionName: 'azureloganalyticsdatacollector',
            id: '[concat(\'/subscriptions/\', subscription().subscriptionId, \'/providers/Microsoft.Web/locations/\', resourceGroup().location, \'/managedApis/azureloganalyticsdatacollector\')]'
          }
        }
      }
    }
  }
}

// Microsoft Entra ID Named Locations Connector
resource entraIDConnectorLogicApp 'Microsoft.Logic/workflows@2019-05-01' = {
  name: 'CTI-EntraID-Connector'
  location: location
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
          defaultValue: {},
          type: 'Object'
        },
        'tenantId': {
          defaultValue: '[parameters(\'tenantId\')]',
          type: 'String'
        },
        'clientId': {
          defaultValue: '[parameters(\'appClientId\')]',
          type: 'String'
        },
        'graphApiUrl': {
          defaultValue: '[parameters(\'graphApiUrl\')]',
          type: 'String'
        }
      },
      triggers: {
        Recurrence: {
          recurrence: {
            frequency: 'Hour',
            interval: 3
          },
          type: 'Recurrence'
        }
      },
      actions: {
        Get_Authentication_Token: {
          runAfter: {},
          type: 'Http',
          inputs: {
            method: 'POST',
            uri: 'https://login.microsoftonline.com/@{parameters(\'tenantId\')}/oauth2/token',
            headers: {
              'Content-Type': 'application/x-www-form-urlencoded'
            },
            body: 'grant_type=client_credentials&client_id=@{parameters(\'clientId\')}&client_secret=@{listSecrets(resourceId(\'Microsoft.KeyVault/vaults/secrets\', \'kv-cti-secrets\', \'clientSecret\'), \'2019-09-01\').value}&resource=https://graph.microsoft.com'
          }
        },
        Get_Named_Locations: {
          runAfter: {
            Get_Authentication_Token: [
              'Succeeded'
            ]
          },
          type: 'Http',
          inputs: {
            method: 'GET',
            uri: '@{parameters(\'graphApiUrl\')}/v1.0/identity/conditionalAccess/namedLocations',
            headers: {
              Authorization: 'Bearer @{body(\'Get_Authentication_Token\').access_token}'
            }
          }
        },
        Parse_Named_Locations: {
          runAfter: {
            Get_Named_Locations: [
              'Succeeded'
            ]
          },
          type: 'ParseJson',
          inputs: {
            content: '@body(\'Get_Named_Locations\')',
            schema: {
              type: 'object',
              properties: {
                '@odata.context': {
                  type: 'string'
                },
                'value': {
                  type: 'array',
                  items: {
                    type: 'object',
                    properties: {
                      '@odata.type': {
                        type: 'string'
                      },
                      id: {
                        type: 'string'
                      },
                      displayName: {
                        type: 'string'
                      },
                      ipRanges: {
                        type: 'array',
                        items: {
                          type: 'object',
                          properties: {
                            '@odata.type': {
                              type: 'string'
                            },
                            cidrAddress: {
                              type: 'string'
                            }
                          }
                        }
                      },
                      isTrusted: {
                        type: 'boolean'
                      },
                      createdDateTime: {
                        type: 'string'
                      },
                      modifiedDateTime: {
                        type: 'string'
                      }
                    }
                  }
                }
              }
            }
          }
        },
        Find_CTI_Blocked_IP_Location: {
          runAfter: {
            Parse_Named_Locations: [
              'Succeeded'
            ]
          },
          type: 'Compose',
          inputs: '@first(filter(body(\'Parse_Named_Locations\').value, item => equals(item.displayName, \'CTI-Malicious-IPs\')))'
        },
        Check_If_CTI_Location_Exists: {
          actions: {
            Get_High_Confidence_IPs: {
              runAfter: {},
              type: 'ApiConnection',
              inputs: {
                body: 'CTI_IPIndicators_CL\n| where ConfidenceScore_d >= 90 and TimeGenerated > ago(12h)\n| where not(IPAddress_s matches regex "^10\\\\.|^172\\\\.(1[6-9]|2[0-9]|3[0-1])\\\\.|^192\\\\.168\\\\.")\n| project IPAddress_s, ConfidenceScore_d, ThreatType_s\n| limit 100',
                host: {
                  connection: {
                    name: '@parameters(\'$connections\')[\'azuremonitorlogs\'][\'connectionId\']'
                  }
                },
                method: 'post',
                path: '/queryData',
                queries: {
                  resourcegroups: '@resourceGroup().name',
                  resourcename: '@{parameters(\'ctiWorkspaceName\')}',
                  resourcetype: 'Log Analytics Workspace',
                  subscriptions: '@{subscription().subscriptionId}',
                  timerange: 'Last 12 hours'
                }
              }
            },
            Update_Named_Location: {
              runAfter: {
                Get_High_Confidence_IPs: [
                  'Succeeded'
                ]
              },
              type: 'Http',
              inputs: {
                method: 'PATCH',
                uri: '@{parameters(\'graphApiUrl\')}/v1.0/identity/conditionalAccess/namedLocations/@{outputs(\'Find_CTI_Blocked_IP_Location\').id}',
                headers: {
                  'Content-Type': 'application/json',
                  Authorization: 'Bearer @{body(\'Get_Authentication_Token\').access_token}'
                },
                body: {
                  '@odata.type': '#microsoft.graph.ipNamedLocation',
                  displayName: 'CTI-Malicious-IPs',
                  isTrusted: false,
                  ipRanges: '@{union(outputs(\'Find_CTI_Blocked_IP_Location\').ipRanges, body(\'Create_IP_Range_Array\'))}'
                }
              }
            },
            Create_IP_Range_Array: {
              runAfter: {
                Get_High_Confidence_IPs: [
                  'Succeeded'
                ]
              },
              type: 'Select',
              inputs: {
                from: '@body(\'Get_High_Confidence_IPs\').tables[0].rows',
                select: {
                  '@odata.type': '#microsoft.graph.ipRange',
                  cidrAddress: '@{concat(item[0], \'/32\')}'
                }
              }
            },
            Log_Transaction_Update: {
              runAfter: {
                Update_Named_Location: [
                  'Succeeded'
                ]
              },
              type: 'ApiConnection',
              inputs: {
                body: {
                  IndicatorType_s: 'IP',
                  IndicatorValue_s: 'Multiple',
                  Action_s: 'Block',
                  TargetSystem_s: 'Microsoft Entra ID',
                  Status_s: 'Success',
                  Timestamp_t: '@{utcNow()}',
                  ActionId_g: '@{guid()}',
                  CorrelationId_g: '@{guid()}',
                  IndicatorId_g: 'Multiple',
                  RunbookName_s: 'CTI-EntraID-Connector',
                  TriggerSource_s: 'Scheduled'
                },
                host: {
                  connection: {
                    name: '@parameters(\'$connections\')[\'azureloganalyticsdatacollector\'][\'connectionId\']'
                  }
                },
                method: 'post',
                path: '/api/logs',
                queries: {
                  logType: 'CTI_TransactionLog_CL'
                }
              }
            }
          },
          runAfter: {
            Find_CTI_Blocked_IP_Location: [
              'Succeeded'
            ]
          },
          expression: {
            not: {
              equals: [
                '@outputs(\'Find_CTI_Blocked_IP_Location\')',
                '@null'
              ]
            }
          },
          type: 'If',
          else: {
            actions: {
              Get_High_Confidence_IPs_For_Create: {
                runAfter: {},
                type: 'ApiConnection',
                inputs: {
                  body: 'CTI_IPIndicators_CL\n| where ConfidenceScore_d >= 90 and TimeGenerated > ago(12h)\n| where not(IPAddress_s matches regex "^10\\\\.|^172\\\\.(1[6-9]|2[0-9]|3[0-1])\\\\.|^192\\\\.168\\\\.")\n| project IPAddress_s, ConfidenceScore_d, ThreatType_s\n| limit 100',
                  host: {
                    connection: {
                      name: '@parameters(\'$connections\')[\'azuremonitorlogs\'][\'connectionId\']'
                    }
                  },
                  method: 'post',
                  path: '/queryData',
                  queries: {
                    resourcegroups: '@resourceGroup().name',
                    resourcename: '@{parameters(\'ctiWorkspaceName\')}',
                    resourcetype: 'Log Analytics Workspace',
                    subscriptions: '@{subscription().subscriptionId}',
                    timerange: 'Last 12 hours'
                  }
                }
              },
              Create_IP_Range_Array_For_Create: {
                runAfter: {
                  Get_High_Confidence_IPs_For_Create: [
                    'Succeeded'
                  ]
                },
                type: 'Select',
                inputs: {
                  from: '@body(\'Get_High_Confidence_IPs_For_Create\').tables[0].rows',
                  select: {
                    '@odata.type': '#microsoft.graph.ipRange',
                    cidrAddress: '@{concat(item[0], \'/32\')}'
                  }
                }
              },
              Create_Named_Location: {
                runAfter: {
                  Create_IP_Range_Array_For_Create: [
                    'Succeeded'
                  ]
                },
                type: 'Http',
                inputs: {
                  method: 'POST',
                  uri: '@{parameters(\'graphApiUrl\')}/v1.0/identity/conditionalAccess/namedLocations',
                  headers: {
                    'Content-Type': 'application/json',
                    Authorization: 'Bearer @{body(\'Get_Authentication_Token\').access_token}'
                  },
                  body: {
                    '@odata.type': '#microsoft.graph.ipNamedLocation',
                    displayName: 'CTI-Malicious-IPs',
                    isTrusted: false,
                    ipRanges: '@body(\'Create_IP_Range_Array_For_Create\')'
                  }
                }
              },
              Log_Transaction_Create: {
                runAfter: {
                  Create_Named_Location: [
                    'Succeeded'
                  ]
                },
                type: 'ApiConnection',
                inputs: {
                  body: {
                    IndicatorType_s: 'IP',
                    IndicatorValue_s: 'Multiple',
                    Action_s: 'Block',
                    TargetSystem_s: 'Microsoft Entra ID',
                    Status_s: 'Success',
                    Timestamp_t: '@{utcNow()}',
                    ActionId_g: '@{guid()}',
                    CorrelationId_g: '@{guid()}',
                    IndicatorId_g: 'Multiple',
                    RunbookName_s: 'CTI-EntraID-Connector',
                    TriggerSource_s: 'Scheduled'
                  },
                  host: {
                    connection: {
                      name: '@parameters(\'$connections\')[\'azureloganalyticsdatacollector\'][\'connectionId\']'
                    }
                  },
                  method: 'post',
                  path: '/api/logs',
                  queries: {
                    logType: 'CTI_TransactionLog_CL'
                  }
                }
              }
            }
          }
        }
      },
      outputs: {}
    },
    parameters: {
      '$connections': {
        value: {
          azureloganalyticsdatacollector: {
            connectionId: '[resourceId(\'Microsoft.Web/connections\', \'azureloganalyticsdatacollector\')]',
            connectionName: 'azureloganalyticsdatacollector',
            id: '[concat(\'/subscriptions/\', subscription().subscriptionId, \'/providers/Microsoft.Web/locations/\', resourceGroup().location, \'/managedApis/azureloganalyticsdatacollector\')]'
          },
          azuremonitorlogs: {
            connectionId: '[resourceId(\'Microsoft.Web/connections\', \'azuremonitorlogs\')]',
            connectionName: 'azuremonitorlogs',
            id: '[concat(\'/subscriptions/\', subscription().subscriptionId, \'/providers/Microsoft.Web/locations/\', resourceGroup().location, \'/managedApis/azuremonitorlogs\')]'
          }
        }
      }
    }
  }
}

// Exchange Online Tenant Block List Connector
resource exoConnectorLogicApp 'Microsoft.Logic/workflows@2019-05-01' = {
  name: 'CTI-ExchangeOnline-Connector'
  location: location
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
          defaultValue: {},
          type: 'Object'
        },
        'tenantId': {
          defaultValue: '[parameters(\'tenantId\')]',
          type: 'String'
        },
        'clientId': {
          defaultValue: '[parameters(\'appClientId\')]',
          type: 'String'
        }
      },
      triggers: {
        Recurrence: {
          recurrence: {
            frequency: 'Hour',
            interval: 4
          },
          type: 'Recurrence'
        }
      },
      actions: {
        Get_Authentication_Token: {
          runAfter: {},
          type: 'Http',
          inputs: {
            method: 'POST',
            uri: 'https://login.microsoftonline.com/@{parameters(\'tenantId\')}/oauth2/token',
            headers: {
              'Content-Type': 'application/x-www-form-urlencoded'
            },
            body: 'grant_type=client_credentials&client_id=@{parameters(\'clientId\')}&client_secret=@{listSecrets(resourceId(\'Microsoft.KeyVault/vaults/secrets\', \'kv-cti-secrets\'), \'clientSecret\'), \'2019-09-01\').value}&resource=https://outlook.office365.com/'
          }
        },
        Get_High_Confidence_Domains_URLs: {
          runAfter: {
            Get_Authentication_Token: [
              'Succeeded'
            ]
          },
          type: 'ApiConnection',
          inputs: {
            body: 'union \n(CTI_DomainIndicators_CL\n| where ConfidenceScore_d >= 85 and TimeGenerated > ago(12h) and isnotempty(Domain_s)\n| extend Value = Domain_s, Type = \'Domain\', Description = Description_s, IndicatorId = IndicatorId_g\n| project Value, Type, Description, IndicatorId),\n(CTI_URLIndicators_CL\n| where ConfidenceScore_d >= 90 and TimeGenerated > ago(12h) and isnotempty(URL_s)\n| extend Value = URL_s, Type = \'URL\', Description = Description_s, IndicatorId = IndicatorId_g\n| project Value, Type, Description, IndicatorId)\n| limit 100',
            host: {
              connection: {
                name: '@parameters(\'$connections\')[\'azuremonitorlogs\'][\'connectionId\']'
              }
            },
            method: 'post',
            path: '/queryData',
            queries: {
              resourcegroups: '@resourceGroup().name',
              resourcename: '@{parameters(\'ctiWorkspaceName\')}',
              resourcetype: 'Log Analytics Workspace',
              subscriptions: '@{subscription().subscriptionId}',
              timerange: 'Last 12 hours'
            }
          }
        },
        Process_Indicators: {
          foreach: '@body(\'Get_High_Confidence_Domains_URLs\').tables[0].rows',
          actions: {
            Add_to_EXO_TenantBlockList: {
              runAfter: {},
              type: 'Http',
              inputs: {
                method: 'POST',
                uri: 'https://outlook.office.com/adminapi/beta/tenantBlockList/entries',
                headers: {
                  'Content-Type': 'application/json',
                  Authorization: 'Bearer @{body(\'Get_Authentication_Token\').access_token}'
                },
                body: {
                  id: '@{guid()}',
                  entryType: '@{if(equals(item()[1], \'Domain\'), \'Domain\', \'Url\')}',
                  value: '@{item()[0]}',
                  expirationDate: '@{addDays(utcNow(), 30)}',
                  action: 'Block',
                  source: 'CTI-Automation',
                  notes: '@{if(equals(item()[2], \'\'), \'Added by CTI automation - high confidence malicious indicator\', item()[2])}'
                },
                retryPolicy: {
                  type: 'fixed',
                  count: 2,
                  interval: 'PT30S'
                }
              }
            },
            Log_Success: {
              runAfter: {
                Add_to_EXO_TenantBlockList: [
                  'Succeeded'
                ]
              },
              type: 'ApiConnection',
              inputs: {
                body: {
                  IndicatorType_s: '@{item()[1]}',
                  IndicatorValue_s: '@{item()[0]}',
                  Action_s: 'Block',
                  TargetSystem_s: 'Exchange Online',
                  Status_s: 'Success',
                  Timestamp_t: '@{utcNow()}',
                  ActionId_g: '@{guid()}',
                  CorrelationId_g: '@{guid()}',
                  IndicatorId_g: '@{item()[3]}',
                  RunbookName_s: 'CTI-ExchangeOnline-Connector',
                  TriggerSource_s: 'Scheduled'
                },
                host: {
                  connection: {
                    name: '@parameters(\'$connections\')[\'azureloganalyticsdatacollector\'][\'connectionId\']'
                  }
                },
                method: 'post',
                path: '/api/logs',
                queries: {
                  logType: 'CTI_TransactionLog_CL'
                }
              }
            },
            Handle_Error: {
              actions: {
                Log_Error: {
                  runAfter: {},
                  type: 'ApiConnection',
                  inputs: {
                    body: {
                      IndicatorType_s: '@{item()[1]}',
                      IndicatorValue_s: '@{item()[0]}',
                      Action_s: 'Block',
                      TargetSystem_s: 'Exchange Online',
                      Status_s: 'Failed',
                      ErrorMessage_s: '@{outputs(\'Add_to_EXO_TenantBlockList\')[\'body\']}',
                      Timestamp_t: '@{utcNow()}',
                      ActionId_g: '@{guid()}',
                      CorrelationId_g: '@{guid()}',
                      IndicatorId_g: '@{item()[3]}',
                      RunbookName_s: 'CTI-ExchangeOnline-Connector',
                      TriggerSource_s: 'Scheduled'
                    },
                    host: {
                      connection: {
                        name: '@parameters(\'$connections\')[\'azureloganalyticsdatacollector\'][\'connectionId\']'
                      }
                    },
                    method: 'post',
                    path: '/api/logs',
                    queries: {
                      logType: 'CTI_TransactionLog_CL'
                    }
                  }
                }
              },
              runAfter: {
                Add_to_EXO_TenantBlockList: [
                  'Failed'
                ]
              },
              type: 'Scope'
            }
          },
          runAfter: {
            Get_High_Confidence_Domains_URLs: [
              'Succeeded'
            ]
          },
          type: 'Foreach',
          runtimeConfiguration: {
            concurrency: {
              repetitions: 10
            }
          }
        }
      },
      outputs: {}
    },
    parameters: {
      '$connections': {
        value: {
          azureloganalyticsdatacollector: {
            connectionId: '[resourceId(\'Microsoft.Web/connections\', \'azureloganalyticsdatacollector\')]',
            connectionName: 'azureloganalyticsdatacollector',
            id: '[concat(\'/subscriptions/\', subscription().subscriptionId, \'/providers/Microsoft.Web/locations/\', resourceGroup().location, \'/managedApis/azureloganalyticsdatacollector\')]'
          },
          azuremonitorlogs: {
            connectionId: '[resourceId(\'Microsoft.Web/connections\', \'azuremonitorlogs\')]',
            connectionName: 'azuremonitorlogs',
            id: '[concat(\'/subscriptions/\', subscription().subscriptionId, \'/providers/Microsoft.Web/locations/\', resourceGroup().location, \'/managedApis/azuremonitorlogs\')]'
          }
        }
      }
    }
  }
}

// Housekeeping Logic App - Removes expired indicators
resource housekeepingLogicApp 'Microsoft.Logic/workflows@2019-05-01' = {
  name: 'CTI-Housekeeping'
  location: location
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
          defaultValue: {},
          type: 'Object'
        },
        'tenantId': {
          defaultValue: '[parameters(\'tenantId\')]',
          type: 'String'
        },
        'clientId': {
          defaultValue: '[parameters(\'appClientId\')]',
          type: 'String'
        }
      },
      triggers: {
        Recurrence: {
          recurrence: {
            frequency: 'Day',
            interval: 1
          },
          type: 'Recurrence'
        }
      },
      actions: {
        Update_Expired_IP_Indicators: {
          runAfter: {},
          type: 'ApiConnection',
          inputs: {
            body: 'let Now = now();\nCTI_IPIndicators_CL\n| where not(isempty(ExpirationDateTime_t))\n| where ExpirationDateTime_t < Now\n| extend IndicatorId_g = IndicatorId_g, Value = IPAddress_s\n| project IndicatorId_g, Value\n| limit 1000',
            host: {
              connection: {
                name: '@parameters(\'$connections\')[\'azuremonitorlogs\'][\'connectionId\']'
              }
            },
            method: 'post',

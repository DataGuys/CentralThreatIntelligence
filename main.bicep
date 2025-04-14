// main.bicep - Central Threat Intelligence (CTI) Solution

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

@description('Enable Sentinel integration with the CTI workspace')
param enableSentinelIntegration bool = true

@description('Resource ID of the existing Sentinel workspace (if you want to integrate with an existing Sentinel)')
param existingSentinelWorkspaceId string = ''

// Define Log Analytics workspace for CTI
resource ctiWorkspace 'Microsoft.OperationalInsights/workspaces@2022-09-01' = {
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
    }
  }
}

// Define custom tables for threat intelligence
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
          name: 'ThreatType_s'
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
          name: 'MalwareFamily_s'
          type: 'string'
        }
        {
          name: 'ThreatType_s'
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
          name: 'ThreatType_s'
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
          name: 'ThreatType_s'
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
      ]
    }
  }
}

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

// Logic Apps for automation
resource logicAppServicePlan 'Microsoft.Web/serverfarms@2022-03-01' = {
  name: 'CTI-LogicApp-ServicePlan'
  location: location
  sku: {
    name: 'WS1'
    tier: 'WorkflowStandard'
  }
  properties: {}
}

// TAXII Connector Logic App
resource taxiiConnectorLogicApp 'Microsoft.Logic/workflows@2019-05-01' = {
  name: 'CTI-TAXII-Connector'
  location: location
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
          }
          type: 'Recurrence'
        }
      }
      actions: {
        // Note: This is a placeholder. You'll need to customize this with your TAXII feed details
        // The actual TAXII implementation would use HTTP actions to connect to your TAXII server
        Parse_JSON: {
          runAfter: {
            HTTP: [
              'Succeeded'
            ]
          },
          type: 'ParseJson',
          inputs: {
            content: '@body(\'HTTP\')',
            schema: {}
          }
        },
        For_each_indicator: {
          foreach: '@body(\'Parse_JSON\')',
          actions: {
            Insert_Log_Analytics_data: {
              runAfter: {},
              type: 'ApiConnection',
              inputs: {
                body: {},
                host: {
                  connection: {
                    name: '@parameters(\'$connections\')[\'azureloganalyticsdatacollector\'][\'connectionId\']'
                  }
                },
                method: 'post',
                path: '/api/logs'
              }
            }
          },
          runAfter: {
            Parse_JSON: [
              'Succeeded'
            ]
          },
          type: 'Foreach'
        },
        HTTP: {
          runAfter: {},
          type: 'Http',
          inputs: {
            method: 'GET',
            uri: 'https://your-taxii-server.com/taxii/collections/collection-id/objects/'
          }
        }
      }
    }
  }
}

// IP Block Automation Logic App - Disseminates high-confidence IP indicators to security tools
resource ipBlockLogicApp 'Microsoft.Logic/workflows@2019-05-01' = {
  name: 'CTI-IP-Block-Automation'
  location: location
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
        // Trigger on high-confidence IP indicators
        When_a_high_confidence_IP_indicator_is_added: {
          type: 'ApiConnection',
          inputs: {
            body: 'CTI_IPIndicators_CL | where ConfidenceScore_d >= 80 and TimeGenerated > ago(15m)',
            host: {
              connection: {
                name: '@parameters(\'$connections\')[\'azuremonitorlogs\'][\'connectionId\']'
              }
            },
            method: 'post',
            path: '/queryData',
            queries: {
              resourcegroups: resourceGroup().name,
              resourcename: ctiWorkspace.name,
              resourcetype: 'Log Analytics Workspace',
              subscriptions: subscription().subscriptionId,
              timerange: 'Last 15 minutes'
            }
          },
          recurrence: {
            frequency: 'Minute',
            interval: 15
          },
          splitOn: '@triggerBody().value'
        }
      },
      actions: {
        // Add to MDE Indicator API
        Add_to_MDE_Indicators: {
          runAfter: {},
          type: 'Http',
          inputs: {
            method: 'POST',
            uri: 'https://api.securitycenter.microsoft.com/api/indicators',
            headers: {
              'Content-Type': 'application/json'
            },
            body: {
              indicatorValue: '@triggerBody().IPAddress_s',
              indicatorType: 'IpAddress',
              action: 'Block',
              title: 'CTI Auto-Block: @{triggerBody().ThreatType_s}',
              description: '@triggerBody().Description_s',
              expirationTime: '@{addDays(utcNow(), 30)}'
            }
          }
        },
        // Add to Entra ID Named Locations (as risky)
        Add_to_Entra_Named_Locations: {
          runAfter: {
            Add_to_MDE_Indicators: [
              'Succeeded'
            ]
          },
          type: 'Http',
          inputs: {
            method: 'PATCH',
            uri: 'https://graph.microsoft.com/v1.0/identity/conditionalAccess/namedLocations/{named-location-id}',
            headers: {
              'Content-Type': 'application/json'
            },
            body: {
              '@odata.type': '#microsoft.graph.ipNamedLocation',
              ipRanges: [
                {
                  '@odata.type': '#microsoft.graph.ipRange',
                  cidrAddress: '@{triggerBody().IPAddress_s}/32'
                }
              ],
              isTrusted: false
            }
          }
        },
        // Log the transaction
        Log_Transaction: {
          runAfter: {
            Add_to_Entra_Named_Locations: [
              'Succeeded'
            ]
          },
          type: 'ApiConnection',
          inputs: {
            body: {
              IndicatorType_s: 'IP',
              IndicatorValue_s: '@triggerBody().IPAddress_s',
              Action_s: 'Block',
              TargetSystem_s: 'MDE,EntraID',
              Status_s: 'Success',
              Timestamp_t: '@utcNow()'
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
}

// File Hash Block Automation Logic App
resource fileHashBlockLogicApp 'Microsoft.Logic/workflows@2019-05-01' = {
  name: 'CTI-FileHash-Block-Automation'
  location: location
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
        When_a_high_confidence_file_hash_is_added: {
          type: 'ApiConnection',
          inputs: {
            body: 'CTI_FileHashIndicators_CL | where ConfidenceScore_d >= 80 and TimeGenerated > ago(15m)',
            host: {
              connection: {
                name: '@parameters(\'$connections\')[\'azuremonitorlogs\'][\'connectionId\']'
              }
            },
            method: 'post',
            path: '/queryData',
            queries: {
              resourcegroups: resourceGroup().name,
              resourcename: ctiWorkspace.name,
              resourcetype: 'Log Analytics Workspace',
              subscriptions: subscription().subscriptionId,
              timerange: 'Last 15 minutes'
            }
          },
          recurrence: {
            frequency: 'Minute',
            interval: 15
          },
          splitOn: '@triggerBody().value'
        }
      },
      actions: {
        // Add to MDE Indicator API
        Add_to_MDE_Indicators: {
          runAfter: {},
          type: 'Http',
          inputs: {
            method: 'POST',
            uri: 'https://api.securitycenter.microsoft.com/api/indicators',
            headers: {
              'Content-Type': 'application/json'
            },
            body: {
              indicatorValue: '@triggerBody().SHA256_s',
              indicatorType: 'FileSha256',
              action: 'Block',
              title: 'CTI Auto-Block: @{triggerBody().MalwareFamily_s}',
              description: '@triggerBody().Description_s',
              expirationTime: '@{addDays(utcNow(), 90)}'
            }
          }
        },
        // Log the transaction
        Log_Transaction: {
          runAfter: {
            Add_to_MDE_Indicators: [
              'Succeeded'
            ]
          },
          type: 'ApiConnection',
          inputs: {
            body: {
              IndicatorType_s: 'FileHash',
              IndicatorValue_s: '@triggerBody().SHA256_s',
              Action_s: 'Block',
              TargetSystem_s: 'MDE',
              Status_s: 'Success',
              Timestamp_t: '@utcNow()'
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
}

// Domain/URL Block Automation Logic App
resource domainUrlBlockLogicApp 'Microsoft.Logic/workflows@2019-05-01' = {
  name: 'CTI-Domain-URL-Block-Automation'
  location: location
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
        // Trigger on domain indicators
        When_a_high_confidence_domain_is_added: {
          type: 'ApiConnection',
          inputs: {
            body: 'union CTI_DomainIndicators_CL, CTI_URLIndicators_CL | where ConfidenceScore_d >= 80 and TimeGenerated > ago(15m)',
            host: {
              connection: {
                name: '@parameters(\'$connections\')[\'azuremonitorlogs\'][\'connectionId\']'
              }
            },
            method: 'post',
            path: '/queryData',
            queries: {
              resourcegroups: resourceGroup().name,
              resourcename: ctiWorkspace.name,
              resourcetype: 'Log Analytics Workspace',
              subscriptions: subscription().subscriptionId,
              timerange: 'Last 15 minutes'
            }
          },
          recurrence: {
            frequency: 'Minute',
            interval: 15
          },
          splitOn: '@triggerBody().value'
        }
      },
      actions: {
        // Add to Exchange Online Tenant Block List
        Add_to_ExO_TenantBlockList: {
          runAfter: {},
          type: 'Http',
          inputs: {
            method: 'POST',
            uri: 'https://outlook.office.com/adminapi/beta/tenantBlockList/entries',
            headers: {
              'Content-Type': 'application/json'
            },
            body: {
              value: [
                {
                  id: '@{guid()}',
                  entryType: 'Url',
                  value: '@{coalesce(triggerBody().Domain_s, triggerBody().URL_s)}',
                  expirationDate: '@{addDays(utcNow(), 30)}',
                  action: 'Block',
                  source: 'CTI-Automation',
                  notes: '@{coalesce(triggerBody().Description_s, \'Blocked by CTI automation\')}'
                }
              ]
            }
          }
        },
        // Add to MDE Indicator API
        Add_to_MDE_Indicators: {
          runAfter: {
            Add_to_ExO_TenantBlockList: [
              'Succeeded'
            ]
          },
          type: 'Http',
          inputs: {
            method: 'POST',
            uri: 'https://api.securitycenter.microsoft.com/api/indicators',
            headers: {
              'Content-Type': 'application/json'
            },
            body: {
              indicatorValue: '@{coalesce(triggerBody().Domain_s, triggerBody().URL_s)}',
              indicatorType: '@{if(contains(triggerBody(), \'Domain_s\'), \'DomainName\', \'Url\')}',
              action: 'Block',
              title: 'CTI Auto-Block: @{triggerBody().ThreatType_s}',
              description: '@{coalesce(triggerBody().Description_s, \'Blocked by CTI automation\')}',
              expirationTime: '@{addDays(utcNow(), 30)}'
            }
          }
        },
        // Log the transaction
        Log_Transaction: {
          runAfter: {
            Add_to_MDE_Indicators: [
              'Succeeded'
            ]
          },
          type: 'ApiConnection',
          inputs: {
            body: {
              IndicatorType_s: '@{if(contains(triggerBody(), \'Domain_s\'), \'Domain\', \'URL\')}',
              IndicatorValue_s: '@{coalesce(triggerBody().Domain_s, triggerBody().URL_s)}',
              Action_s: 'Block',
              TargetSystem_s: 'ExchangeOnline,MDE',
              Status_s: 'Success',
              Timestamp_t: '@utcNow()'
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
}

// Sentinel integration (optional)
resource sentinelSolution 'Microsoft.OperationsManagement/solutions@2015-11-01-preview' = if(enableSentinelIntegration) {
  name: 'SecurityInsights(${ctiWorkspace.name})'
  location: location
  properties: {
    workspaceResourceId: ctiWorkspace.id
  }
  plan: {
    name: 'SecurityInsights(${ctiWorkspace.name})'
    publisher: 'Microsoft'
    product: 'OMSGallery/SecurityInsights'
    promotionCode: ''
  }
}

// Sentinel Data Connector for CTI workspace (if using existing Sentinel)
resource sentinelDataConnector 'Microsoft.SecurityInsights/dataConnectors@2022-11-01' = if(enableSentinelIntegration && !empty(existingSentinelWorkspaceId)) {
  scope: resourceGroup(split(existingSentinelWorkspaceId, '/')[2], split(existingSentinelWorkspaceId, '/')[4])
  name: 'CTI-Workspace-Connector'
  kind: 'AzureLogAnalytics'
  properties: {
    tenantId: subscription().tenantId
    subscriptionId: subscription().subscriptionId
    workspaceResourceId: ctiWorkspace.id
    dataTypes: {
      alerts: {
        state: 'enabled'
      }
    }
  }
}

// Cross-workspace query Analytics Rule (if using existing Sentinel)
resource crossWorkspaceRule 'Microsoft.SecurityInsights/alertRules@2022-11-01' = if(enableSentinelIntegration && !empty(existingSentinelWorkspaceId)) {
  scope: resourceGroup(split(existingSentinelWorkspaceId, '/')[2], split(existingSentinelWorkspaceId, '/')[4])
  name: 'CTI-IP-Match-Rule'
  kind: 'Scheduled'
  properties: {
    displayName: 'Traffic to CTI flagged IP addresses'
    enabled: true
    query: '''
    let IPIndicators = workspace("${ctiWorkspace.id}").CTI_IPIndicators_CL
    | where ConfidenceScore_d >= 70
    | project IPAddress = IPAddress_s, ThreatType = ThreatType_s, Confidence = ConfidenceScore_d;
    
    CommonSecurityLog
    | where DeviceAction !~ "block"
    | where isnotempty(DestinationIP) 
    | join kind=inner IPIndicators on $left.DestinationIP == $right.IPAddress
    | project TimeGenerated, DeviceName, SourceIP, DestinationIP, ThreatType, Confidence
    '''
    queryFrequency: 'PT1H'
    queryPeriod: 'PT1H'
    severity: 'Medium'
    suppressionDuration: 'PT1H'
    suppressionEnabled: false
    tactics: [
      'CommandAndControl'
      'Exfiltration'
    ]
    triggerOperator: 'GreaterThan'
    triggerThreshold: 0
  }
}

// Outputs
output ctiWorkspaceId string = ctiWorkspace.id
output ctiWorkspaceName string = ctiWorkspace.name

// Microsoft Sentinel integration – fixed nesting & bumped API version

param ctiWorkspaceName string
param ctiWorkspaceId string
param location string
param enableSentinelIntegration bool
param enableAnalyticsRules bool
param enableHuntingQueries bool
param existingSentinelWorkspaceId string
param tags object

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
    workspaceResourceId: ctiWorkspaceId
  }
}

// Existing workspace reference
resource workspace 'Microsoft.OperationalInsights/workspaces@2022-10-01' existing = {
  name: ctiWorkspaceName
}

resource analyticRule 'Microsoft.OperationalInsights/workspaces/providers/alertRules@2025-03-01' = if (enableSentinelIntegration && enableAnalyticsRules) {
  parent: workspace
  name: 'Microsoft.SecurityInsights/CTI-ThreatIntelMatch'
  kind: 'ThreatIntelligence'
  properties: {
    displayName: 'Threat Intelligence Indicator Match'
    enabled: true
    severity: 'High'
    productFilter: 'Microsoft Sentinel'
    sourceSettings: [
      {
        sourceId: 'Azure Sentinel'
        sourceType: 'SentinelAlerting'
        status: 'Enabled'
      }
    ]
  }
  dependsOn: [ enableSentinelIntegration && empty(existingSentinelWorkspaceId) ? sentinelSolution : workspace ]
}

resource huntingQuery 'Microsoft.OperationalInsights/workspaces/savedSearches@2020-08-01' = if (enableSentinelIntegration && enableHuntingQueries) {
  parent: workspace
  name: 'CTI-DomainIOCMatch'
  properties: {
    category: 'Hunting Queries'
    displayName: 'Domain IOC matches in DNS queries'
    query: '''
      let iocs = CTI_DomainIndicators_CL | where Active_b == true;
      DnsEvents | where Name has_any (iocs)
    '''
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

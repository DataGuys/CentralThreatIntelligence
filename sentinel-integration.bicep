param ctiWorkspaceName string
param ctiWorkspaceId string
param location string
param enableSentinelIntegration bool
param enableAnalyticsRules bool
param enableHuntingQueries bool
param existingSentinelWorkspaceId string
param tags object

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
    workspaceResourceId: ctiWorkspaceId
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
    enableSentinelIntegration && empty(existingSentinelWorkspaceId) ? sentinelSolution : ctiWorkspaceId
  ]
}

// Implement Hunting Queries if enabled
resource huntingQuery 'Microsoft.OperationalInsights/workspaces/savedSearches@2020-08-01' = if (enableHuntingQueries && enableSentinelIntegration) {
  name: '${ctiWorkspaceName}/CTI-DomainIOCMatch'
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

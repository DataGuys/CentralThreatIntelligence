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

// NOTE: ThreatIntelligence kind rules require a specific template GUID.
// Replace '00000000-0000-0000-0000-000000000000' with the actual Threat Intelligence rule template GUID you want to use.
// Common template GUIDs for TI Map data connector:
// - IP address: '23e326f1-a69d-40f3-850b-9143f6cb189f'
// - Domain name: '044b68dd-a385-4dfa-b498-193d4919501b'
// - File hash: 'ea862697-47e1-4940-a55a-fe66610df9e5'
// - URL: 'ac9a37e1-18be-455e-b05c-94889875ed09'
// Choose one appropriate template or create multiple rule resources if needed.
var threatIntelRuleTemplateGuid = '00000000-0000-0000-0000-000000000000' // <-- Replace this placeholder GUID
var threatIntelRuleName = guid(workspace.id, 'CTI-ThreatIntelMatch', threatIntelRuleTemplateGuid) // Generate a unique name

resource analyticRule 'Microsoft.SecurityInsights/alertRules@2023-02-01-preview' = if (enableSentinelIntegration && enableAnalyticsRules) {
  // Alert rules are deployed as child resources of the Log Analytics workspace.
  scope: workspace // Deploy within the workspace scope
  name: threatIntelRuleName
  kind: 'ThreatIntelligence'
  properties: {
    enabled: true
    alertRuleTemplateName: threatIntelRuleTemplateGuid // Required for ThreatIntelligence kind
    // Tactics are inherited from the template for ThreatIntelligence kind rules
    // Severity, productFilter, sourceSettings are not applicable for ThreatIntelligence kind
  }
  // dependsOn is implicitly handled by the scope property
}

resource huntingQuery 'Microsoft.OperationalInsights/workspaces/savedSearches@2020-08-01' = if (enableSentinelIntegration && enableHuntingQueries) {
  parent: workspace
  name: 'CTI-DomainIOCMatch'
  properties: {
    category: 'Hunting Queries'
    displayName: 'Domain IOC matches in DNS queries'
    query: '''
      let iocs = CTI_DomainIndicators_CL | where Active_b == true | project DomainName_s;
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
  // Implicitly depends on workspace. Explicit dependency on sentinelSolution might be needed
  dependsOn: [
    sentinelSolution
  ]
}

# Central Threat Intelligence (CTI) Solution
## Quick Deployment
The fastest way to deploy this solution is using Azure Cloud Shell:

### Open Azure Cloud Shell (Bash mode)
* Create the app registration first:
```bash
curl -sL https://raw.githubusercontent.com/DataGuys/CentralThreatIntelligence/refs/heads/main/create-cti-app.sh | tr -d '\r' | bash
```
* Deploy the solution with the generated client ID:
```bash
bash -c "$(curl -fsSL https://raw.githubusercontent.com/DataGuys/CentralThreatIntelligence/main/deploy.sh)" \
  -- --subscription-name "MySubscription" \
     --resource-group MyRG \
     --location eastus \
     --client-id 00000000-0000-0000-0000-000000000000
```
* For customized deployment:
```bash
curl -sL https://raw.githubusercontent.com/DataGuys/CentralThreatIntelligence/refs/heads/main/deploy.sh | bash -s -- --resource-group "MyRG" --location "westus2" --client-id "00000000-0000-0000-0000-000000000000" --advanced
```

## Solution Overview
The Central Threat Intelligence (CTI) solution creates a unified platform for collecting, managing, and operationalizing threat intelligence across your Microsoft security stack. It addresses the challenge of dispersed threat intelligence by creating a central repository with automated distribution.
Architecture Components

Central Log Analytics Workspace: Dedicated repository for all threat intelligence data
Custom Data Tables: Specialized schema for different IOC types (IP, Domain, URL, FileHash)
Automated Logic Apps: Workflow automation for IOC distribution and management
Microsoft Sentinel Integration: Analytics rules and cross-workspace hunting
Microsoft Defender XDR Integration: Direct indicator submission and alerting
Unified Security Operations Portal: Integration with Microsoft's security platform

## Prerequisites

Azure Subscription: Active subscription with Contributor permissions
Microsoft 365 E3/E5 License: For Microsoft Defender and Exchange Online
Microsoft Sentinel License: If enabling the Sentinel integration
Microsoft Defender XDR License: For XDR integration features
Microsoft Entra ID Application: With appropriate API permissions

## Required API Permissions
The create-cti-app.sh script automatically registers an application with these permissions:
APIPermission TypePermissionsMicrosoft Threat ProtectionApplicationIndicator.ReadWrite.AllMicrosoft GraphApplicationIdentityRiskyUser.ReadWrite.All, Policy.ReadWrite.ConditionalAccessOffice 365 Exchange OnlineApplicationThreatIntelligence.Read.All

# Post-Deployment Configuration
## 1. Configure TAXII Feeds

Navigate to the CTI-TAXII2-Connector Logic App in the Azure Portal
Add your TAXII server details to the Logic App
Use the CTI_IntelligenceFeeds_CL table to store feed metadata

Example feed metadata:
```kql
let FeedData = datatable(
    FeedId_g:string,
    FeedName_s:string,
    FeedType_s:string,
    FeedURL_s:string,
    CollectionId_s:string,
    EncodedCredentials_s:string,
    Description_s:string,
    Category_s:string,
    TLP_s:string,
    ConfidenceScore_d:double
)
[
    "00000000-0000-0000-0000-000000000000",
    "MISP Community Feed",
    "TAXII",
    "https://taxii.example.org",
    "collection-id",
    "base64_encoded_credentials",
    "MISP Community TAXII Feed",
    "Community",
    "TLP:AMBER",
    70
];
```

### FeedData
2. Microsoft Defender Threat Intelligence
The MDTI connector automatically pulls threat intelligence from Microsoft's premium feed, if enabled during deployment.
3. Custom API Sources
To integrate custom API feeds:

Create a custom Logic App for your API source
Use the existing table schemas for storing indicators
Follow the same pattern as the TAXII connector for authentication and data insertion

Operational Tasks
Indicator Management

Expiration Handling: The Housekeeping Logic App automatically manages indicator lifecycle
Confidence Updates: Use the Analytics Feedback table to adjust confidence scores
Manual Updates: Use Sentinel workbooks to manage indicators directly

Monitoring Feed Health

Access the "CTI - Feed Health" workbook in Sentinel
Monitor feed reliability, indicator freshness, and distribution success rates

Tracking Detections

Run the provided KQL queries for threat detection and analysis
Monitor the CTI analytics rules in Sentinel
Check the transaction logs for successful IOC distribution

Troubleshooting
Common Issues

Logic App Failures:

Check application permissions
Verify key vault access
Review Logic App run history


Data Ingestion Issues:

Validate table schemas
Check for rate limiting
Ensure proper formatting of data


Integration Problems:

Verify API endpoints
Check authentication credentials
Review network connectivity

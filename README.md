# Central Threat Intelligence (CTI) Solution

## Quick Start

Deploy the CTI solution directly in Azure Cloud Shell:

```bash
curl -sL https://raw.githubusercontent.com/DataGuys/CentralThreatIntelligence/refs/heads/main/deploy.sh | bash -s -- --advanced
```

For a customized deployment with specific parameters:

```bash
curl -sL https://raw.githubusercontent.com/DataGuys/CentralThreatIntelligence/refs/heads/main/deploy.sh | bash -s -- --resource-group "MyRG" --location "westus2" --client-id "00000000-0000-0000-0000-000000000000"
```

## Solution Overview

The Central Threat Intelligence (CTI) solution creates a unified platform for collecting, managing, and operationalizing threat intelligence across your Microsoft security stack. This guide provides detailed implementation instructions to ensure successful deployment and configuration.

## Architecture Components

1. **Central Log Analytics Workspace**: Dedicated repository for all threat intelligence data
2. **Custom Data Tables**: Specialized schema for different IOC types (IP, Domain, URL, FileHash)
3. **Automated Logic Apps**: Workflow automation for IOC distribution and management
4. **Microsoft Sentinel Integration**: Analytics rules and cross-workspace hunting 
5. **Microsoft Defender XDR Integration**: Direct indicator submission and alerting
6. **Unified Security Operations Portal**: Integration with Microsoft's security platform

## Prerequisites

Before deploying the solution, ensure you have:

1. **Azure Subscription**: Active subscription with Contributor permissions
2. **Microsoft 365 E3/E5 License**: Provides access to Microsoft Defender and Exchange Online
3. **Microsoft Sentinel License**: If enabling the Sentinel integration
4. **Microsoft Defender XDR License**: For XDR integration features
5. **Microsoft Entra ID Application**: Registered app with appropriate API permissions

### Required API Permissions

Register an application in Microsoft Entra ID with the following permissions:

| API | Permission Type | Permissions |
|-----|----------------|-------------|
| Microsoft Threat Protection | Application | Indicator.ReadWrite.All |
| Microsoft Graph | Application | IdentityRiskyUser.ReadWrite.All, Policy.ReadWrite.ConditionalAccess |
| Office 365 Exchange Online | Application | ThreatIntelligence.Read.All |

## Deployment Options

### Option 1: Azure Cloud Shell Deployment (Recommended)

1. Open [Azure Cloud Shell](https://shell.azure.com/)
2. Ensure you're in Bash mode (not PowerShell)
3. Run the deployment command:

```bash
curl -sL https://raw.githubusercontent.com/DataGuys/CentralThreatIntelligence/refs/heads/main/deploy.sh | bash
```

### Option 2: Manual Deployment

1. **Clone the repository**:
   ```bash
   git clone https://github.com/DataGuys/CentralThreatIntelligence.git
   cd CentralThreatIntelligence
   ```

2. **Run the deployment script**:
   ```bash
   chmod +x deploy.sh
   ./deploy.sh
   ```

### Option 3: Customized Deployment

For a customized deployment with specific parameters:

```bash
./deploy.sh --resource-group "CTI-ResourceGroup" \
  --location "eastus" \
  --workspace-name "CTI-Workspace" \
  --client-id "00000000-0000-0000-0000-000000000000" \
  --tenant-id "00000000-0000-0000-0000-000000000000"
```

## Post-Deployment Configuration

### 1. Configure TAXII Feeds

- Navigate to the CTI-TAXII2-Connector Logic App in the Azure Portal
- Add your TAXII server details to the Logic App
- Use the `CTI_IntelligenceFeeds_CL` table to store feed metadata

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

FeedData
```

### 2. Microsoft Defender Threat Intelligence

The MDTI connector automatically pulls threat intelligence from Microsoft's premium feed, if enabled during deployment.

### 3. Custom API Sources

To integrate custom API feeds:

1. Create a custom Logic App for your API source
2. Use the existing table schemas for storing indicators
3. Follow the same pattern as the TAXII connector for authentication, parsing, and data insertion

## Operational Tasks

### 1. Indicator Management

- **Expiration Handling**: The Housekeeping Logic App automatically manages indicator lifecycle
- **Confidence Updates**: Use the Analytics Feedback table to adjust confidence scores
- **Manual Updates**: Use Sentinel workbooks to manage indicators directly

### 2. Monitoring Feed Health

1. Access the "CTI - Feed Health" workbook in Sentinel
2. Monitor feed reliability, indicator freshness, and distribution success rates

### 3. Tracking Detections

1. Run the provided KQL queries for threat detection and analysis
2. Monitor the CTI analytics rules in Sentinel
3. Check the transaction logs for successful IOC distribution

## Troubleshooting

### Common Issues

1. **Logic App Failures**:
   - Check application permissions
   - Verify key vault access
   - Review Logic App run history

2. **Data Ingestion Issues**:
   - Validate table schemas
   - Check for rate limiting
   - Ensure proper formatting of data

3. **Integration Problems**:
   - Verify API endpoints
   - Check authentication credentials
   - Review network connectivity

## Advanced Customization

### Custom Table Schema

To modify or extend table schemas:

1. Update the Bicep template with new column definitions
2. Redeploy the solution or use Azure CLI to update specific tables

### Adding New Logic Apps

To integrate additional threat intelligence sources:

1. Create a new Logic App using the provided templates as examples
2. Follow the same pattern for authentication, data normalization, and Log Analytics ingestion

### Extending Analytics

To create custom analytics:

1. Use the provided KQL queries as starting points
2. Develop new analytics rules in Sentinel
3. Create alerting automation with Logic Apps

## Maintenance

### Regular Tasks

1. **Weekly**:
   - Review feed health
   - Check for failed automations
   - Monitor indicators

2. **Monthly**:
   - Update feed configurations
   - Review detection effectiveness
   - Clean up expired indicators

3. **Quarterly**:
   - Evaluate feed performance
   - Adjust confidence thresholds
   - Update MITRE ATT&CK mappings

## Security Best Practices

1. **Access Control**:
   - Implement least privilege principle
   - Use managed identities where possible
   - Regularly review permissions

2. **Data Protection**:
   - Encrypt all connections
   - Protect API keys and credentials
   - Monitor for unauthorized access

3. **Compliance**:
   - Follow TLP protocols for indicator sharing
   - Document indicator sources and handling
   - Implement appropriate data retention policies

## Support and Contributions

For questions, issues, or contributions, please open an issue or pull request in the GitHub repository.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

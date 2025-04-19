# Central Threat Intelligence (CTI) Solution

## Disclaimer

## **IMPORTANT**: This is **NOT** an official Microsoft product or solution. This project is a third-party custom implementation for centralizing threat intelligence across Microsoft security products. You assume all risk by implementing and maintaining this solution; consider this your warning

## Overview

The Central Threat Intelligence (CTI) solution provides a unified platform for collecting, managing, and operationalizing threat intelligence across your organization's security ecosystem. It addresses the challenge of scattered threat intelligence by creating a centralized repository with automated distribution capabilities.

A cyber threat intelligence platform serves as a centralized tool that collects, processes, and analyzes threat data from various sources, providing actionable insights into potential cyber risks. This solution implements this concept specifically for organizations using Microsoft security products.

## Key Features

### Centralized Intelligence Repository

- Dedicated Log Analytics workspace for storing all threat intelligence data
- Custom tables with specialized schemas for different indicator types (IP, Domain, URL, FileHash)
- Standardized data format aligned with STIX 2.1 for interoperability

### Multi-Source Intelligence Collection

- TAXII 2.0 connector for consuming industry-standard threat feeds
- Microsoft Defender Threat Intelligence integration (optional)
- Manual indicator submission through custom workbooks
- Support for custom API sources and CSV feeds

### Automated Distribution to Security Controls

- Microsoft Defender XDR integration for endpoint protection
- Microsoft Entra ID (formerly Azure AD) integration for identity risk management
- Exchange Online integration for email security
- Microsoft Sentinel integration for SIEM and XDR capabilities

### Advanced Analysis Capabilities

- Cross-table correlation through KQL queries
- MITRE ATT&CK mapping for TTPs
- Confidence scoring and automatic feedback loop
- Temporal analysis with first/last seen timestamps

### Lifecycle Management

- Automated expiration of indicators
- Confidence score adjustment based on false positives/negatives
- Historical analysis capabilities
- Performance metrics for feed quality assessment

## Architecture Components

1. **Core Infrastructure**
   - Log Analytics workspace
   - Key Vault for secrets
   - User-assigned managed identities

2. **Custom Data Tables**
   - Specialized schemas for different IOC types
   - Support for STIX 2.1 object model
   - Extended properties for enrichment

3. **Logic Apps for Integration**
   - TAXII connector for industry feeds
   - Defender connector for Microsoft security products
   - Exchange Online connector for email security
   - Automated housekeeping processes

4. **Microsoft Sentinel Integration**
   - Analytics rules for alerting
   - Custom hunting queries
   - Investigation workbooks

5. **Unified Security Operations Portal**
   - Integration with Microsoft Defender portal
   - Cross-workspace query capabilities
   - Interactive dashboards

## Prerequisites

- Azure Subscription with Contributor permissions
- Microsoft 365 E3/E5 license (for Microsoft Defender and Exchange Online)
- Microsoft Sentinel license (if enabling Sentinel integration)
- Microsoft Defender XDR license (for XDR integration)
- Microsoft Entra ID Application with appropriate API permissions

## Deployment

The fastest way to deploy this solution is using Azure Cloud Shell:

### 1. Create the app registration first

#### 1 App Registration Deployment

```bash
curl -sL https://raw.githubusercontent.com/DataGuys/CentralThreatIntelligence/main/create-cti-app.sh | tr -d '\r' | bash -s
```

### 2. Deploy the solution with the generated client ID

```bash
SUB_ID=\"\"; PS3='Select subscription: '; mapfile -t SUBS < <(az account list --query \"[].{name:name,id:id}\" -o tsv); select SUB in \"\${SUBS[@]}\"; do [[ -n \$SUB ]] && az account set --subscription \"\${SUB##*$'\t'}\" && echo \"Switched to subscription: \${SUB%%$'\t'*}\" && CHOSEN_SUB_ID=\"\${SUB##*$'\t'}\" && break; done" # Capture chosen ID
echo " curl -sL https://raw.githubusercontent.com/DataGuys/CentralThreatIntelligence/main/deploy.sh | tr -d '\r' |  bash -s -- --subscription-id \${SUB_ID} --client-id ${APP_ID} --location eastus"
echo "----------------------------------------"
```

### 3. For customized deployment

```bash
curl -sL https://raw.githubusercontent.com/DataGuys/CentralThreatIntelligence/refs/heads/main/deploy.sh | bash -s -- --resource-group "CTI-RG" --location "eastus" --client-id "00000000-0000-0000-0000-000000000000" --advanced
```

## Post-Deployment Configuration

### 1. Configure TAXII Feeds

The TAXII2 connector Logic App needs to be configured with your TAXII server details. Use the `CTI_IntelligenceFeeds_CL` table to store feed metadata.

### 2. Microsoft Defender Threat Intelligence

If enabled during deployment, the MDTI connector will automatically pull threat intelligence from Microsoft's premium feed.

### 3. Custom API Sources

To integrate custom API feeds, create a custom Logic App following the same pattern as the TAXII connector.

## Usage Examples

### Indicator Management

- Use the provided workbooks for manual indicator management
- Run the KQL queries in `CTI_Advanced_Queries.kql` for threat detection
- Monitor the feed health through the "CTI - Feed Health" workbook

### Tracking Detections

- Monitor the CTI analytics rules in Sentinel
- Review transaction logs for successful IOC distribution

## Repository Structure

- `core-infrastructure.bicep`: Core Azure resources definition
- `custom-tables.bicep`: Log Analytics table schemas
- `api-connections.bicep`: API connections for Logic Apps
- `logic-apps/`: Integration connectors for various sources
- `sentinel-integration.bicep`: Microsoft Sentinel enablement
- `CTI_Advanced_Queries.kql`: KQL queries for threat detection
- `CTI-ManualIndicatorSubmission.workbook`: Workbook for manual IOC submission

## Areas for Improvement

Based on review, here are potential enhancements to consider:

1. **Error Handling**: Implement more robust error handling and retry logic in Logic Apps
2. **Documentation**: Expand documentation on custom API integration
3. **Testing Framework**: Add testing guidelines and validation procedures
4. **Security Hardening**: Strengthen security posture with network isolation
5. **Scaling Guidance**: Add recommendations for enterprise-scale deployments
6. **Privacy Compliance**: Include GDPR/privacy considerations
7. **Business Continuity**: Add disaster recovery guidance
8. **Performance Optimization**: Add tuning guidance for high-volume environments
9. **Cost Management**: Include cost estimation and optimization tips
10. **Visualization**: Enhance dashboards and reporting capabilities

## Comparison to Microsoft's Native Solutions

While Microsoft offers its own threat intelligence platforms like Microsoft Defender Threat Intelligence, this custom solution provides unique capabilities for centralization across all Microsoft security products. It serves as a complementary solution rather than a replacement.

Key differences from Microsoft's native offerings:

- Centralized repository for all threat intelligence across products
- Custom schema extensions beyond standard Microsoft formats
- Dedicated workflows for specialized intelligence feeds
- Enhanced correlation across different indicator types
- Full control over data retention and processing logic

## Open Source Alternatives

If you're looking for open-source alternatives, consider platforms like OpenCTI, which provides structured storage of threat intelligence using STIX2 standards. Other options include:

- MISP: Malware Information Sharing Platform
- TheHive: Security incident response platform
- YETI: Your Everyday Threat Intelligence
- GOSINT: Open source intelligence gathering platform

## Contact and Support

This project is maintained by DataGuys. For questions or support, please open an issue on the GitHub repository.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

---

I'll now provide my analysis and suggestions for improvements to the Central Threat Intelligence solution:

## Analysis and Recommendations

After reviewing the repository, I found that the Central Threat Intelligence (CTI) solution represents a well-thought-out implementation for centralizing threat intelligence in Microsoft environments. However, there are several areas that could be improved:

### Architecture Strengths

1. **Comprehensive Integration**: The solution connects with multiple Microsoft security products, providing a unified view of threat intelligence.
2. **Scalable Design**: The use of Bicep templates and modular architecture enables scaling from small to enterprise deployments.
3. **Standardized Data Model**: The custom tables align with STIX 2.1, providing industry-standard formats.
4. **Automation Focus**: Logic Apps provide no-code/low-code automation for intelligence processing.

### Technical Gaps

1. **Limited Error Handling**: The Logic App implementations could benefit from more robust error handling, particularly for API rate limits and transient failures.
2. **Deployment Complexity**: The initialization process requires multiple steps that could be simplified.
3. **Monitoring Gaps**: More comprehensive monitoring for the health of the overall solution is needed.
4. **Limited Data Transformation**: Advanced enrichment and transformation capabilities could be expanded.

### Feature Suggestions

1. **Enhanced Machine Learning**: Implement ML models for threat scoring and prioritization.
2. **API Gateway**: Add an API gateway for standardized access to the threat intelligence.
3. **Threat Hunting Workbooks**: Develop more specialized hunting workbooks for different threat types.
4. **Collaborative Analysis**: Add capabilities for security analysts to collaborate on investigations.
5. **Integration with Open-Source Tools**: Expand beyond Microsoft products to integrate with tools like MISP or OpenCTI.

### Documentation Improvements

1. **Architecture Diagrams**: Add detailed architecture diagrams showing data flows.
2. **Operational Guidance**: Include day-to-day operational procedures.
3. **Troubleshooting Guide**: Develop comprehensive troubleshooting documentation.
4. **Performance Tuning**: Add guidance on optimizing for high-volume environments.

The solution offers a solid foundation but would benefit from these enhancements to reach enterprise-grade maturity. With proper implementation, this CTI solution could significantly improve an organization's threat intelligence capabilities across their Microsoft security stack.

**TL;DR –** The Central Threat Intelligence (CTI) solution provides a comprehensive platform for collecting, managing, and operationalizing threat intelligence across Microsoft security products, though it could benefit from enhanced error handling, monitoring, and machine learning capabilities.

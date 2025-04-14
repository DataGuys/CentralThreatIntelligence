# Integration with Microsoft's Unified Security Operations Portal

## Overview

Microsoft's unified security operations platform integrates Microsoft Sentinel and Microsoft Defender XDR into a single, cohesive security operations experience. This guide outlines how to connect your Central Threat Intelligence (CTI) solution to this unified platform.

## Prerequisites

1. A Microsoft 365 E5 license or equivalent that includes Microsoft Sentinel and Microsoft Defender XDR
2. Global Administrator or Security Administrator privileges
3. The deployed CTI solution with:
   - CTI Log Analytics Workspace
   - Microsoft Sentinel enabled on the workspace (if using the workspace as the primary Sentinel instance)

## Integration Options

There are two primary methods for integrating your CTI solution with the unified SecOps platform:

### Option 1: Direct Integration via Log Analytics Workspace (Recommended)

This approach adds your CTI Log Analytics workspace directly to the Microsoft Defender portal.

#### Implementation Steps:

1. **Enable Microsoft Sentinel on your CTI workspace** (if not already done)
   - This is configured in the Bicep template with the `enableSentinelIntegration` parameter

2. **Connect the CTI workspace to the Microsoft Defender portal**:
   - Navigate to the [Microsoft Defender portal](https://security.microsoft.com)
   - Select **Settings** > **Microsoft Sentinel** > **Connect workspace**
   - Select your CTI workspace from the list of available workspaces
   - If prompted, designate whether this is your primary workspace

3. **Configure workspace roles and permissions**:
   - Ensure the appropriate users have the necessary permissions to access the CTI data
   - Configure proper Azure RBAC roles for the CTI workspace

### Option 2: Cross-Workspace Integration

If you already have a primary Microsoft Sentinel workspace in the unified SecOps portal, you can integrate your CTI workspace through cross-workspace queries.

#### Implementation Steps:

1. **Connect your primary Sentinel workspace to the Microsoft Defender portal** (if not already done)

2. **Configure cross-workspace queries**:
   - Use the `workspace()` function in KQL to query across both workspaces
   - Example:
     ```kql
     let CTIWorkspaceId = "<your-cti-workspace-resource-id>";
     
     workspace(CTIWorkspaceId).CTI_IPIndicators_CL
     | where ConfidenceScore_d >= 80
     | project IPAddress_s, ThreatType_s, SourceFeed_s
     ```

3. **Create Sentinel Analytics Rules using cross-workspace queries**:
   - Navigate to Microsoft Sentinel > Analytics
   - Create new scheduled analytics rules that use cross-workspace queries
   - These rules will generate alerts and incidents in your primary workspace

## Recommended Configuration

### For New Deployments:

1. Deploy the CTI solution with `enableSentinelIntegration = true`
2. Connect the CTI workspace directly to the Microsoft Defender portal (Option 1)
3. Configure the CTI workspace as a secondary workspace if you already have a primary Sentinel workspace

### For Existing Sentinel Deployments:

1. Deploy the CTI solution with `enableSentinelIntegration = true`
2. Use the cross-workspace query approach (Option 2)
3. Configure the data connector in your primary workspace to ingest alerts from the CTI workspace

## Verifying Integration

After integrating your CTI workspace with the unified SecOps portal:

1. **Verify Data Access**:
   - Navigate to Microsoft Defender portal > Hunting
   - Run a simple query against your CTI tables (e.g., `CTI_IPIndicators_CL | limit 10`)
   - Confirm that data is accessible

2. **Test Cross-Workspace Functionality**:
   - If using Option 2, test a cross-workspace query to ensure it returns results
   - Verify that analytics rules using cross-workspace queries generate alerts properly

3. **Check Incident Generation**:
   - Confirm that CTI-related incidents appear in your unified incident queue

## Additional Capabilities

Once integration is complete, you can leverage the following unified SecOps capabilities:

1. **AI-assisted investigation** with Microsoft Security Copilot
2. **Unified incident management** across Sentinel and Defender XDR
3. **Cross-domain hunting** using Advanced Hunting
4. **Automated response** with Sentinel playbooks and Defender automated investigation

## Troubleshooting

If you encounter issues during integration:

1. **Workspace Connectivity Issues**:
   - Verify Azure roles and permissions
   - Check that the resources are in the same Azure AD tenant
   - Review connection logs in the Azure Monitor activity log

2. **Data Not Appearing**:
   - Verify that the CTI data ingestion Logic Apps are running successfully
   - Check for any workspace ingestion delays (typically 5-15 minutes)
   - Ensure the query time range is appropriate for your data

3. **Cross-Workspace Query Failures**:
   - Confirm the workspace resource ID is correct
   - Verify that the current user has permissions on both workspaces
   - Check for any workspace-specific table schema differences

## Key Limitations

Be aware of these limitations when integrating with the unified SecOps platform:

1. **Query Performance**: Cross-workspace queries may have slightly increased latency compared to single workspace queries

2. **Feature Parity**: Some Sentinel features might only be available in the Azure portal version of Sentinel

3. **Workspace Limits**: Standard Log Analytics workspace limits apply (daily ingestion caps, retention periods, etc.)

## Next Steps

1. Create Sentinel workbooks that span CTI and other security data
2. Configure automated response playbooks triggered by CTI matches
3. Establish regular CTI data review processes in the unified SecOps workflow

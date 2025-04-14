#!/bin/bash
# deploy.sh - Deploy the Central Threat Intelligence (CTI) Solution

# Set error handling
set -e

# Configuration variables - change these as needed
RESOURCE_GROUP_NAME="CTI-ResourceGroup"
LOCATION="eastus"
DEPLOYMENT_NAME="CTI-Deployment-$(date +%Y%m%d%H%M%S)"
CTI_WORKSPACE_NAME="CTI-Workspace"
CTI_WORKSPACE_RETENTION_DAYS=90
CTI_WORKSPACE_DAILY_QUOTA_GB=5
ENABLE_SENTINEL_INTEGRATION=true
EXISTING_SENTINEL_WORKSPACE_ID=""  # Fill this in if you have an existing Sentinel workspace

# Display script banner
echo "=================================================="
echo "Central Threat Intelligence (CTI) Solution Deployment"
echo "=================================================="
echo "This script will deploy the following components:"
echo "- CTI Log Analytics Workspace"
echo "- Custom Tables for Threat Intelligence"
echo "- Workbooks and Dashboards"
echo "- Logic Apps for Automation"
echo "- Optional Sentinel Integration"
echo ""

# Create workbooks directory if it doesn't exist
echo "Creating workbooks directory..."
mkdir -p workbooks

# Create placeholder workbook JSON files
echo "Creating placeholder workbook JSON files..."

# IOC Overview Workbook
if [ ! -f "workbooks/ioc-overview.json" ]; then
    echo '{
        "version": "Notebook/1.0",
        "items": [
            {
                "type": 1,
                "content": {
                    "json": "# CTI - IOC Overview\\nThis workbook provides an overview of Indicators of Compromise (IOCs) in your Central Threat Intelligence workspace."
                },
                "name": "text - 0"
            },
            {
                "type": 3,
                "content": {
                    "version": "KqlItem/1.0",
                    "query": "union CTI_IPIndicators_CL, CTI_FileHashIndicators_CL, CTI_DomainIndicators_CL, CTI_URLIndicators_CL\\n| summarize count() by Type = case(\\n    _TableName == \\"CTI_IPIndicators_CL\\", \\"IP Addresses\\",\\n    _TableName == \\"CTI_FileHashIndicators_CL\\", \\"File Hashes\\",\\n    _TableName == \\"CTI_DomainIndicators_CL\\", \\"Domains\\",\\n    _TableName == \\"CTI_URLIndicators_CL\\", \\"URLs\\",\\n    \\"Other\\"\\n)",
                    "size": 0,
                    "title": "Distribution of IOCs by Type",
                    "timeContext": {
                        "durationMs": 2592000000
                    },
                    "queryType": 0,
                    "resourceType": "microsoft.operationalinsights/workspaces",
                    "visualization": "piechart"
                },
                "name": "ioc-distribution"
            }
        ],
        "styleSettings": {}
    }' > workbooks/ioc-overview.json
    echo "Created IOC Overview workbook."
fi

# Feed Health Workbook
if [ ! -f "workbooks/feed-health.json" ]; then
    echo '{
        "version": "Notebook/1.0",
        "items": [
            {
                "type": 1,
                "content": {
                    "json": "# CTI - Feed Health\\nThis workbook monitors the health and reliability of your threat intelligence feeds."
                },
                "name": "text - 0"
            },
            {
                "type": 3,
                "content": {
                    "version": "KqlItem/1.0",
                    "query": "union CTI_IPIndicators_CL, CTI_FileHashIndicators_CL, CTI_DomainIndicators_CL, CTI_URLIndicators_CL\\n| summarize count() by SourceFeed_s\\n| order by count_ desc",
                    "size": 0,
                    "title": "IOCs by Feed Source",
                    "timeContext": {
                        "durationMs": 2592000000
                    },
                    "queryType": 0,
                    "resourceType": "microsoft.operationalinsights/workspaces",
                    "visualization": "barchart"
                },
                "name": "iocs-by-feed"
            }
        ],
        "styleSettings": {}
    }' > workbooks/feed-health.json
    echo "Created Feed Health workbook."
fi

# IOC Lifecycle Workbook
if [ ! -f "workbooks/ioc-lifecycle.json" ]; then
    echo '{
        "version": "Notebook/1.0",
        "items": [
            {
                "type": 1,
                "content": {
                    "json": "# CTI - IOC Lifecycle\\nThis workbook tracks the lifecycle of Indicators of Compromise (IOCs) in your environment."
                },
                "name": "text - 0"
            },
            {
                "type": 3,
                "content": {
                    "version": "KqlItem/1.0",
                    "query": "union CTI_IPIndicators_CL, CTI_FileHashIndicators_CL, CTI_DomainIndicators_CL, CTI_URLIndicators_CL\\n| summarize New = countif(FirstSeen_t >= ago(1d)), Existing = countif(FirstSeen_t < ago(1d)), Expiring = countif(LastSeen_t < ago(30d))\\n| extend Total = New + Existing\\n| project New, Existing, Expiring, Total\\n| project-away Total\\n| render columnchart",
                    "size": 0,
                    "title": "IOC Lifecycle Status",
                    "timeContext": {
                        "durationMs": 2592000000
                    },
                    "queryType": 0,
                    "resourceType": "microsoft.operationalinsights/workspaces"
                },
                "name": "ioc-lifecycle-status"
            }
        ],
        "styleSettings": {}
    }' > workbooks/ioc-lifecycle.json
    echo "Created IOC Lifecycle workbook."
fi

# IOC Dissemination Workbook
if [ ! -f "workbooks/ioc-dissemination.json" ]; then
    echo '{
        "version": "Notebook/1.0",
        "items": [
            {
                "type": 1,
                "content": {
                    "json": "# CTI - IOC Dissemination\\nThis workbook tracks the dissemination of IOCs to security tools across your environment."
                },
                "name": "text - 0"
            },
            {
                "type": 3,
                "content": {
                    "version": "KqlItem/1.0",
                    "query": "CTI_TransactionLog_CL\\n| summarize Success = countif(Status_s == \\"Success\\"), Failure = countif(Status_s == \\"Failure\\") by TargetSystem_s\\n| order by Success + Failure desc",
                    "size": 0,
                    "title": "IOC Dissemination Status by Target System",
                    "timeContext": {
                        "durationMs": 2592000000
                    },
                    "queryType": 0,
                    "resourceType": "microsoft.operationalinsights/workspaces",
                    "visualization": "barchart"
                },
                "name": "dissemination-status"
            }
        ],
        "styleSettings": {}
    }' > workbooks/ioc-dissemination.json
    echo "Created IOC Dissemination workbook."
fi

# Check Azure CLI login status
echo "Checking Azure CLI login status..."
SUBSCRIPTION_ID=$(az account show --query id -o tsv 2>/dev/null || echo "")

if [ -z "$SUBSCRIPTION_ID" ]; then
    echo "You need to log in to Azure first."
    az login
    SUBSCRIPTION_ID=$(az account show --query id -o tsv)
    echo "Logged in to subscription: $SUBSCRIPTION_ID"
else
    echo "Already logged in to subscription: $SUBSCRIPTION_ID"
fi

# Check if resource group exists, create if it doesn't
echo "Checking if resource group exists..."
if ! az group show --name "$RESOURCE_GROUP_NAME" &> /dev/null; then
    echo "Creating resource group $RESOURCE_GROUP_NAME in $LOCATION..."
    az group create --name "$RESOURCE_GROUP_NAME" --location "$LOCATION"
else
    echo "Resource group $RESOURCE_GROUP_NAME already exists."
fi

# Deploy the Bicep template
echo "Deploying CTI solution to resource group $RESOURCE_GROUP_NAME..."
az deployment group create \
  --name "$DEPLOYMENT_NAME" \
  --resource-group "$RESOURCE_GROUP_NAME" \
  --template-file main.bicep \
  --parameters \
    location="$LOCATION" \
    ctiWorkspaceName="$CTI_WORKSPACE_NAME" \
    ctiWorkspaceRetentionInDays="$CTI_WORKSPACE_RETENTION_DAYS" \
    ctiWorkspaceDailyQuotaGb="$CTI_WORKSPACE_DAILY_QUOTA_GB" \
    enableSentinelIntegration="$ENABLE_SENTINEL_INTEGRATION" \
    existingSentinelWorkspaceId="$EXISTING_SENTINEL_WORKSPACE_ID"

# Check if deployment was successful
if [ $? -eq 0 ]; then
    echo "✅ CTI solution deployment completed successfully."
    
    # Get workspace details
    CTI_WORKSPACE_ID=$(az deployment group show --name "$DEPLOYMENT_NAME" --resource-group "$RESOURCE_GROUP_NAME" --query "properties.outputs.ctiWorkspaceId.value" -o tsv)
    CTI_WORKSPACE_NAME=$(az deployment group show --name "$DEPLOYMENT_NAME" --resource-group "$RESOURCE_GROUP_NAME" --query "properties.outputs.ctiWorkspaceName.value" -o tsv)
    
    echo "CTI Workspace ID: $CTI_WORKSPACE_ID"
    echo "CTI Workspace Name: $CTI_WORKSPACE_NAME"
    
    echo ""
    echo "=================================================="
    echo "🎉 Deployment Complete!"
    echo "=================================================="
    echo ""
    echo "Next steps:"
    echo "1. Configure your TAXII feeds and API connectors in the Logic Apps"
    echo "   - Update the TAXII Connector Logic App with your TAXII server details"
    echo "   - Create API connections for your commercial feeds"
    echo ""
    echo "2. Customize workbooks for your environment"
    echo "   - Replace placeholder workbooks with more comprehensive dashboards"
    echo "   - Add additional visualizations for your specific use cases"
    echo ""
    echo "3. Set up API connections for Logic Apps"
    echo "   - Create connections to Log Analytics Data Collector API"
    echo "   - Set up authentication for Microsoft Defender for Endpoint API"
    echo "   - Configure connections to Exchange Online and other target systems"
    echo ""
    echo "4. Implement lifecycle management for your IOCs"
    echo "   - Set up purging of expired indicators"
    echo "   - Implement confidence score adjustment logic"
    echo ""
    echo "5. Configure cross-workspace analytics in Sentinel"
    echo "   - Create additional analytics rules for IOC matching"
    echo "   - Set up playbooks for automated response"
    echo ""
    
    # Offer to open the Azure portal
    read -p "Would you like to open the Azure portal to view the deployed resources? (y/n): " OPEN_PORTAL
    if [[ "$OPEN_PORTAL" == "y" || "$OPEN_PORTAL" == "Y" ]]; then
        az portal open --resource-group "$RESOURCE_GROUP_NAME"
    fi
else
    echo "❌ CTI solution deployment failed. Check the error messages above."
    exit 1
fi

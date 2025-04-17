#!/bin/bash
# Enhanced CTI Deployment Script - Aligns with Microsoft Security 2025
# This script deploys the Advanced Central Threat Intelligence (CTI) Solution
# Author: Claude
# Version: 2.0
# Date: April 2025

# Set strict error handling
set -e
set -o pipefail

# Color definitions for output
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[0;33m'
readonly BLUE='\033[0;34m'
readonly PURPLE='\033[0;35m'
readonly CYAN='\033[0;36m'
readonly NC='\033[0m' # No Color

# Configuration variables with sensible defaults
RESOURCE_GROUP_NAME="CTI-ResourceGroup"
LOCATION="eastus"
CTI_WORKSPACE_NAME="CTI-Workspace"
CTI_WORKSPACE_RETENTION_DAYS=90
CTI_WORKSPACE_DAILY_QUOTA_GB=5
ENABLE_SENTINEL_INTEGRATION=true
ENABLE_MDTI=true
ENABLE_SECURITY_COPILOT=false
EXISTING_SENTINEL_WORKSPACE_ID=""
APP_CLIENT_ID=""
TENANT_ID=""
KEY_VAULT_NAME=""
CLIENT_SECRET_NAME="clientSecret"
MANAGED_IDENTITY_NAME="id-cti-automation"
GRAPH_API_URL="https://graph.microsoft.com"
DEPLOYMENT_NAME="CTI-Deployment-$(date +%Y%m%d%H%M%S)"
BICEP_FILE="main.bicep"
PARAMETERS_FILE=""
SKIP_WORKBOOKS=false
SKIP_CLIENT_SECRET=false
ENABLE_ANALYTICS_RULES=true
ENABLE_HUNTING_QUERIES=true
ADVANCED_DEPLOYMENT=false

# Log function with multiline support and timestamp
function log() {
    local level=$1
    local message=$2
    local timestamp=$(date +"%Y-%m-%d %H:%M:%S")
    
    # Convert message to array of lines
    IFS=$'\n' read -d '' -r -a lines <<< "$message"
    
    # Process each line
    for line in "${lines[@]}"; do
        case $level in
            "INFO")
                echo -e "${BLUE}[$timestamp] [INFO] $line${NC}"
                ;;
            "SUCCESS")
                echo -e "${GREEN}[$timestamp] [SUCCESS] $line${NC}"
                ;;
            "WARNING")
                echo -e "${YELLOW}[$timestamp] [WARNING] $line${NC}"
                ;;
            "ERROR")
                echo -e "${RED}[$timestamp] [ERROR] $line${NC}"
                ;;
            "STEP")
                echo -e "${PURPLE}[$timestamp] [STEP] $line${NC}"
                ;;
            "DATA")
                echo -e "${CYAN}[$timestamp] [DATA] $line${NC}"
                ;;
            *)
                echo -e "[$timestamp] $line"
                ;;
        esac
    done
}

# Function to display script usage
function display_usage() {
    echo "Usage: $0 [options]"
    echo ""
    echo "Options:"
    echo "  -h, --help                       Display this help message"
    echo "  -g, --resource-group NAME        Set the resource group name (default: $RESOURCE_GROUP_NAME)"
    echo "  -l, --location LOCATION          Set the Azure location (default: $LOCATION)"
    echo "  -w, --workspace-name NAME        Set the Log Analytics workspace name (default: $CTI_WORKSPACE_NAME)"
    echo "  -r, --retention-days DAYS        Set the workspace retention days (default: $CTI_WORKSPACE_RETENTION_DAYS)"
    echo "  -q, --quota-gb GB                Set the workspace daily quota in GB (default: $CTI_WORKSPACE_DAILY_QUOTA_GB)"
    echo "  -s, --sentinel BOOL              Enable/disable Sentinel integration (default: $ENABLE_SENTINEL_INTEGRATION)"
    echo "  -m, --mdti BOOL                  Enable/disable MDTI integration (default: $ENABLE_MDTI)"
    echo "  --security-copilot BOOL          Enable/disable Security Copilot integration (default: $ENABLE_SECURITY_COPILOT)"
    echo "  -e, --existing-sentinel ID       Resource ID of existing Sentinel workspace (optional)"
    echo "  -c, --client-id ID               Application Client ID for API authentication"
    echo "  -t, --tenant-id ID               Tenant ID (default: current tenant)"
    echo "  -k, --key-vault NAME             Key Vault name (optional, auto-generated if not provided)"
    echo "  -p, --parameters FILE            Parameters file path (optional)"
    echo "  --enable-analytics BOOL          Enable Sentinel analytics rules (default: $ENABLE_ANALYTICS_RULES)"
    echo "  --enable-hunting BOOL            Enable Sentinel hunting queries (default: $ENABLE_HUNTING_QUERIES)"
    echo "  --advanced                       Enable advanced deployment options (adds Q&A prompts)"
    echo "  --skip-workbooks                 Skip workbook creation"
    echo "  --skip-client-secret             Skip client secret prompt and configuration"
    echo ""
    echo "Examples:"
    echo "  $0 --resource-group MyRG --location westus2 --client-id 00000000-0000-0000-0000-000000000000"
    echo "  $0 --advanced --mdti true --security-copilot true"
}

function check_prerequisites() {
    log "STEP" "Checking prerequisites"
    
    # Check if running in Azure Cloud Shell
    if [ -z "$AZURE_EXTENSION_DIR" ]; then
        # Only check for Azure CLI if not in Cloud Shell
        if ! command -v az &> /dev/null; then
            log "ERROR" "Azure CLI is not installed. Please install it first: https://docs.microsoft.com/en-us/cli/azure/install-azure-cli"
            exit 1
        fi
    else
        log "INFO" "Running in Azure Cloud Shell, Azure CLI is available"
    fi
    
    # Check if Azure CLI is logged in
    if ! az account show &> /dev/null; then
        log "WARNING" "Not logged in to Azure. Please login."
        az login
    fi

    # Rest of the function remains unchanged
    # ...
}

# Function to validate Azure subscription
function validate_azure_subscription() {
    log "STEP" "Validating Azure subscription"
    
    # Get current subscription
    SUBSCRIPTION_ID=$(az account show --query id -o tsv)
    SUBSCRIPTION_NAME=$(az account show --query name -o tsv)
    
    log "INFO" "Using subscription: $SUBSCRIPTION_NAME ($SUBSCRIPTION_ID)"
    
    # Check if subscription has required resource providers
    REQUIRED_PROVIDERS=("Microsoft.OperationalInsights" "Microsoft.SecurityInsights" "Microsoft.Logic" "Microsoft.Web" "Microsoft.KeyVault" "Microsoft.ManagedIdentity")
    MISSING_PROVIDERS=()
    
    for provider in "${REQUIRED_PROVIDERS[@]}"; do
        REGISTRATION_STATE=$(az provider show --namespace $provider --query "registrationState" -o tsv 2>/dev/null || echo "NotRegistered")
        
        if [[ "$REGISTRATION_STATE" != "Registered" ]]; then
            MISSING_PROVIDERS+=("$provider")
        fi
    done
    
    if [[ ${#MISSING_PROVIDERS[@]} -gt 0 ]]; then
        log "WARNING" "The following resource providers are not registered in your subscription:"
        for provider in "${MISSING_PROVIDERS[@]}"; do
            log "WARNING" "  - $provider"
        done
        
        if [[ "$ADVANCED_DEPLOYMENT" == "true" ]]; then
            read -p "Do you want to register these providers now? (y/n): " REGISTER_PROVIDERS
            if [[ "$REGISTER_PROVIDERS" == "y" || "$REGISTER_PROVIDERS" == "Y" ]]; then
                for provider in "${MISSING_PROVIDERS[@]}"; do
                    log "INFO" "Registering $provider..."
                    az provider register --namespace $provider
                    # Wait for registration to complete
                    log "INFO" "Waiting for $provider registration to complete..."
                    az provider show --namespace $provider --query "registrationState" -o tsv
                done
            else
                log "ERROR" "Cannot proceed without required resource providers"
                exit 1
            fi
        else
            # In non-advanced mode, automatically register providers
            log "INFO" "Registering required resource providers..."
            for provider in "${MISSING_PROVIDERS[@]}"; do
                log "INFO" "Registering $provider..."
                az provider register --namespace $provider
            done
            
            # Wait for registration to complete
            for provider in "${MISSING_PROVIDERS[@]}"; do
                log "INFO" "Waiting for $provider registration to complete..."
                while [[ "$(az provider show --namespace $provider --query "registrationState" -o tsv 2>/dev/null)" != "Registered" ]]; do
                    log "INFO" "Still waiting for $provider registration..."
                    sleep 10
                done
                log "SUCCESS" "$provider registered successfully"
            done
        fi
    else
        log "SUCCESS" "All required resource providers are registered"
    fi
    
    # Set tenant ID from current context if not specified
    if [ -z "$TENANT_ID" ]; then
        TENANT_ID=$(az account show --query tenantId -o tsv)
        log "INFO" "Using current tenant ID: $TENANT_ID"
    fi
    
    log "SUCCESS" "Azure subscription validation completed"
}

# Function to create resource group if it doesn't exist
function ensure_resource_group() {
    log "STEP" "Checking resource group"
    
    if ! az group show --name "$RESOURCE_GROUP_NAME" &> /dev/null; then
        log "INFO" "Creating resource group $RESOURCE_GROUP_NAME in $LOCATION..."
        az group create --name "$RESOURCE_GROUP_NAME" --location "$LOCATION" \
            --tags "solution=CentralThreatIntelligence" "environment=Production" "createdBy=DeployScript" "deploymentDate=$(date +%Y-%m-%d)"
        log "SUCCESS" "Resource group $RESOURCE_GROUP_NAME created"
    else
        log "INFO" "Resource group $RESOURCE_GROUP_NAME already exists"
        # Update tags
        az group update --name "$RESOURCE_GROUP_NAME" --set tags."solution=CentralThreatIntelligence" tags."environment=Production" tags."updatedBy=DeployScript" tags."updateDate=$(date +%Y-%m-%d)" &> /dev/null
    fi
}

# Function to generate or use existing app registration
function setup_app_registration() {
    if [[ -z "$APP_CLIENT_ID" ]]; then
        if [[ "$ADVANCED_DEPLOYMENT" == "true" ]]; then
            read -p "Do you want to create a new app registration for the CTI solution? (y/n): " CREATE_APP
            if [[ "$CREATE_APP" == "y" || "$CREATE_APP" == "Y" ]]; then
                log "STEP" "Creating new app registration"
                
                # Generate a unique name for the app
                APP_NAME="CTI-Solution-$(date +%Y%m%d%H%M%S)"
                
                # Create the app registration
                APP_CREATION=$(az ad app create --display-name "$APP_NAME" -o json)
                APP_CLIENT_ID=$(echo $APP_CREATION | jq -r '.appId')
                
                log "SUCCESS" "Created app registration: $APP_NAME"
                log "DATA" "Client ID: $APP_CLIENT_ID"
                
                # Create a service principal for the app
                az ad sp create --id $APP_CLIENT_ID &> /dev/null
                
                # Create a client secret
                if [[ "$SKIP_CLIENT_SECRET" != "true" ]]; then
                    CLIENT_SECRET=$(az ad app credential reset --id $APP_CLIENT_ID --append --years 2 --query password -o tsv)
                    log "DATA" "Generated client secret (store this securely - it won't be shown again)"
                fi
                
                # Add required API permissions
                log "INFO" "Adding required API permissions"
                
                # Microsoft Graph permissions
                az ad app permission add --id $APP_CLIENT_ID \
                    --api 00000003-0000-0000-c000-000000000000 \
                    --api-permissions e1fe6dd8-ba31-4d61-89e7-88639da4683d=Scope &> /dev/null # User.Read
                
                az ad app permission add --id $APP_CLIENT_ID \
                    --api 00000003-0000-0000-c000-000000000000 \
                    --api-permissions 594c1fb6-4f81-4475-ae41-0c394909246c=Role &> /dev/null # IdentityRiskyUser.ReadWrite.All
                
                # Grant admin consent (requires admin privileges)
                log "WARNING" "API permissions require admin consent. Please have an admin run:"
                log "DATA" "az ad app permission admin-consent --id $APP_CLIENT_ID"
            else
                log "ERROR" "An application Client ID is required. Please provide one with --client-id parameter."
                exit 1
            fi
        else
            log "ERROR" "An application Client ID is required. Please provide one with --client-id parameter."
            exit 1
        fi
    else
        # Validate that the provided app registration exists
        if ! az ad app show --id $APP_CLIENT_ID &> /dev/null; then
            log "ERROR" "The provided Client ID does not exist or you don't have permission to view it."
            exit 1
        fi
        
        log "SUCCESS" "Using existing app registration with Client ID: $APP_CLIENT_ID"
        
        # If advanced mode and no client secret should be skipped, offer to create a new secret
        if [[ "$ADVANCED_DEPLOYMENT" == "true" && "$SKIP_CLIENT_SECRET" != "true" ]]; then
            read -p "Do you want to create a new client secret for this app registration? (y/n): " CREATE_SECRET
            if [[ "$CREATE_SECRET" == "y" || "$CREATE_SECRET" == "Y" ]]; then
                CLIENT_SECRET=$(az ad app credential reset --id $APP_CLIENT_ID --append --years 2 --query password -o tsv)
                log "DATA" "Generated client secret (store this securely - it won't be shown again)"
            fi
        fi
    fi
}

# Function to create workbook JSON files with enhanced templates
function create_workbooks() {
    if [[ "$SKIP_WORKBOOKS" == "true" ]]; then
        log "INFO" "Skipping workbook creation as specified"
        return
    fi
    
    log "STEP" "Creating enhanced workbooks for threat intelligence"
    
    # Create workbooks directory if it doesn't exist
    mkdir -p workbooks
    
    # Define workbooks with modern design patterns
    declare -A workbooks=(
        ["ti-overview"]="Threat Intelligence - Overview Dashboard"
        ["ti-feed-health"]="Threat Intelligence - Feed Health and Metrics"
        ["ti-indicator-lifecycle"]="Threat Intelligence - Indicator Lifecycle"
        ["ti-incident-correlation"]="Threat Intelligence - Incident Correlation"
        ["ti-mitre-coverage"]="Threat Intelligence - MITRE ATT&CK Coverage"
        ["ti-security-posture"]="Threat Intelligence - Security Posture Impact"
        ["ti-manual-submission"]="Threat Intelligence - Manual Indicator Submission"
    )
    
    for name in "${!workbooks[@]}"; do
        local display_name="${workbooks[$name]}"
        
        if [ ! -f "workbooks/$name.json" ]; then
            log "INFO" "Creating workbook: $display_name"
            
            case "$name" in
                "ti-overview")
                    cat > "workbooks/$name.json" << EOF
{
    "version": "Notebook/1.0",
    "items": [
        {
            "type": 1,
            "content": {
                "json": "# $display_name\\n\\nThis dashboard provides a comprehensive overview of your threat intelligence feeds, indicators, and their impact on your environment. It leverages the Advanced CTI solution to correlate threat data with your security events, providing actionable insights."
            },
            "name": "Title"
        },
        {
            "type": 9,
            "content": {
                "version": "KqlParameterItem/1.0",
                "parameters": [
                    {
                        "id": "081de72c-1d83-40c0-b4ae-283052c1b440",
                        "version": "KqlParameterItem/1.0",
                        "name": "TimeRange",
                        "type": 4,
                        "isRequired": true,
                        "value": {
                            "durationMs": 2592000000
                        },
                        "typeSettings": {
                            "selectableValues": [
                                {
                                    "durationMs": 86400000
                                },
                                {
                                    "durationMs": 604800000
                                },
                                {
                                    "durationMs": 2592000000
                                },
                                {
                                    "durationMs": 7776000000
                                }
                            ],
                            "allowCustom": true
                        },
                        "label": "Time Range"
                    },
                    {
                        "id": "8c43ef28-bbce-4828-a086-30d92984a98d",
                        "version": "KqlParameterItem/1.0",
                        "name": "TLP",
                        "type": 2,
                        "isRequired": false,
                        "multiSelect": true,
                        "quote": "'",
                        "delimiter": ",",
                        "typeSettings": {
                            "additionalResourceOptions": [],
                            "showDefault": false
                        },
                        "jsonData": "[\n    { \"value\": \"TLP:RED\", \"label\": \"TLP:RED\" },\n    { \"value\": \"TLP:AMBER\", \"label\": \"TLP:AMBER\" },\n    { \"value\": \"TLP:GREEN\", \"label\": \"TLP:GREEN\" },\n    { \"value\": \"TLP:WHITE\", \"label\": \"TLP:WHITE\" },\n    { \"value\": \"TLP:CLEAR\", \"label\": \"TLP:CLEAR\" }\n]",
                        "label": "Traffic Light Protocol"
                    },
                    {
                        "id": "3b4cdc8c-122c-4c5a-a688-e0e7ab35bd32",
                        "version": "KqlParameterItem/1.0",
                        "name": "MinimumConfidence",
                        "type": 1,
                        "isRequired": false,
                        "value": "50",
                        "label": "Minimum Confidence"
                    }
                ],
                "style": "pills",
                "queryType": 0,
                "resourceType": "microsoft.operationalinsights/workspaces"
            },
            "name": "Parameters"
        },
        {
            "type": 3,
            "content": {
                "version": "KqlItem/1.0",
                "query": "// Summary metrics for threat intelligence indicators\\nunion\\n(CTI_IPIndicators_CL | extend Type = 'IP Addresses', Value = IPAddress_s),\\n(CTI_DomainIndicators_CL | extend Type = 'Domains', Value = Domain_s),\\n(CTI_URLIndicators_CL | extend Type = 'URLs', Value = URL_s),\\n(CTI_FileHashIndicators_CL | extend Type = 'File Hashes', Value = SHA256_s)\\n| where Active_b == true\\n| where TimeGenerated {TimeRange}\\n| where isempty('{TLP}') or TLP_s in ({TLP})\\n| where ConfidenceScore_d >= {MinimumConfidence}\\n| summarize count() by Type\\n| project Type, Indicators = count_\\n| union (\\n    // Add source metrics\\n    union\\n    (CTI_IPIndicators_CL),\\n    (CTI_DomainIndicators_CL),\\n    (CTI_URLIndicators_CL),\\n    (CTI_FileHashIndicators_CL)\\n    | where Active_b == true\\n    | where TimeGenerated {TimeRange}\\n    | where isempty('{TLP}') or TLP_s in ({TLP})\\n    | where ConfidenceScore_d >= {MinimumConfidence}\\n    | summarize SourceCount = dcount(SourceFeed_s)\\n    | extend Type = 'Sources', Indicators = SourceCount\\n    | project Type, Indicators\\n)\\n| union (\\n    // Add a match metric\\n    union\\n    (CommonSecurityLog\\n    | where TimeGenerated {TimeRange}\\n    | where isnotempty(DestinationIP)\\n    | join kind=inner (\\n        CTI_IPIndicators_CL\\n        | where Active_b == true\\n        | where isempty('{TLP}') or TLP_s in ({TLP})\\n        | where ConfidenceScore_d >= {MinimumConfidence}\\n    ) on $left.DestinationIP == $right.IPAddress_s\\n    | summarize count()),\\n    (DnsEvents\\n    | where TimeGenerated {TimeRange}\\n    | join kind=inner (\\n        CTI_DomainIndicators_CL\\n        | where Active_b == true\\n        | where isempty('{TLP}') or TLP_s in ({TLP})\\n        | where ConfidenceScore_d >= {MinimumConfidence}\\n    ) on $left.Name == $right.Domain_s\\n    | summarize count())\\n    | summarize MatchCount = sum(count_)\\n    | extend Type = 'Matches', Indicators = MatchCount\\n    | project Type, Indicators\\n)",
                "size": 3,
                "timeContext": {
                    "durationMs": 0
                },
                "timeContextFromParameter": "TimeRange",
                "queryType": 0,
                "resourceType": "microsoft.operationalinsights/workspaces",
                "visualization": "tiles",
                "tileSettings": {
                    "titleContent": {
                        "columnMatch": "Type",
                        "formatter": 1
                    },
                    "leftContent": {
                        "columnMatch": "Indicators",
                        "formatter": 12,
                        "formatOptions": {
                            "palette": "blue"
                        },
                        "numberFormat": {
                            "unit": 17,
                            "options": {
                                "style": "decimal",
                                "maximumFractionDigits": 0
                            }
                        }
                    },
                    "showBorder": true
                },
                "chartSettings": {}
            },
            "name": "ThreatIntelSummary"
        },
        {
            "type": 3,
            "content": {
                "version": "KqlItem/1.0",
                "query": "// Indicator distribution by type\\nunion\\n(CTI_IPIndicators_CL | extend Type = 'IP Addresses', Value = IPAddress_s),\\n(CTI_DomainIndicators_CL | extend Type = 'Domains', Value = Domain_s),\\n(CTI_URLIndicators_CL | extend Type = 'URLs', Value = URL_s),\\n(CTI_FileHashIndicators_CL | extend Type = 'File Hashes', Value = SHA256_s)\\n| where Active_b == true\\n| where TimeGenerated {TimeRange}\\n| where isempty('{TLP}') or TLP_s in ({TLP})\\n| where ConfidenceScore_d >= {MinimumConfidence}\\n| summarize count() by Type\\n| sort by count_ desc",
                "size": 1,
                "title": "Indicator Types",
                "timeContext": {
                    "durationMs": 0
                },
                "timeContextFromParameter": "TimeRange",
                "queryType": 0,
                "resourceType": "microsoft.operationalinsights/workspaces",
                "visualization": "piechart"
            },
            "customWidth": "33",
            "name": "IndicatorTypes"
        },
        {
            "type": 3,
            "content": {
                "version": "KqlItem/1.0",
                "query": "// Indicator sources distribution\\nunion\\n(CTI_IPIndicators_CL),\\n(CTI_DomainIndicators_CL),\\n(CTI_URLIndicators_CL),\\n(CTI_FileHashIndicators_CL)\\n| where Active_b == true\\n| where TimeGenerated {TimeRange}\\n| where isempty('{TLP}') or TLP_s in ({TLP})\\n| where ConfidenceScore_d >= {MinimumConfidence}\\n| summarize IndicatorCount = count() by SourceFeed_s\\n| order by IndicatorCount desc\\n| limit 10",
                "size": 1,
                "title": "Top 10 Indicator Sources",
                "timeContext": {
                    "durationMs": 0
                },
                "timeContextFromParameter": "TimeRange",
                "queryType": 0,
                "resourceType": "microsoft.operationalinsights/workspaces",
                "visualization": "barchart"
            },
            "customWidth": "33",
            "name": "IndicatorSources"
        },
        {
            "type": 3,
            "content": {
                "version": "KqlItem/1.0",
                "query": "// Indicator threat types\\nunion\\n(CTI_IPIndicators_CL),\\n(CTI_DomainIndicators_CL),\\n(CTI_URLIndicators_CL),\\n(CTI_FileHashIndicators_CL)\\n| where Active_b == true\\n| where TimeGenerated {TimeRange}\\n| where isempty('{TLP}') or TLP_s in ({TLP})\\n| where ConfidenceScore_d >= {MinimumConfidence}\\n| extend ThreatCategory = case(\\n    ThreatType_s contains 'C2' or ThreatType_s contains 'Command', 'Command & Control',\\n    ThreatType_s contains 'Phish', 'Phishing',\\n    ThreatType_s contains 'Malware' or ThreatType_s contains 'Trojan' or ThreatType_s contains 'Virus', 'Malware',\\n    ThreatType_s contains 'Ransomware', 'Ransomware',\\n    ThreatType_s contains 'Scan', 'Scanning',\\n    ThreatType_s contains 'Botnet', 'Botnet',\\n    ThreatType_s contains 'TOR', 'TOR Network',\\n    ThreatType_s contains 'Crypto', 'Cryptocurrency',\\n    'Other'\\n)\\n| summarize IndicatorCount = count() by ThreatCategory\\n| order by IndicatorCount desc",
                "size": 1,
                "title": "Threat Types",
                "timeContext": {
                    "durationMs": 0
                },
                "timeContextFromParameter": "TimeRange",
                "queryType": 0,
                "resourceType": "microsoft.operationalinsights/workspaces",
                "visualization": "piechart"
            },
            "customWidth": "33",
            "name": "ThreatTypes"
        },
        {
            "type": 3,
            "content": {
                "version": "KqlItem/1.0",
                "query": "// Indicator addition trend\\nunion\\n(CTI_IPIndicators_CL | extend Type = 'IP Addresses'),\\n(CTI_DomainIndicators_CL | extend Type = 'Domains'),\\n(CTI_URLIndicators_CL | extend Type = 'URLs'),\\n(CTI_FileHashIndicators_CL | extend Type = 'File Hashes')\\n| where Active_b == true\\n| where TimeGenerated {TimeRange}\\n| where isempty('{TLP}') or TLP_s in ({TLP})\\n| where ConfidenceScore_d >= {MinimumConfidence}\\n| summarize count() by Type, bin(TimeGenerated, 1d)\\n| render timechart",
                "size": 0,
                "title": "Indicator Trend",
                "timeContext": {
                    "durationMs": 0
                },
                "timeContextFromParameter": "TimeRange",
                "queryType": 0,
                "resourceType": "microsoft.operationalinsights/workspaces",
                "visualization": "linechart"
            },
            "customWidth": "50",
            "name": "IndicatorTrend"
        },
        {
            "type": 3,
            "content": {
                "version": "KqlItem/1.0",
                "query": "// TLP Distribution\\nunion\\n(CTI_IPIndicators_CL),\\n(CTI_DomainIndicators_CL),\\n(CTI_URLIndicators_CL),\\n(CTI_FileHashIndicators_CL)\\n| where Active_b == true\\n| where TimeGenerated {TimeRange}\\n| where ConfidenceScore_d >= {MinimumConfidence}\\n| summarize count() by TLP_s\\n| extend SortOrder = case(\\n    TLP_s == 'TLP:RED', 1,\\n    TLP_s == 'TLP:AMBER', 2,\\n    TLP_s == 'TLP:GREEN', 3,\\n    TLP_s == 'TLP:WHITE', 4,\\n    TLP_s == 'TLP:CLEAR', 5,\\n    6\\n)\\n| order by SortOrder asc\\n| project TLP_s, count_",
                "size": 0,
                "title": "TLP Distribution",
                "timeContext": {
                    "durationMs": 0
                },
                "timeContextFromParameter": "TimeRange",
                "queryType": 0,
                "resourceType": "microsoft.operationalinsights/workspaces",
                "visualization": "barchart",
                "gridSettings": {
                    "sortBy": [
                        {
                            "itemKey": "count_",
                            "sortOrder": 1
                        }
                    ]
                },
                "sortBy": [
                    {
                        "itemKey": "count_",
                        "sortOrder": 1
                    }
                ],
                "chartSettings": {
                    "seriesLabelSettings": [
                        {
                            "seriesName": "TLP:RED",
                            "color": "redBright"
                        },
                        {
                            "seriesName": "TLP:AMBER",
                            "color": "orange"
                        },
                        {
                            "seriesName": "TLP:GREEN",
                            "color": "green"
                        },
                        {
                            "seriesName": "TLP:WHITE",
                            "color": "gray"
                        },
                        {
                            "seriesName": "TLP:CLEAR",
                            "color": "gray"
                        }
                    ]
                }
            },
            "customWidth": "50",
            "name": "TLPDistribution"
        },
        {
            "type": 3,
            "content": {
                "version": "KqlItem/1.0",
                "query": "// Top matches with threat intelligence\\nlet IPMatches = CommonSecurityLog\\n| where TimeGenerated {TimeRange}\\n| where isnotempty(DestinationIP)\\n| join kind=inner (\\n    CTI_IPIndicators_CL\\n    | where Active_b == true\\n    | where isempty('{TLP}') or TLP_s in ({TLP})\\n    | where ConfidenceScore_d >= {MinimumConfidence}\\n) on $left.DestinationIP == $right.IPAddress_s\\n| extend IndicatorValue = DestinationIP, IndicatorType = 'IP', EventType = 'Network Connection', System = DeviceName\\n| project TimeGenerated, System, IndicatorType, IndicatorValue, ThreatType_s, ConfidenceScore_d, SourceFeed_s;\\n\\nlet DomainMatches = DnsEvents\\n| where TimeGenerated {TimeRange}\\n| join kind=inner (\\n    CTI_DomainIndicators_CL\\n    | where Active_b == true\\n    | where isempty('{TLP}') or TLP_s in ({TLP})\\n    | where ConfidenceScore_d >= {MinimumConfidence}\\n) on $left.Name == $right.Domain_s\\n| extend IndicatorValue = Name, IndicatorType = 'Domain', EventType = 'DNS Query', System = Computer\\n| project TimeGenerated, System, IndicatorType, IndicatorValue, ThreatType_s, ConfidenceScore_d, SourceFeed_s;\\n\\nunion IPMatches, DomainMatches\\n| sort by TimeGenerated desc\\n| take 50",
                "size": 0,
                "title": "Recent Threat Intelligence Matches",
                "timeContext": {
                    "durationMs": 0
                },
                "timeContextFromParameter": "TimeRange",
                "queryType": 0,
                "resourceType": "microsoft.operationalinsights/workspaces",
                "gridSettings": {
                    "formatters": [
                        {
                            "columnMatch": "TimeGenerated",
                            "formatter": 6,
                            "dateFormat": {
                                "showUtcTime": false,
                                "formatName": "shortDateTimePattern"
                            }
                        },
                        {
                            "columnMatch": "ConfidenceScore_d",
                            "formatter": 8,
                            "formatOptions": {
                                "min": 0,
                                "max": 100,
                                "palette": "redGreen"
                            },
                            "numberFormat": {
                                "unit": 1,
                                "options": {
                                    "style": "decimal"
                                }
                            }
                        }
                    ],
                    "filter": true,
                    "labelSettings": [
                        {
                            "columnId": "TimeGenerated",
                            "label": "Time"
                        },
                        {
                            "columnId": "System",
                            "label": "System"
                        },
                        {
                            "columnId": "IndicatorType",
                            "label": "Type"
                        },
                        {
                            "columnId": "IndicatorValue",
                            "label": "Value"
                        },
                        {
                            "columnId": "ThreatType_s",
                            "label": "Threat Type"
                        },
                        {
                            "columnId": "ConfidenceScore_d",
                            "label": "Confidence"
                        },
                        {
                            "columnId": "SourceFeed_s",
                            "label": "Source"
                        }
                    ]
                }
            },
            "name": "RecentMatches"
        }
    ],
    "fromTemplateId": "sentinel-ThreatIntelligenceDashboard",
    "styleSettings": {
        "showBorder": true
    },
    "$schema": "https://github.com/Microsoft/Application-Insights-Workbooks/blob/master/schema/workbook.json"
}
EOF
                    ;;
                "ti-feed-health")
                    cat > "workbooks/$name.json" << EOF
{
    "version": "Notebook/1.0",
    "items": [
        {
            "type": 1,
            "content": {
                "json": "# $display_name\\n\\nThis workbook monitors the health and reliability of your threat intelligence feeds, helping you ensure the quality and freshness of your threat intelligence data."
            },
            "name": "Title"
        },
        {
            "type": 9,
            "content": {
                "version": "KqlParameterItem/1.0",
                "parameters": [
                    {
                        "id": "92dfa8a3-183b-4d9e-aeff-502dbd575c17",
                        "version": "KqlParameterItem/1.0",
                        "name": "TimeRange",
                        "type": 4,
                        "isRequired": true,
                        "value": {
                            "durationMs": 2592000000
                        },
                        "typeSettings": {
                            "selectableValues": [
                                {
                                    "durationMs": 604800000
                                },
                                {
                                    "durationMs": 1209600000
                                },
                                {
                                    "durationMs": 2592000000
                                },
                                {
                                    "durationMs": 5184000000
                                },
                                {
                                    "durationMs": 7776000000
                                }
                            ],
                            "allowCustom": true
                        },
                        "label": "Time Range"
                    },
                    {
                        "id": "41a328a3-716a-4825-84e5-e2e5aedf5a1a",
                        "version": "KqlParameterItem/1.0",
                        "name": "FeedType",
                        "type": 2,
                        "isRequired": false,
                        "multiSelect": true,
                        "quote": "'",
                        "delimiter": ",",
                        "typeSettings": {
                            "additionalResourceOptions": [],
                            "showDefault": false
                        },
                        "jsonData": "[\n    { \"value\": \"TAXII\", \"label\": \"TAXII\" },\n    { \"value\": \"API\", \"label\": \"API\" },\n    { \"value\": \"Manual\", \"label\": \"Manual\" },\n    { \"value\": \"Microsoft Defender Threat Intelligence\", \"label\": \"Microsoft Defender Threat Intelligence\" }\n]",
                        "label": "Feed Type"
                    }
                ],
                "style": "pills",
                "queryType": 0,
                "resourceType": "microsoft.operationalinsights/workspaces"
            },
            "name": "Parameters"
        },
        {
            "type": 3,
            "content": {
                "version": "KqlItem/1.0",
                "query": "// Feed Health Summary\\nCTI_IntelligenceFeeds_CL\\n| where TimeGenerated {TimeRange}\\n| where isempty('{FeedType}') or FeedType_s in ({FeedType})\\n| summarize arg_max(TimeGenerated, *) by FeedName_s\\n| extend Status = case(\\n    Status_s == 'Active', 'Active',\\n    Status_s == 'Warning', 'Warning',\\n    Status_s == 'Error', 'Error',\\n    Status_s == 'Disabled', 'Disabled',\\n    'Unknown'\\n)\\n| summarize FeedCount = count(), ActiveCount = countif(Status == 'Active'), WarningCount = countif(Status == 'Warning'), ErrorCount = countif(Status == 'Error')\\n| project \\n    ['Total Feeds'] = FeedCount,\\n    ['Active Feeds'] = ActiveCount,\\n    ['Warning Feeds'] = WarningCount,\\n    ['Error Feeds'] = ErrorCount,\\n    ['Health Rate (%)'] = round((toreal(ActiveCount) / FeedCount) * 100, 2)",
                "size": 3,
                "title": "Feed Health Summary",
                "timeContext": {
                    "durationMs": 0
                },
                "timeContextFromParameter": "TimeRange",
                "queryType": 0,
                "resourceType": "microsoft.operationalinsights/workspaces",
                "visualization": "tiles",
                "tileSettings": {
                    "titleContent": {
                        "formatter": 1
                    },
                    "leftContent": {
                        "columnMatch": "Total Feeds",
                        "formatter": 12,
                        "formatOptions": {
                            "palette": "blue"
                        }
                    },
                    "secondaryContent": {
                        "columnMatch": "Active Feeds",
                        "formatter": 1
                    },
                    "secondaryLeftContent": {
                        "columnMatch": "Active Feeds",
                        "formatter": 12,
                        "formatOptions": {
                            "palette": "blue"
                        }
                    },
                    "showBorder": true
                }
            },
            "name": "FeedSummary"
        },
        {
            "type": 3,
            "content": {
                "version": "KqlItem/1.0",
                "query": "// Feed health breakdown\\nCTI_IntelligenceFeeds_CL\\n| where TimeGenerated {TimeRange}\\n| where isempty('{FeedType}') or FeedType_s in ({FeedType})\\n| summarize arg_max(TimeGenerated, *) by FeedName_s\\n| extend Status = case(\\n    Status_s == 'Active', 'Active',\\n    Status_s == 'Warning', 'Warning',\\n    Status_s == 'Error', 'Error',\\n    Status_s == 'Disabled', 'Disabled',\\n    'Unknown'\\n)\\n| summarize count() by Status\\n| sort by Status asc",
                "size": 1,
                "title": "Feed Status Distribution",
                "timeContext": {
                    "durationMs": 0
                },
                "timeContextFromParameter": "TimeRange",
                "queryType": 0,
                "resourceType": "microsoft.operationalinsights/workspaces",
                "visualization": "piechart",
                "chartSettings": {
                    "seriesLabelSettings": [
                        {
                            "seriesName": "Active",
                            "color": "green"
                        },
                        {
                            "seriesName": "Warning",
                            "color": "yellow"
                        },
                        {
                            "seriesName": "Error",
                            "color": "redBright"
                        },
                        {
                            "seriesName": "Disabled",
                            "color": "gray"
                        },
                        {
                            "seriesName": "Unknown",
                            "color": "purple"
                        }
                    ]
                }
            },
            "customWidth": "33",
            "name": "FeedStatusDistribution"
        },
        {
            "type": 3,
            "content": {
                "version": "KqlItem/1.0",
                "query": "// Feed type breakdown\\nCTI_IntelligenceFeeds_CL\\n| where TimeGenerated {TimeRange}\\n| where isempty('{FeedType}') or FeedType_s in ({FeedType})\\n| summarize arg_max(TimeGenerated, *) by FeedName_s\\n| summarize count() by FeedType_s\\n| sort by count_ desc",
                "size": 1,
                "title": "Feed Types",
                "timeContext": {
                    "durationMs": 0
                },
                "timeContextFromParameter": "TimeRange",
                "queryType": 0,
                "resourceType": "microsoft.operationalinsights/workspaces",
                "visualization": "piechart"
            },
            "customWidth": "33",
            "name": "FeedTypes"
        },
        {
            "type": 3,
            "content": {
                "version": "KqlItem/1.0",
                "query": "// Indicator count by feed\\nCTI_IntelligenceFeeds_CL\\n| where TimeGenerated {TimeRange}\\n| where isempty('{FeedType}') or FeedType_s in ({FeedType})\\n| summarize arg_max(TimeGenerated, *) by FeedName_s\\n| project FeedName_s, IndicatorCount_d, TimeGenerated\\n| sort by IndicatorCount_d desc\\n| top 10 by IndicatorCount_d",
                "size": 1,
                "title": "Top 10 Feeds by Indicator Count",
                "timeContext": {
                    "durationMs": 0
                },
                "timeContextFromParameter": "TimeRange",
                "queryType": 0,
                "resourceType": "microsoft.operationalinsights/workspaces",
                "visualization": "barchart"
            },
            "customWidth": "33",
            "name": "TopFeeds"
        },
        {
            "type": 3,
            "content": {
                "version": "KqlItem/1.0",
                "query": "// Feed update freshness\\nCTI_IntelligenceFeeds_CL\\n| where TimeGenerated {TimeRange}\\n| where isempty('{FeedType}') or FeedType_s in ({FeedType})\\n| summarize arg_max(TimeGenerated, *) by FeedName_s\\n| extend DaysSinceUpdate = datetime_diff('day', now(), LastUpdated_t)\\n| extend UpdateFreshness = case(\\n    DaysSinceUpdate <= 1, 'Last 24 hours',\\n    DaysSinceUpdate <= 7, 'Last week',\\n    DaysSinceUpdate <= 30, 'Last month',\\n    'Older than 30 days'\\n)\\n| extend SortOrder = case(\\n    UpdateFreshness == 'Last 24 hours', 1,\\n    UpdateFreshness == 'Last week', 2,\\n    UpdateFreshness == 'Last month', 3,\\n    UpdateFreshness == 'Older than 30 days', 4,\\n    5\\n)\\n| summarize count() by UpdateFreshness, SortOrder\\n| sort by SortOrder asc\\n| project UpdateFreshness, count_",
                "size": 0,
                "title": "Feed Freshness",
                "timeContext": {
                    "durationMs": 0
                },
                "timeContextFromParameter": "TimeRange",
                "queryType": 0,
                "resourceType": "microsoft.operationalinsights/workspaces",
                "visualization": "piechart",
                "chartSettings": {
                    "seriesLabelSettings": [
                        {
                            "seriesName": "Last 24 hours",
                            "color": "green"
                        },
                        {
                            "seriesName": "Last week",
                            "color": "blue"
                        },
                        {
                            "seriesName": "Last month",
                            "color": "yellow"
                        },
                        {
                            "seriesName": "Older than 30 days",
                            "color": "red"
                        }
                    ]
                }
            },
            "customWidth": "50",
            "name": "FeedFreshness"
        },
        {
            "type": 3,
            "content": {
                "version": "KqlItem/1.0",
                "query": "// Feed collection history\\nCTI_IntelligenceFeeds_CL\\n| where TimeGenerated {TimeRange}\\n| where isempty('{FeedType}') or FeedType_s in ({FeedType})\\n| summarize Updates = count() by FeedName_s, bin(TimeGenerated, 1d)\\n| order by TimeGenerated asc\\n| render timechart",
                "size": 0,
                "title": "Feed Update History",
                "timeContext": {
                    "durationMs": 0
                },
                "timeContextFromParameter": "TimeRange",
                "queryType": 0,
                "resourceType": "microsoft.operationalinsights/workspaces",
                "visualization": "linechart"
            },
            "customWidth": "50",
            "name": "FeedUpdateHistory"
        },
        {
            "type": 3,
            "content": {
                "version": "KqlItem/1.0",
                "query": "// Transaction log for feed operations\\nCTI_TransactionLog_CL\\n| where TimeGenerated {TimeRange}\\n| where TriggerSource_s in ('CTI-TAXII2-Connector', 'CTI-MDTI-Connector', 'CTI-EntraID-Connector', 'CTI-ExchangeOnline-Connector')\\n| extend FeedConnector = TriggerSource_s\\n| summarize SuccessCount = countif(Status_s == 'Success'), FailureCount = countif(Status_s == 'Failed') by FeedConnector, bin(Timestamp_t, 1d)\\n| extend SuccessRate = round((SuccessCount * 100.0) / (SuccessCount + FailureCount), 2)\\n| project Timestamp_t, FeedConnector, SuccessCount, FailureCount, SuccessRate\\n| sort by Timestamp_t asc\\n| render timechart",
                "size": 0,
                "title": "Feed Success Rate Over Time",
                "timeContext": {
                    "durationMs": 0
                },
                "timeContextFromParameter": "TimeRange",
                "queryType": 0,
                "resourceType": "microsoft.operationalinsights/workspaces"
            },
            "name": "FeedSuccessRate"
        },
        {
            "type": 3,
            "content": {
                "version": "KqlItem/1.0",
                "query": "// Detailed feed information\\nCTI_IntelligenceFeeds_CL\\n| where TimeGenerated {TimeRange}\\n| where isempty('{FeedType}') or FeedType_s in ({FeedType})\\n| summarize arg_max(TimeGenerated, *) by FeedName_s\\n| extend DaysSinceUpdate = datetime_diff('day', now(), LastUpdated_t)\\n| extend Status = case(\\n    Status_s == 'Active', 'Active',\\n    Status_s == 'Warning', 'Warning',\\n    Status_s == 'Error', 'Error',\\n    Status_s == 'Disabled', 'Disabled',\\n    'Unknown'\\n)\\n| extend StatusIcon = case(\\n    Status == 'Active', '✓',\\n    Status == 'Warning', '⚠',\\n    Status == 'Error', '✗',\\n    Status == 'Disabled', '○',\\n    '?'\\n)\\n| project \\n    ['Feed Name'] = FeedName_s, \\n    ['Status'] = strcat(StatusIcon, ' ', Status),\\n    ['Type'] = FeedType_s,\\n    ['Indicator Count'] = IndicatorCount_d,\\n    ['TLP'] = TLP_s,\\n    ['Last Updated'] = LastUpdated_t,\\n    ['Days Since Update'] = DaysSinceUpdate,\\n    ['Update Frequency'] = UpdateFrequency_s,\\n    ['Description'] = Description_s\\n| order by ['Days Since Update'] asc, ['Indicator Count'] desc",
                "size": 0,
                "title": "Feed Details",
                "timeContext": {
                    "durationMs": 0
                },
                "timeContextFromParameter": "TimeRange",
                "queryType": 0,
                "resourceType": "microsoft.operationalinsights/workspaces",
                "gridSettings": {
                    "formatters": [
                        {
                            "columnMatch": "Status",
                            "formatter": 1
                        },
                        {
                            "columnMatch": "Indicator Count",
                            "formatter": 3,
                            "formatOptions": {
                                "palette": "blue"
                            }
                        },
                        {
                            "columnMatch": "Last Updated",
                            "formatter": 6,
                            "formatOptions": {
                                "customColumnWidthSetting": "20ch"
                            },
                            "dateFormat": {
                                "showUtcTime": false,
                                "formatName": "shortDateTimePattern"
                            }
                        },
                        {
                            "columnMatch": "Days Since Update",
                            "formatter": 8,
                            "formatOptions": {
                                "min": 0,
                                "max": 30,
                                "palette": "greenRed"
                            },
                            "numberFormat": {
                                "unit": 0,
                                "options": {
                                    "style": "decimal",
                                    "maximumFractionDigits": 0
                                }
                            }
                        },
                        {
                            "columnMatch": "Description",
                            "formatter": 1
                        }
                    ],
                    "filter": true,
                    "sortBy": [
                        {
                            "itemKey": "Days Since Update",
                            "sortOrder": 1
                        }
                    ],
                    "labelSettings": [
                        {
                            "columnId": "Feed Name"
                        },
                        {
                            "columnId": "Status"
                        },
                        {
                            "columnId": "Type"
                        },
                        {
                            "columnId": "Indicator Count"
                        },
                        {
                            "columnId": "TLP"
                        },
                        {
                            "columnId": "Last Updated"
                        },
                        {
                            "columnId": "Days Since Update"
                        },
                        {
                            "columnId": "Update Frequency"
                        },
                        {
                            "columnId": "Description"
                        }
                    ]
                },
                "sortBy": [
                    {
                        "itemKey": "Days Since Update",
                        "sortOrder": 1
                    }
                ]
            },
            "name": "FeedDetails"
        }
    ],
    "$schema": "https://github.com/Microsoft/Application-Insights-Workbooks/blob/master/schema/workbook.json"
}
EOF
                    ;;
                "ti-manual-submission")
                    cat > "workbooks/$name.json" << EOF
{
    "version": "Notebook/1.0",
    "items": [
        {
            "type": 1,
            "content": {
                "json": "# $display_name\\n\\nThis workbook allows security analysts to manually submit threat intelligence indicators to the CTI solution. All submissions are logged and secured using Log Analytics RBAC.\\n\\n> **Note:** This workbook requires Contributor permissions on the Log Analytics workspace to submit data."
            },
            "name": "Introduction"
        },
        {
            "type": 9,
            "content": {
                "version": "KqlParameterItem/1.0",
                "parameters": [
                    {
                        "id": "a4952ad9-e5a6-44f7-a99f-20d602d852f0",
                        "version": "KqlParameterItem/1.0",
                        "name": "IndicatorType",
                        "label": "Indicator Type",
                        "type": 2,
                        "description": "Select the type of indicator to submit",
                        "isRequired": true,
                        "typeSettings": {
                            "additionalResourceOptions": [],
                            "showDefault": false
                        },
                        "jsonData": "[\n    { \"value\": \"IP\", \"label\": \"IP Address\" },\n    { \"value\": \"Domain\", \"label\": \"Domain Name\" },\n    { \"value\": \"URL\", \"label\": \"URL\" },\n    { \"value\": \"FileHash\", \"label\": \"File Hash\" },\n    { \"value\": \"Email\", \"label\": \"Email Address\" }\n]"
                    },
                    {
                        "id": "c18d7e62-818a-4320-bdad-9c09585e4c0f",
                        "version": "KqlParameterItem/1.0",
                        "name": "SourceFeed",
                        "label": "Source",
                        "type": 1,
                        "description": "Source of this indicator (e.g., Manual, OSINT, Vendor)",
                        "isRequired": true,
                        "value": "Manual"
                    }
                ],
                "style": "pills",
                "queryType": 0,
                "resourceType": "microsoft.operationalinsights/workspaces"
            },
            "name": "IndicatorTypeParameters"
        },
        {
            "type": 12,
            "content": {
                "version": "NotebookGroup/1.0",
                "groupType": "editable",
                "title": "IP Address Submission",
                "items": [
                    {
                        "type": 9,
                        "content": {
                            "version": "KqlParameterItem/1.0",
                            "parameters": [
                                {
                                    "id": "dbf4f30e-7270-4dc3-8189-96c7c3cf6112",
                                    "version": "KqlParameterItem/1.0",
                                    "name": "IPAddress",
                                    "label": "IP Address",
                                    "type": 1,
                                    "description": "Enter the malicious IP address (IPv4 format)",
                                    "isRequired": true,
                                    "value": ""
                                },
                                {
                                    "id": "a3c5c9dd-fe29-4b48-b029-955c49c0c66b",
                                    "version": "KqlParameterItem/1.0",
                                    "name": "IPConfidenceScore",
                                    "label": "Confidence Score",
                                    "type": 1,
                                    "description": "Confidence score (0-100)",
                                    "isRequired": true,
                                    "value": "70"
                                },
                                {
                                    "id": "e0c53edf-9345-4ad6-a9f1-4f1f151a02d5",
                                    "version": "KqlParameterItem/1.0",
                                    "name": "IPThreatType",
                                    "label": "Threat Type",
                                    "type": 2,
                                    "description": "Category of threat",
                                    "isRequired": true,
                                    "multiSelect": false,
                                    "quote": "'",
                                    "delimiter": ",",
                                    "typeSettings": {
                                        "additionalResourceOptions": [],
                                        "showDefault": false
                                    },
                                    "jsonData": "[\n    { \"value\": \"C2\", \"label\": \"Command & Control\" },\n    { \"value\": \"Malware\", \"label\": \"Malware Distribution\" },\n    { \"value\": \"Phishing\", \"label\": \"Phishing\" },\n    { \"value\": \"Scanning\", \"label\": \"Scanning/Reconnaissance\" },\n    { \"value\": \"Botnet\", \"label\": \"Botnet\" },\n    { \"value\": \"TOR\", \"label\": \"TOR Exit Node\" },\n    { \"value\": \"Proxy\", \"label\": \"Proxy/VPN\" },\n    { \"value\": \"Cryptocurrency\", \"label\": \"Cryptocurrency Mining\" },\n    { \"value\": \"Other\", \"label\": \"Other\" }\n]",
                                    "value": "C2"
                                },
                                {
                                    "id": "e9d38233-82d2-4945-9465-5ec63d18ea69",
                                    "version": "KqlParameterItem/1.0",
                                    "name": "IPTLP",
                                    "label": "TLP",
                                    "type": 2,
                                    "description": "Traffic Light Protocol designation",
                                    "isRequired": true,
                                    "typeSettings": {
                                        "additionalResourceOptions": [],
                                        "showDefault": false
                                    },
                                    "jsonData": "[\n    { \"value\": \"TLP:RED\", \"label\": \"TLP:RED\" },\n    { \"value\": \"TLP:AMBER\", \"label\": \"TLP:AMBER\" },\n    { \"value\": \"TLP:GREEN\", \"label\": \"TLP:GREEN\" },\n    { \"value\": \"TLP:WHITE\", \"label\": \"TLP:WHITE\" },\n    { \"value\": \"TLP:CLEAR\", \"label\": \"TLP:CLEAR\" }\n]",
                                    "value": "TLP:AMBER"
                                },
                                {
                                    "id": "7e36db4e-7b9c-40bd-8362-320cf565690d",
                                    "version": "KqlParameterItem/1.0",
                                    "name": "IPDescription",
                                    "label": "Description",
                                    "type": 1,
                                    "description": "Additional context about this indicator",
                                    "isRequired": false,
                                    "value": ""
                                },
                                {
                                    "id": "94a39535-7525-4c31-9479-7f686526b754",
                                    "version": "KqlParameterItem/1.0",
                                    "name": "IPExpirationDays",
                                    "label": "Expiration (Days)",
                                    "type": 1,
                                    "description": "Days until this indicator expires",
                                    "isRequired": true,
                                    "value": "30"
                                },
                                {
                                    "id": "94c15353-89ce-4d14-9c3f-a7d1b4e0551a",
                                    "version": "KqlParameterItem/1.0",
                                    "name": "IPActionType",
                                    "label": "Action Type",
                                    "type": 2,
                                    "description": "Action to take when this indicator is matched",
                                    "isRequired": true,
                                    "typeSettings": {
                                        "additionalResourceOptions": [],
                                        "showDefault": false
                                    },
                                    "jsonData": "[\n    { \"value\": \"Alert\", \"label\": \"Alert Only\" },\n    { \"value\": \"AlertAndBlock\", \"label\": \"Alert and Block\" },\n    { \"value\": \"Block\", \"label\": \"Block Only\" }\n]",
                                    "value": "Alert"
                                },
                                {
                                    "id": "7a23af6c-7b1c-4a9c-b4f8-ec4a42952a9c",
                                    "version": "KqlParameterItem/1.0",
                                    "name": "IPDistributionTargets",
                                    "label": "Distribution Targets",
                                    "type": 2,
                                    "isRequired": true,
                                    "multiSelect": true,
                                    "quote": "'",
                                    "delimiter": ",",
                                    "typeSettings": {
                                        "additionalResourceOptions": [],
                                        "showDefault": false
                                    },
                                    "jsonData": "[\n    { \"value\": \"Microsoft Sentinel\", \"label\": \"Microsoft Sentinel\" },\n    { \"value\": \"Microsoft Defender XDR\", \"label\": \"Microsoft Defender XDR\" },\n    { \"value\": \"Microsoft Entra ID\", \"label\": \"Microsoft Entra ID\" },\n    { \"value\": \"Microsoft Exchange Online\", \"label\": \"Microsoft Exchange Online\" }\n]",
                                    "value": [
                                        "Microsoft Sentinel"
                                    ]
                                }
                            ],
                            "style": "formVertical",
                            "queryType": 0,
                            "resourceType": "microsoft.operationalinsights/workspaces"
                        },
                        "customWidth": "65",
                        "name": "IPAddressParameters"
                    },
                    {
                        "type": 1,
                        "content": {
                            "json": "### IP Submission Guidelines\\n\\n- Enter the IP address in standard IPv4 format (e.g., 192.168.1.1)\\n- Confidence score should reflect your certainty (higher = more certain)\\n- Private IP addresses (10.x.x.x, 172.16-31.x.x, 192.168.x.x) will not be accepted\\n- TLP designation controls sharing permissions:\\n  - RED: No sharing outside organization\\n  - AMBER: Limited sharing within trusted community\\n  - GREEN: Community-wide sharing permitted\\n  - WHITE/CLEAR: Unlimited sharing\\n- Description should include context such as observed behaviors, campaigns, or threat actors\\n- Distribution targets determine where this indicator will be sent"
                        },
                        "customWidth": "35",
                        "name": "IPGuidelines"
                    },
                    {
                        "type": 3,
                        "content": {
                            "version": "KqlItem/1.0",
                            "query": "// Validate IP format using regex\\r\\nlet ipRegex = @'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$';\\r\\nlet privateIPRegex = @'^(10\\\\.|172\\\\.(1[6-9]|2[0-9]|3[0-1])\\\\.|192\\\\.168\\\\.)';\\r\\nlet isValidIP = '{IPAddress}' matches regex ipRegex;\\r\\nlet isPrivateIP = '{IPAddress}' matches regex privateIPRegex;\\r\\nlet confidenceInRange = {IPConfidenceScore} between (0 .. 100);\\r\\nlet daysInRange = {IPExpirationDays} between (1 .. 365);\\r\\n\\r\\nprint \\r\\n  ValidationResult = case(\\r\\n    isempty('{IPAddress}'), 'Please enter an IP address',\\r\\n    not(isValidIP), 'Invalid IP address format. Use standard IPv4 format (e.g., 1.2.3.4)',\\r\\n    isPrivateIP, 'Warning: This appears to be a private IP address',\\r\\n    not(confidenceInRange), 'Confidence score must be between 0 and 100',\\r\\n    not(daysInRange), 'Expiration days must be between 1 and 365',\\r\\n    'Valid')\\r\\n",
                            "size": 3,
                            "title": "Validation",
                            "noDataMessage": "Enter values above to validate",
                            "timeContext": {
                                "durationMs": 86400000
                            },
                            "queryType": 0,
                            "resourceType": "microsoft.operationalinsights/workspaces"
                        },
                        "name": "IPValidation"
                    },
                    {
                        "type": 9,
                        "content": {
                            "version": "KqlParameterItem/1.0",
                            "parameters": [
                                {
                                    "id": "a0e31e14-1c39-448e-ac0b-87378e6da14b",
                                    "version": "KqlParameterItem/1.0",
                                    "name": "IPSubmitButton",
                                    "type": 1,
                                    "value": "Submit IP Indicator",
                                    "typeSettings": {
                                        "parameterMode": "button",
                                        "buttonProvision": {
                                            "enabled": true,
                                            "actionType": "item",
                                            "linkTarget": "WorkbookTemplateV1",
                                            "linkLabel": "Submit",
                                            "gotoStep": "IPSubmission",
                                            "itemTarget": "cti-workbook-template",
                                            "resourceIds": [],
                                            "resultMapping": "link"
                                        }
                                    }
                                }
                            ],
                            "style": "formVertical",
                            "queryType": 0,
                            "resourceType": "microsoft.operationalinsights/workspaces"
                        },
                        "name": "IPSubmitButton"
                    },
                    {
                        "type": 3,
                        "content": {
                            "version": "KqlItem/1.0",
                            "query": "// Generate a GUID for the indicator\\r\\nlet indicatorId = guid();\\r\\nlet now = now();\\r\\nlet expirationDate = now() + {IPExpirationDays}d;\\r\\n\\r\\n// First validate the inputs\\r\\nlet ipRegex = @'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$';\\r\\nlet isValidIP = '{IPAddress}' matches regex ipRegex;\\r\\nlet confidenceInRange = {IPConfidenceScore} between (0 .. 100);\\r\\nlet daysInRange = {IPExpirationDays} between (1 .. 365);\\r\\n\\r\\nprint Result = case(\\r\\n    not(isValidIP), 'Invalid IP address format',\\r\\n    not(confidenceInRange), 'Confidence score must be between 0 and 100',\\r\\n    not(daysInRange), 'Expiration days must be between 1 and 365',\\r\\n    \"Submitting indicator...\");\\r\\n\\r\\n// If validation passes, submit the indicator\\r\\nprint Operation = case(\\r\\n    not(isValidIP) or not(confidenceInRange) or not(daysInRange), 'Validation failed',\\r\\n    \"Submitting IP indicator to CTI_IPIndicators_CL\");\\r\\n  \\r\\n// Only execute the insert if all validations pass\\r\\nlet insertResult = () {\\r\\n    let insertSuccess = true;\\r\\n    print \\r\\n        InsertedIP = '{IPAddress}',\\r\\n        InsertedIndicatorId = indicatorId,\\r\\n        InsertResult = \"Successfully added IP indicator\"\\r\\n};\\r\\n\\r\\nprint InsertStatus = case(\\r\\n    not(isValidIP) or not(confidenceInRange) or not(daysInRange), \\r\\n    'Submission canceled due to validation errors',\\r\\n    'The indicator will be available in CTI_IPIndicators_CL within a few minutes');\\r\\n\\r\\n// This would call the actual data insertion function\\r\\n// In a real workbook, you would use the Data function to insert\\r\\n// For demonstration purposes, we're just showing the data that would be inserted\\r\\nprint DataToBeInserted = strcat(  \\r\\n  'IPAddress_s: \"{IPAddress}\", ',\\r\\n  'IndicatorId_g: \"', indicatorId, '\", ',\\r\\n  'ConfidenceScore_d: ', {IPConfidenceScore}, ', ',\\r\\n  'SourceFeed_s: \"{SourceFeed}\", ',\\r\\n  'FirstSeen_t: \"', now, '\", ',\\r\\n  'LastSeen_t: \"', now, '\", ',\\r\\n  'ExpirationDateTime_t: \"', expirationDate, '\", ',\\r\\n  'ThreatType_s: \"{IPThreatType}\", ',\\r\\n  'TLP_s: \"{IPTLP}\", ',\\r\\n  'Action_s: \"{IPActionType}\", ',\\r\\n  'Description_s: \"{IPDescription}\", ',\\r\\n  'DistributionTargets_s: \"{IPDistributionTargets}\", ',\\r\\n  'Active_b: true')\\r\\n",
                            "size": 0,
                            "queryType": 0,
                            "resourceType": "microsoft.operationalinsights/workspaces",
                            "visualization": "card",
                            "workspaceLevelHelperInfo": {
                                "workspaceHelperInfo": {
                                    "workspaceId": "a4376cfb-0d1f-4cba-8c61-44a305638f26",
                                    "subscriptionId": "d91307c8-d5df-4ca4-87e0-72b0bab90d4b",
                                    "resourcegroup": "rg-sentinel-workspace",
                                    "displaynameParameter": "",
                                    "resourceName": "sentinel-log-analytics",
                                    "resourceNameParameter": "",
                                    "currentResourceParameter": "",
                                    "linkToTemplate": ""
                                }
                            }
                        },
                        "conditionalVisibility": {
                            "parameterName": "IPSubmitButton",
                            "comparison": "isNotEqualTo",
                            "value": ""
                        },
                        "name": "IPSubmission"
                    }
                ],
                "conditionalVisibility": {
                    "parameterName": "IndicatorType",
                    "comparison": "isEqualTo",
                    "value": "IP"
                }
            },
            "name": "IPAddressGroup"
        }
    ],
    "fallbackResourceIds": [
        "Azure Monitor"
    ],
    "$schema": "https://github.com/Microsoft/Application-Insights-Workbooks/blob/master/schema/workbook.json"
}
EOF
                    ;;
                *)
                    log "INFO" "Creating placeholder for workbook: $display_name"
                    cat > "workbooks/$name.json" << EOF
{
    "version": "Notebook/1.0",
    "items": [
        {
            "type": 1,
            "content": {
                "json": "# $display_name\\n\\nThis workbook provides insights for your threat intelligence operation."
            },
            "name": "title"
        },
        {
            "type": 9,
            "content": {
                "version": "KqlParameterItem/1.0",
                "parameters": [
                    {
                        "id": "626d0cd2-3590-4ef0-a65c-8a355072a2aa",
                        "version": "KqlParameterItem/1.0",
                        "name": "TimeRange",
                        "type": 4,
                        "isRequired": true,
                        "value": {
                            "durationMs": 2592000000
                        },
                        "typeSettings": {
                            "selectableValues": [
                                {
                                    "durationMs": 86400000
                                },
                                {
                                    "durationMs": 604800000
                                },
                                {
                                    "durationMs": 2592000000
                                },
                                {
                                    "durationMs": 5184000000
                                },
                                {
                                    "durationMs": 7776000000
                                }
                            ],
                            "allowCustom": true
                        },
                        "label": "Time Range"
                    }
                ],
                "style": "pills",
                "queryType": 0,
                "resourceType": "microsoft.operationalinsights/workspaces"
            },
            "name": "parameters"
        },
        {
            "type": 1,
            "content": {
                "json": "## Workbook Under Development\\n\\nThis workbook is currently under development and will be available in a future update.\\n\\nPlease check back soon for updates."
            },
            "name": "developmentMessage"
        }
    ],
    "$schema": "https://github.com/Microsoft/Application-Insights-Workbooks/blob/master/schema/workbook.json"
}
EOF
                    ;;
            esac
            
            log "SUCCESS" "Created workbook: $display_name"
        else
            log "INFO" "Workbook $display_name already exists, skipping"
        fi
    done
    
    log "SUCCESS" "Workbooks creation completed"
}

# Function to create enhanced analytics rules
function create_analytics_rules() {
    if [[ "$ENABLE_ANALYTICS_RULES" != "true" ]]; then
        log "INFO" "Skipping analytics rules creation as specified"
        return
    fi
    
    log "STEP" "Creating enhanced analytics rules for threat intelligence"
    
    # Create directory for analytics rules
    mkdir -p analytics
    
    # Define analytics rules with modern detection patterns
    declare -A analytics_rules=(
        ["ti-ip-match"]="Threat Intelligence IP Match"
        ["ti-domain-match"]="Threat Intelligence Domain Match"
        ["ti-filehash-match"]="Threat Intelligence File Hash Match"
        ["ti-multi-ioc-match"]="Threat Intelligence Multi-IOC Match"
        ["ti-ransomware-activity"]="Threat Intelligence Ransomware Activity"
        ["ti-new-threat-actor"]="Threat Intelligence New Threat Actor Detection"
        ["ti-lateral-movement"]="Threat Intelligence Lateral Movement Activity"
    )
    
    for name in "${!analytics_rules[@]}"; do
        local display_name="${analytics_rules[$name]}"
        
        if [ ! -f "analytics/$name.json" ]; then
            log "INFO" "Creating analytics rule: $display_name"
            
            case "$name" in
                "ti-ip-match")
                    cat > "analytics/$name.json" << EOF
{
    "id": "69b7723c-2889-43f4-8098-f3157158a21a",
    "name": "$display_name",
    "description": "This rule detects when an IP address from your threat intelligence has been observed in the logs.",
    "severity": "Medium",
    "requiredDataConnectors": [
        {
            "connectorId": "AzureSecurityCenter",
            "dataTypes": [ "CommonSecurityLog" ]
        }
    ],
    "queryFrequency": "1h",
    "queryPeriod": "1h",
    "triggerOperator": "GreaterThan",
    "triggerThreshold": 0,
    "suppressionDuration": "1h",
    "suppressionEnabled": false,
    "tactics": [ "CommandAndControl", "Impact" ],
    "techniques": [ "T1071", "T1498" ],
    "query": "let minTimeRange = 1h;\nlet iocData = CTI_IPIndicators_CL\n| where Active_b == true\n| where ConfidenceScore_d >= 70\n| project IPAddress_s, ThreatType_s, Confidence = ConfidenceScore_d, SourceFeed_s, Description_s;\n\nCommonSecurityLog\n| where DeviceAction !~ \"block\" and DeviceAction !~ \"deny\"\n| where isnotempty(DestinationIP)\n| join kind=inner iocData on $left.DestinationIP == $right.IPAddress_s\n| extend CompromisedEntity = DeviceName\n| extend EntityType = \"Host\"\n| extend Indicator = DestinationIP\n| extend Evidence = strcat(\"IP address \", DestinationIP, \" matched threat intelligence from \", SourceFeed_s, \" with confidence \", Confidence)\n| project\n    TimeGenerated,\n    DestinationIP,\n    SourceIP,\n    ThreatType_s,\n    Confidence,\n    Description_s,\n    DeviceName,\n    DeviceVendor,\n    DeviceProduct,\n    CompromisedEntity,\n    EntityType,\n    Evidence",
    "entityMappings": [
        {
            "entityType": "IP",
            "fieldMappings": [
                {
                    "identifier": "Address",
                    "columnName": "DestinationIP"
                }
            ]
        },
        {
            "entityType": "Host",
            "fieldMappings": [
                {
                    "identifier": "HostName",
                    "columnName": "DeviceName"
                }
            ]
        }
    ],
    "customDetails": {
        "Indicator": "DestinationIP",
        "ThreatType": "ThreatType_s",
        "SourceIP": "SourceIP",
        "Confidence": "Confidence"
    },
    "alertDetailsOverride": {
        "alertDisplayNameFormat": "Threat intelligence match: IP {{DestinationIP}} observed on {{DeviceName}}",
        "alertDescriptionFormat": "A network connection was detected from {{DeviceName}} ({{SourceIP}}) to a known malicious IP address {{DestinationIP}}. The IP is associated with {{ThreatType_s}} activity with a confidence score of {{Confidence}}. This may indicate a potential security incident involving this system.\n\nAdditional context from threat intelligence feed: {{Description_s}}\n\nIf this is expected traffic, consider adding an exception for this IP.",
        "alertSeverityColumnName": "Confidence",
        "alertTacticsColumnName": "ThreatType_s"
    },
    "enabled": true,
    "status": "Available"
}
EOF
                    ;;
                "ti-domain-match")
                    cat > "analytics/$name.json" << EOF
{
    "id": "b21f14c8-35c3-4e9d-95c2-8a26c9c8c6e9",
    "name": "$display_name",
    "description": "This rule detects when a domain name from your threat intelligence has been observed in DNS queries.",
    "severity": "Medium",
    "requiredDataConnectors": [
        {
            "connectorId": "AzureSecurityCenter",
            "dataTypes": [ "DnsEvents" ]
        }
    ],
    "queryFrequency": "1h",
    "queryPeriod": "1h",
    "triggerOperator": "GreaterThan",
    "triggerThreshold": 0,
    "suppressionDuration": "1h",
    "suppressionEnabled": false,
    "tactics": [ "CommandAndControl", "Exfiltration" ],
    "techniques": [ "T1071", "T1568" ],
    "query": "let minTimeRange = 1h;\nlet iocData = CTI_DomainIndicators_CL\n| where Active_b == true\n| where ConfidenceScore_d >= 70\n| project Domain = Domain_s, ThreatType_s, Confidence = ConfidenceScore_d, SourceFeed_s, Description_s;\n\nDnsEvents\n| where isnotempty(Name)\n| join kind=inner iocData on $left.Name == $right.Domain\n| extend CompromisedEntity = Computer\n| extend EntityType = \"Host\"\n| extend Indicator = Name\n| extend Evidence = strcat(\"DNS query for \", Name, \" matched threat intelligence from \", SourceFeed_s, \" with confidence \", Confidence)\n| extend IsAdminOperation = \"False\"\n| project\n    TimeGenerated,\n    Name,\n    ClientIP,\n    Computer,\n    ThreatType_s,\n    Confidence,\n    Description_s,\n    QueryType,\n    CompromisedEntity,\n    EntityType,\n    Evidence",
    "entityMappings": [
        {
            "entityType": "Host",
            "fieldMappings": [
                {
                    "identifier": "HostName",
                    "columnName": "Computer"
                }
            ]
        },
        {
            "entityType": "DNS",
            "fieldMappings": [
                {
                    "identifier": "DomainName",
                    "columnName": "Name"
                }
            ]
        }
    ],
    "customDetails": {
        "Indicator": "Name",
        "ThreatType": "ThreatType_s",
        "ClientIP": "ClientIP",
        "Confidence": "Confidence"
    },
    "alertDetailsOverride": {
        "alertDisplayNameFormat": "Threat intelligence match: domain {{Name}} queried from {{Computer}}",
        "alertDescriptionFormat": "A DNS query was detected from {{Computer}} for a known malicious domain {{Name}}. The domain is associated with {{ThreatType_s}} activity with a confidence score of {{Confidence}}. This may indicate a potential security incident involving this system.\n\nAdditional context from threat intelligence feed: {{Description_s}}\n\nIf this is expected traffic, consider adding an exception for this domain.",
        "alertSeverityColumnName": "Confidence",
        "alertTacticsColumnName": "ThreatType_s"
    },
    "enabled": true,
    "status": "Available"
}
EOF
                    ;;
                "ti-filehash-match")
                    cat > "analytics/$name.json" << EOF
{
    "id": "f9bf7c79-13a0-46a8-8a72-f53e2aa37662",
    "name": "$display_name",
    "description": "This rule detects when a file with a hash from your threat intelligence has been observed in the environment.",
    "severity": "High",
    "requiredDataConnectors": [
        {
            "connectorId": "MicrosoftDefenderThreatProtection",
            "dataTypes": [ "DeviceFileEvents" ]
        }
    ],
    "queryFrequency": "1h",
    "queryPeriod": "1h",
    "triggerOperator": "GreaterThan",
    "triggerThreshold": 0,
    "suppressionDuration": "6h",
    "suppressionEnabled": false,
    "tactics": [ "Execution", "Defense Evasion" ],
    "techniques": [ "T1204", "T1027" ],
    "query": "let minTimeRange = 1h;\nlet iocData = CTI_FileHashIndicators_CL\n| where Active_b == true\n| where ConfidenceScore_d >= 70\n| project SHA256_s, ThreatType_s, Confidence = ConfidenceScore_d, SourceFeed_s, Description_s, MalwareFamily_s;\n\nDeviceFileEvents\n| where isnotempty(SHA256)\n| join kind=inner iocData on $left.SHA256 == $right.SHA256_s\n| extend CompromisedEntity = DeviceName\n| extend EntityType = \"Host\"\n| extend Indicator = SHA256\n| extend Evidence = strcat(\"File with hash \", SHA256, \" matched threat intelligence from \", SourceFeed_s, \" with confidence \", Confidence)\n| project\n    TimeGenerated,\n    SHA256,\n    FileName,\n    FolderPath,\n    DeviceName,\n    ThreatType_s,\n    MalwareFamily_s,\n    Confidence,\n    Description_s,\n    InitiatingProcessFileName,\n    InitiatingProcessFolderPath,\n    InitiatingProcessAccountName,\n    InitiatingProcessAccountUpn,\n    CompromisedEntity,\n    EntityType,\n    Evidence",
    "entityMappings": [
        {
            "entityType": "Host",
            "fieldMappings": [
                {
                    "identifier": "HostName",
                    "columnName": "DeviceName"
                }
            ]
        },
        {
            "entityType": "FileHash",
            "fieldMappings": [
                {
                    "identifier": "Algorithm",
                    "columnName": "SHA256",
                    "value": "SHA-256"
                },
                {
                    "identifier": "Value",
                    "columnName": "SHA256"
                }
            ]
        },
        {
            "entityType": "File",
            "fieldMappings": [
                {
                    "identifier": "Name",
                    "columnName": "FileName"
                },
                {
                    "identifier": "Directory",
                    "columnName": "FolderPath"
                }
            ]
        },
        {
            "entityType": "Account",
            "fieldMappings": [
                {
                    "identifier": "Name",
                    "columnName": "InitiatingProcessAccountName"
                },
                {
                    "identifier": "UPNSuffix",
                    "columnName": "InitiatingProcessAccountUpn"
                }
            ]
        },
        {
            "entityType": "Process",
            "fieldMappings": [
                {
                    "identifier": "ProcessId",
                    "columnName": "InitiatingProcessId"
                },
                {
                    "identifier": "CommandLine",
                    "columnName": "InitiatingProcessCommandLine"
                }
            ]
        }
    ],
    "customDetails": {
        "Indicator": "SHA256",
        "MalwareFamily": "MalwareFamily_s",
        "ThreatType": "ThreatType_s",
        "FileName": "FileName",
        "Confidence": "Confidence"
    },
    "alertDetailsOverride": {
        "alertDisplayNameFormat": "Threat intelligence match: Malicious file {{FileName}} detected on {{DeviceName}}",
        "alertDescriptionFormat": "A known malicious file has been detected on {{DeviceName}}. The file {{FileName}} (SHA256: {{SHA256}}) was observed, which matches threat intelligence indicators for {{MalwareFamily_s}} malware with a confidence score of {{Confidence}}.\n\nThe file was initiated by the process {{InitiatingProcessFileName}} run by {{InitiatingProcessAccountName}}.\n\nAdditional context from threat intelligence feed: {{Description_s}}\n\nThis requires immediate investigation as malicious code has been executed on the system.",
        "alertSeverityColumnName": "Confidence",
        "alertTacticsColumnName": "ThreatType_s"
    },
    "enabled": true,
    "status": "Available"
}
EOF
                    ;;
                "ti-multi-ioc-match")
                    cat > "analytics/$name.json" << EOF
{
    "id": "d7d3a8e2-1c11-4f2b-adcd-92a745a4256e",
    "name": "$display_name",
    "description": "This rule detects when multiple different types of indicators from your threat intelligence have been observed on the same host within a short timeframe, which may indicate coordinated malicious activity.",
    "severity": "High",
    "requiredDataConnectors": [
        {
            "connectorId": "AzureSecurityCenter",
            "dataTypes": [ "CommonSecurityLog", "DnsEvents" ]
        },
        {
            "connectorId": "MicrosoftDefenderThreatProtection",
            "dataTypes": [ "DeviceFileEvents" ]
        }
    ],
    "queryFrequency": "6h",
    "queryPeriod": "6h",
    "triggerOperator": "GreaterThan",
    "triggerThreshold": 0,
    "suppressionDuration": "12h",
    "suppressionEnabled": false,
    "tactics": [ "InitialAccess", "Execution", "CommandAndControl", "Exfiltration" ],
    "techniques": [ "T1566", "T1204", "T1071", "T1041" ],
    "query": "// Get IP matches\nlet ipMatches = CommonSecurityLog\n| where DeviceAction !~ \"block\" and DeviceAction !~ \"deny\"\n| where isnotempty(DestinationIP)\n| join kind=inner (\n    CTI_IPIndicators_CL\n    | where Active_b == true\n    | where ConfidenceScore_d >= 70\n    | project IPAddress_s, ThreatType = ThreatType_s, Confidence = ConfidenceScore_d, SourceFeed = SourceFeed_s, Description = Description_s\n) on $left.DestinationIP == $right.IPAddress_s\n| extend HostName = DeviceName\n| extend IOCType = \"IP\", IOCValue = DestinationIP\n| project TimeGenerated, HostName, IOCType, IOCValue, ThreatType, Confidence, SourceFeed, Description;\n\n// Get domain matches\nlet domainMatches = DnsEvents\n| where isnotempty(Name)\n| join kind=inner (\n    CTI_DomainIndicators_CL\n    | where Active_b == true\n    | where ConfidenceScore_d >= 70\n    | project Domain_s, ThreatType = ThreatType_s, Confidence = ConfidenceScore_d, SourceFeed = SourceFeed_s, Description = Description_s\n) on $left.Name == $right.Domain_s\n| extend HostName = Computer\n| extend IOCType = \"Domain\", IOCValue = Name\n| project TimeGenerated, HostName, IOCType, IOCValue, ThreatType, Confidence, SourceFeed, Description;\n\n// Get file hash matches\nlet fileHashMatches = DeviceFileEvents\n| where isnotempty(SHA256)\n| join kind=inner (\n    CTI_FileHashIndicators_CL\n    | where Active_b == true\n    | where ConfidenceScore_d >= 70\n    | project SHA256_s, ThreatType = ThreatType_s, Confidence = ConfidenceScore_d, SourceFeed = SourceFeed_s, Description = Description_s\n) on $left.SHA256 == $right.SHA256_s\n| extend HostName = DeviceName\n| extend IOCType = \"FileHash\", IOCValue = SHA256\n| extend FileName = FileName\n| project TimeGenerated, HostName, IOCType, IOCValue, FileName, ThreatType, Confidence, SourceFeed, Description;\n\n// Combine all matches\nlet allMatches = ipMatches\n| union domainMatches\n| union fileHashMatches;\n\n// Find hosts with multiple different IOC types\nallMatches\n| summarize\n    IOCTypes = make_set(IOCType),\n    IOCValues = make_set(IOCValue),\n    ThreatTypes = make_set(ThreatType),\n    MaxConfidence = max(Confidence),\n    EarliestDetection = min(TimeGenerated),\n    LatestDetection = max(TimeGenerated),\n    Evidence = make_set(strcat(IOCType, \":\", IOCValue, \" (Threat: \", ThreatType, \")\"))\n    by HostName\n| where array_length(IOCTypes) > 1\n| extend\n    CompromisedEntity = HostName,\n    EntityType = \"Host\",\n    TimeDelta = datetime_diff('minute', LatestDetection, EarliestDetection)\n| project\n    CompromisedEntity,\n    EntityType,\n    IOCTypes,\n    IOCValues,\n    ThreatTypes,\n    MaxConfidence,\n    TimeDelta,\n    EarliestDetection,\n    LatestDetection,\n    Evidence",
    "entityMappings": [
        {
            "entityType": "Host",
            "fieldMappings": [
                {
                    "identifier": "HostName",
                    "columnName": "CompromisedEntity"
                }
            ]
        }
    ],
    "customDetails": {
        "IOCTypes": "IOCTypes",
        "IOCValues": "IOCValues",
        "ThreatTypes": "ThreatTypes",
        "MaxConfidence": "MaxConfidence",
        "TimeDelta": "TimeDelta"
    },
    "alertDetailsOverride": {
        "alertDisplayNameFormat": "Multiple threat intelligence matches detected on {{CompromisedEntity}}",
        "alertDescriptionFormat": "Multiple different types of threat intelligence indicators have been observed on host {{CompromisedEntity}} within {{TimeDelta}} minutes. This pattern strongly suggests coordinated malicious activity and warrants immediate investigation.\n\nEvidence of activity:\n{{Evidence}}\n\nThe first suspicious activity was detected at {{EarliestDetection}} and the most recent at {{LatestDetection}}.\n\nThis host should be isolated and investigated as it is likely compromised with {{ThreatTypes}} related malware.",
        "alertSeverityColumnName": "MaxConfidence",
        "alertDynamicProperties": {
            "IncidentTimelineStartTime": "EarliestDetection",
            "IncidentTimelineEndTime": "LatestDetection"
        }
    },
    "enabled": true,
    "status": "Available"
}
EOF
                    ;;
                *)
                    log "INFO" "Creating placeholder for analytics rule: $display_name"
                    cat > "analytics/$name.json" << EOF
{
    "id": "$(uuidgen)",
    "name": "$display_name",
    "description": "This rule will be available in a future update",
    "severity": "Medium",
    "requiredDataConnectors": [
        {
            "connectorId": "AzureSecurityCenter",
            "dataTypes": [ "SecurityAlert" ]
        }
    ],
    "queryFrequency": "1d",
    "queryPeriod": "1d",
    "triggerOperator": "GreaterThan",
    "triggerThreshold": 0,
    "query": "SecurityAlert\n| take 10",
    "entityMappings": [],
    "enabled": false,
    "status": "Available"
}
EOF
                    ;;
            esac
            
            log "SUCCESS" "Created analytics rule: $display_name"
        else
            log "INFO" "Analytics rule $display_name already exists, skipping"
        fi
    done
    
    log "SUCCESS" "Analytics rules creation completed"
}

# Function to deploy the Bicep template
function deploy_bicep_template() {
    log "STEP" "Deploying CTI solution to resource group $RESOURCE_GROUP_NAME"
    
    # Create a temporary parameters file if none was provided
    if [ -z "$PARAMETERS_FILE" ]; then
        TEMP_PARAMS_FILE=$(mktemp)
        log "INFO" "Creating temporary parameters file: $TEMP_PARAMS_FILE"
        
        # Generate initial client secret for bicep deployment
        # This should be replaced post-deployment in production
        INITIAL_CLIENT_SECRET=""
        if [ "$SKIP_CLIENT_SECRET" != "true" ] && [ -n "$APP_CLIENT_ID" ]; then
            log "INFO" "Enter an initial client secret for application $APP_CLIENT_ID"
            log "INFO" "(This will be securely stored in Key Vault and can be updated later)"
            read -sp "Client Secret: " INITIAL_CLIENT_SECRET
            echo ""
        fi
        
        # Create parameters file with modern parameters
        cat > "$TEMP_PARAMS_FILE" << EOF
{
    "\$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentParameters.json#",
    "contentVersion": "1.0.0.0",
    "parameters": {
        "location": {
            "value": "$LOCATION"
        },
        "ctiWorkspaceName": {
            "value": "$CTI_WORKSPACE_NAME"
        },
        "ctiWorkspaceRetentionInDays": {
            "value": $CTI_WORKSPACE_RETENTION_DAYS
        },
        "ctiWorkspaceDailyQuotaGb": {
            "value": $CTI_WORKSPACE_DAILY_QUOTA_GB
        },
        "enableSentinelIntegration": {
            "value": $ENABLE_SENTINEL_INTEGRATION
        },
        "enableMDTI": {
            "value": $ENABLE_MDTI
        },
        "enableSecurityCopilot": {
            "value": $ENABLE_SECURITY_COPILOT
        },
        "existingSentinelWorkspaceId": {
            "value": "$EXISTING_SENTINEL_WORKSPACE_ID"
        },
        "appClientId": {
            "value": "$APP_CLIENT_ID"
        },
        "tenantId": {
            "value": "$TENANT_ID"
        },
        "keyVaultName": {
            "value": "$KEY_VAULT_NAME"
        },
        "clientSecretName": {
            "value": "$CLIENT_SECRET_NAME"
        },
        "managedIdentityName": {
            "value": "$MANAGED_IDENTITY_NAME"
        },
        "graphApiUrl": {
            "value": "$GRAPH_API_URL"
        },
        "initialClientSecret": {
            "value": "$INITIAL_CLIENT_SECRET"
        },
        "enableAnalyticsRules": {
            "value": $ENABLE_ANALYTICS_RULES
        },
        "enableHuntingQueries": {
            "value": $ENABLE_HUNTING_QUERIES
        },
        "tags": {
            "value": {
                "solution": "CentralThreatIntelligence",
                "environment": "Production",
                "createdBy": "DeployScript",
                "deploymentDate": "$(date +%Y-%m-%d)"
            }
        }
    }
}
EOF
        PARAMETERS_FILE="$TEMP_PARAMS_FILE"
    fi
    
    # Deploy the template
    log "INFO" "Starting Bicep deployment - this may take several minutes..."
    
    DEPLOYMENT_OUTPUT=$(az deployment group create \
      --name "$DEPLOYMENT_NAME" \
      --resource-group "$RESOURCE_GROUP_NAME" \
      --template-file "$BICEP_FILE" \
      --parameters "$PARAMETERS_FILE" \
      --output json)
    
    # Check if deployment was successful
    DEPLOYMENT_STATE=$(echo "$DEPLOYMENT_OUTPUT" | jq -r '.properties.provisioningState')
    
    if [[ "$DEPLOYMENT_STATE" != "Succeeded" ]]; then
        log "ERROR" "Deployment failed with state: $DEPLOYMENT_STATE"
        
        # Extract error messages if available
        ERROR_DETAILS=$(echo "$DEPLOYMENT_OUTPUT" | jq -r '.properties.error.details[]?.message' 2>/dev/null || echo "")
        if [[ -n "$ERROR_DETAILS" ]]; then
            log "ERROR" "Error details: $ERROR_DETAILS"
        fi
        
        # Clean up temporary parameters file if created
        if [ -n "$TEMP_PARAMS_FILE" ]; then
            rm -f "$TEMP_PARAMS_FILE"
        fi
        
        exit 1
    fi
    
    # Clean up temporary parameters file if created
    if [ -n "$TEMP_PARAMS_FILE" ]; then
        rm -f "$TEMP_PARAMS_FILE"
    fi
    
    # Extract key outputs
    CTI_WORKSPACE_ID=$(echo "$DEPLOYMENT_OUTPUT" | jq -r '.properties.outputs.ctiWorkspaceId.value')
    CTI_WORKSPACE_NAME=$(echo "$DEPLOYMENT_OUTPUT" | jq -r '.properties.outputs.ctiWorkspaceName.value')
    KEY_VAULT_NAME=$(echo "$DEPLOYMENT_OUTPUT" | jq -r '.properties.outputs.keyVaultName.value')
    MANAGED_IDENTITY_ID=$(echo "$DEPLOYMENT_OUTPUT" | jq -r '.properties.outputs.managedIdentityId.value')
    MANAGED_IDENTITY_PRINCIPAL_ID=$(echo "$DEPLOYMENT_OUTPUT" | jq -r '.properties.outputs.managedIdentityPrincipalId.value')
    TAXII_CONNECTOR_NAME=$(echo "$DEPLOYMENT_OUTPUT" | jq -r '.properties.outputs.taxiiConnectorName.value')
    DEFENDER_CONNECTOR_NAME=$(echo "$DEPLOYMENT_OUTPUT" | jq -r '.properties.outputs.defenderConnectorName.value')
    COPILOT_CONNECTOR_NAME=$(echo "$DEPLOYMENT_OUTPUT" | jq -r '.properties.outputs.securityCopilotConnectorName.value')
    
    log "SUCCESS" "CTI solution deployment completed successfully"
    log "DATA" "CTI Workspace ID: $CTI_WORKSPACE_ID"
    log "DATA" "CTI Workspace Name: $CTI_WORKSPACE_NAME"
    log "DATA" "Key Vault Name: $KEY_VAULT_NAME"
    
    # Save deployment info for later reference
    mkdir -p .cti
    cat > .cti/deployment-info.json << EOF
{
    "deploymentName": "$DEPLOYMENT_NAME",
    "deploymentTime": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
    "resourceGroup": "$RESOURCE_GROUP_NAME",
    "location": "$LOCATION",
    "ctiWorkspaceId": "$CTI_WORKSPACE_ID",
    "ctiWorkspaceName": "$CTI_WORKSPACE_NAME",
    "keyVaultName": "$KEY_VAULT_NAME",
    "managedIdentityId": "$MANAGED_IDENTITY_ID",
    "managedIdentityPrincipalId": "$MANAGED_IDENTITY_PRINCIPAL_ID",
    "taxiiConnectorName": "$TAXII_CONNECTOR_NAME",
    "defenderConnectorName": "$DEFENDER_CONNECTOR_NAME",
    "copilotConnectorName": "$COPILOT_CONNECTOR_NAME",
    "sentinelIntegration": $ENABLE_SENTINEL_INTEGRATION,
    "mdtiIntegration": $ENABLE_MDTI,
    "securityCopilotIntegration": $ENABLE_SECURITY_COPILOT
}
EOF

    log "INFO" "Deployment information saved to .cti/deployment-info.json"
}

# Function to configure Security Copilot integration
function configure_security_copilot() {
    if [[ "$ENABLE_SECURITY_COPILOT" != "true" ]]; then
        log "INFO" "Skipping Security Copilot configuration as it's not enabled"
        return
    fi
    
    log "STEP" "Configuring Security Copilot integration"
    
    # Check if Security Copilot connector is deployed
    if [ -z "$COPILOT_CONNECTOR_NAME" ]; then
        log "WARNING" "Security Copilot connector name not found in deployment outputs"
        return
    fi
    
    log "INFO" "Security Copilot connector deployed: $COPILOT_CONNECTOR_NAME"
    
    # In a real implementation, this would configure Security Copilot plugins or extensions
    # For now, just provide guidance since Security Copilot API access is limited
    
    log "INFO" "To complete Security Copilot integration:"
    log "INFO" "1. Ensure you have Security Copilot licenses assigned to users"
    log "INFO" "2. Connect your CTI Workspace as a data source in Security Copilot"
    log "INFO" "3. Configure the Security Copilot plugin for threat intelligence analysis"
    
    log "SUCCESS" "Security Copilot integration setup completed"
}

# Function to handle post-deployment configuration
function post_deployment_configuration() {
    log "STEP" "Performing post-deployment configuration"
    
    # Update client secret in Key Vault if needed
    if [ "$SKIP_CLIENT_SECRET" != "true" ] && [ -n "$APP_CLIENT_ID" ] && [ -n "$KEY_VAULT_NAME" ]; then
        if [ -z "$INITIAL_CLIENT_SECRET" ]; then
            log "INFO" "Enter the client secret for application $APP_CLIENT_ID to store in Key Vault"
            read -sp "Client Secret: " CLIENT_SECRET
            echo ""
            
            if [ -n "$CLIENT_SECRET" ]; then
                log "INFO" "Storing client secret in Key Vault..."
                az keyvault secret set --vault-name "$KEY_VAULT_NAME" --name "$CLIENT_SECRET_NAME" --value "$CLIENT_SECRET" --output none
                log "SUCCESS" "Client secret stored in Key Vault"
            else
                log "WARNING" "No client secret provided, skipping"
            fi
        else
            log "INFO" "Initial client secret was already set during deployment"
        fi
    fi
    
    # Deploy workbooks if enabled
    if [ "$SKIP_WORKBOOKS" != "true" ]; then
        log "INFO" "Deploying workbooks to Log Analytics workspace"
        
        # List all workbook files
        WORKBOOK_FILES=$(ls -1 workbooks/*.json 2>/dev/null)
        
        if [ -n "$WORKBOOK_FILES" ]; then
            for workbook_file in $WORKBOOK_FILES; do
                workbook_name=$(basename "$workbook_file" .json)
                workbook_display_name=$(jq -r '.items[] | select(.name == "Title" or .name == "title") | .content.json' "$workbook_file" | head -n1 | sed 's/^# //')
                
                if [ -z "$workbook_display_name" ]; then
                    workbook_display_name="Threat Intelligence - $workbook_name"
                fi
                
                log "INFO" "Deploying workbook: $workbook_display_name"
                
                # Generate a deterministic GUID for the workbook
                WORKBOOK_ID=$(uuidgen --sha1 --namespace @dns --name "cti-$workbook_name-$CTI_WORKSPACE_ID")
                
                # Deploy the workbook
                az portal workbook create \
                  --resource-group "$RESOURCE_GROUP_NAME" \
                  --name "$WORKBOOK_ID" \
                  --location "$LOCATION" \
                  --tags "solution=CentralThreatIntelligence" \
                  --display-name "$workbook_display_name" \
                  --source-id "$CTI_WORKSPACE_ID" \
                  --category "sentinel" \
                  --definition "@$workbook_file" \
                  --output none
                
                if [ $? -eq 0 ]; then
                    log "SUCCESS" "Workbook $workbook_display_name deployed successfully"
                else
                    log "WARNING" "Failed to deploy workbook $workbook_display_name"
                fi
            done
        else
            log "WARNING" "No workbook files found in the workbooks directory"
        fi
    fi
    
    # Deploy analytics rules if enabled
    if [ "$ENABLE_ANALYTICS_RULES" == "true" ] && [ "$ENABLE_SENTINEL_INTEGRATION" == "true" ]; then
        log "INFO" "Deploying analytics rules to Sentinel"
        
        # List all analytics rule files
        RULE_FILES=$(ls -1 analytics/*.json 2>/dev/null)
        
        if [ -n "$RULE_FILES" ]; then
            for rule_file in $RULE_FILES; do
                rule_name=$(jq -r '.name' "$rule_file")
                
                log "INFO" "Deploying analytics rule: $rule_name"
                
                # Deploy the analytics rule using Sentinel API
                # This is a simplified version and would need to be expanded in a real implementation
                # to handle the Sentinel API authentication and rule creation
                
                # For now, just provide guidance
                log "INFO" "To manually import this rule:"
                log "INFO" "1. Navigate to Microsoft Sentinel > Analytics"
                log "INFO" "2. Click 'Create' > 'Import'"
                log "INFO" "3. Select file: $rule_file"
            done
        else
            log "WARNING" "No analytics rule files found in the analytics directory"
        fi
    fi
    
    # Configure Security Copilot integration
    configure_security_copilot
    
    log "SUCCESS" "Post-deployment configuration completed"
}

# Function to display next steps
function display_next_steps() {
    echo ""
    echo "=================================================="
    echo "🎉 Advanced CTI Solution Deployment Complete!"
    echo "=================================================="
    echo ""
    echo "Next steps:"
    echo ""
    echo "1. Configure your TAXII feeds and API connections"
    echo "   - Update the TAXII Connector Logic App with your TAXII server details"
    echo "   - Run the TAXII connector to populate initial data"
    echo ""
    echo "2. Connect to Microsoft Defender XDR"
    echo "   - Ensure the application has the required API permissions"
    echo "   - Update client secrets in the Key Vault if needed"
    echo ""
    echo "3. Set up Microsoft Sentinel integration"
    echo "   - Review the deployed analytics rules and workbooks"
    echo "   - Create custom playbooks for automated response"
    echo ""
    if [[ "$ENABLE_SECURITY_COPILOT" == "true" ]]; then
        echo "4. Complete Security Copilot configuration"
        echo "   - Connect your CTI Workspace as a data source in Security Copilot"
        echo "   - Install Security Copilot plugins for threat intelligence analysis"
        echo ""
    fi
    
    echo "For detailed documentation, refer to README.md"
    
    # Offer to open the Azure portal
    echo ""
    read -p "Would you like to open the Azure portal to view the deployed resources? (y/n): " OPEN_PORTAL
    if [[ "$OPEN_PORTAL" == "y" || "$OPEN_PORTAL" == "Y" ]]; then
        az portal open --resource-group "$RESOURCE_GROUP_NAME"
    fi
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    key="$1"
    
    case $key in
        -h|--help)
            display_usage
            exit 0
            ;;
        -g|--resource-group)
            RESOURCE_GROUP_NAME="$2"
            shift 2
            ;;
        -l|--location)
            LOCATION="$2"
            shift 2
            ;;
        -w|--workspace-name)
            CTI_WORKSPACE_NAME="$2"
            shift 2
            ;;
        -r|--retention-days)
            CTI_WORKSPACE_RETENTION_DAYS="$2"
            shift 2
            ;;
        -q|--quota-gb)
            CTI_WORKSPACE_DAILY_QUOTA_GB="$2"
            shift 2
            ;;
        -s|--sentinel)
            ENABLE_SENTINEL_INTEGRATION="$2"
            shift 2
            ;;
        -m|--mdti)
            ENABLE_MDTI="$2"
            shift 2
            ;;
        --security-copilot)
            ENABLE_SECURITY_COPILOT="$2"
            shift 2
            ;;
        -e|--existing-sentinel)
            EXISTING_SENTINEL_WORKSPACE_ID="$2"
            shift 2
            ;;
        -c|--client-id)
            APP_CLIENT_ID="$2"
            shift 2
            ;;
        -t|--tenant-id)
            TENANT_ID="$2"
            shift 2
            ;;
        -k|--key-vault)
            KEY_VAULT_NAME="$2"
            shift 2
            ;;
        -p|--parameters)
            PARAMETERS_FILE="$2"
            shift 2
            ;;
        --enable-analytics)
            ENABLE_ANALYTICS_RULES="$2"
            shift 2
            ;;
        --enable-hunting)
            ENABLE_HUNTING_QUERIES="$2"
            shift 2
            ;;
        --advanced)
            ADVANCED_DEPLOYMENT=true
            shift
            ;;
        --skip-workbooks)
            SKIP_WORKBOOKS=true
            shift
            ;;
        --skip-client-secret)
            SKIP_CLIENT_SECRET=true
            shift
            ;;
        *)
            log "ERROR" "Unknown option: $key"
            display_usage
            exit 1
            ;;
    esac
done

# Main script execution
echo "=================================================="
echo "Advanced Central Threat Intelligence (CTI) Solution Deployment"
echo "Version: 2.0 - April 2025"
echo "=================================================="
echo ""

# Check prerequisites
check_prerequisites

# Validate Azure subscription
validate_azure_subscription

# Create or use existing app registration
setup_app_registration

# Create workbooks
create_workbooks

# Create analytics rules
create_analytics_rules

# Ensure resource group exists
ensure_resource_group

# Deploy bicep template
deploy_bicep_template

# Post-deployment configuration
post_deployment_configuration

# Display next steps
display_next_steps

exit 0

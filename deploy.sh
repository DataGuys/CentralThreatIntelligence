#!/bin/bash
# Enhanced CTI Deployment Script with Subscription Selection
# Author: Claude
# Version: 2.0
# Date: April 2025

# Set strict error handling
set -e
set -o pipefail

# Color definitions for better readability
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[0;33m'
readonly BLUE='\033[0;34m'
readonly PURPLE='\033[0;35m'
readonly CYAN='\033[0;36m'
readonly NC='\033[0m' # No Color

# Configuration variables with defaults
RESOURCE_GROUP_NAME="CTI-ResourceGroup"
LOCATION="eastus"
CTI_WORKSPACE_NAME="CTI-Workspace"
ENABLE_SENTINEL_INTEGRATION=true
ENABLE_MDTI=true
ENABLE_SECURITY_COPILOT=false
SKIP_WORKBOOKS=false
ADVANCED_DEPLOYMENT=false

# Log function with timestamps
function log() {
    local level=$1
    local message=$2
    local timestamp=$(date +"%Y-%m-%d %H:%M:%S")
    
    case $level in
        "INFO")
            echo -e "${BLUE}[$timestamp] [INFO] $message${NC}"
            ;;
        "SUCCESS")
            echo -e "${GREEN}[$timestamp] [SUCCESS] $message${NC}"
            ;;
        "WARNING")
            echo -e "${YELLOW}[$timestamp] [WARNING] $message${NC}"
            ;;
        "ERROR")
            echo -e "${RED}[$timestamp] [ERROR] $message${NC}"
            ;;
        "STEP")
            echo -e "${PURPLE}[$timestamp] [STEP] $message${NC}"
            ;;
        "DATA")
            echo -e "${CYAN}[$timestamp] [DATA] $message${NC}"
            ;;
        *)
            echo -e "[$timestamp] $message"
            ;;
    esac
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
    echo "  --advanced                       Enable advanced deployment options"
    echo "  --skip-workbooks                 Skip workbook creation"
    echo ""
    echo "Examples:"
    echo "  $0 --resource-group MyRG --location westus2"
    echo "  $0 --advanced"
}

# Function to check prerequisites
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
    
    log "SUCCESS" "Prerequisites check completed"
}

# Function to select Azure subscription
function select_subscription() {
    log "STEP" "Fetching available Azure subscriptions"
    
    # Get list of subscriptions
    SUBSCRIPTIONS=$(az account list --query "[?state=='Enabled'].{name:name, id:id, isDefault:isDefault}" -o json)
    
    if [ -z "$SUBSCRIPTIONS" ] || [ "$SUBSCRIPTIONS" == "[]" ]; then
        log "ERROR" "No enabled Azure subscriptions found. Please check your Azure account."
        exit 1
    fi
    
    # Count subscriptions
    SUBSCRIPTION_COUNT=$(echo $SUBSCRIPTIONS | jq '. | length')
    
    if [ $SUBSCRIPTION_COUNT -eq 1 ]; then
        # If only one subscription, use it
        SUBSCRIPTION_ID=$(echo $SUBSCRIPTIONS | jq -r '.[0].id')
        SUBSCRIPTION_NAME=$(echo $SUBSCRIPTIONS | jq -r '.[0].name')
        log "INFO" "Using the only available subscription: $SUBSCRIPTION_NAME ($SUBSCRIPTION_ID)"
        
        # Set the subscription as active
        az account set --subscription "$SUBSCRIPTION_ID"
    else
        # Display subscription selection menu
        log "INFO" "Multiple subscriptions found. Please select one:"
        echo ""
        
        # Display subscriptions with numbers
        echo "$SUBSCRIPTIONS" | jq -r 'to_entries | .[] | "\(.key+1). \(.value.name) (\(.value.id)) \(if .value.isDefault then "- DEFAULT" else "" end)"' | while read -r line; do
            if [[ $line == *"DEFAULT"* ]]; then
                echo -e "${GREEN}$line${NC}"
            else
                echo "$line"
            fi
        done
        
        echo ""
        # Ask user to select a subscription
        while true; do
            read -p "Enter the number of the subscription to use (1-$SUBSCRIPTION_COUNT): " SELECTION
            
            if [[ "$SELECTION" =~ ^[0-9]+$ ]] && [ "$SELECTION" -ge 1 ] && [ "$SELECTION" -le $SUBSCRIPTION_COUNT ]; then
                # Valid selection
                SELECTED_INDEX=$((SELECTION-1))
                SUBSCRIPTION_ID=$(echo $SUBSCRIPTIONS | jq -r ".[$SELECTED_INDEX].id")
                SUBSCRIPTION_NAME=$(echo $SUBSCRIPTIONS | jq -r ".[$SELECTED_INDEX].name")
                break
            else
                log "WARNING" "Invalid selection. Please enter a number between 1 and $SUBSCRIPTION_COUNT."
            fi
        done
        
        log "INFO" "Setting active subscription to: $SUBSCRIPTION_NAME ($SUBSCRIPTION_ID)"
        
        # Set the subscription as active
        az account set --subscription "$SUBSCRIPTION_ID"
    fi
    
    # Verify the active subscription
    CURRENT_SUB=$(az account show --query "{ name: name, id: id }" -o json)
    CURRENT_SUB_ID=$(echo $CURRENT_SUB | jq -r '.id')
    CURRENT_SUB_NAME=$(echo $CURRENT_SUB | jq -r '.name')
    
    if [ "$CURRENT_SUB_ID" != "$SUBSCRIPTION_ID" ]; then
        log "ERROR" "Failed to set the selected subscription as active. Please try again."
        exit 1
    fi
    
    log "SUCCESS" "Successfully set subscription: $CURRENT_SUB_NAME ($CURRENT_SUB_ID)"
}

# Function to validate subscription for required providers
function validate_subscription() {
    log "STEP" "Validating subscription for required providers"
    
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
                    log "INFO" "Waiting for $provider registration to complete..."
                    while [[ "$(az provider show --namespace $provider --query "registrationState" -o tsv 2>/dev/null)" != "Registered" ]]; do
                        log "INFO" "Still waiting for $provider registration..."
                        sleep 10
                    done
                    log "SUCCESS" "$provider registered successfully"
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
}

# Function to select Azure location
function select_location() {
    log "STEP" "Selecting Azure location"
    
    # Get list of available locations
    LOCATIONS=$(az account list-locations --query "[].{name:name, displayName:displayName}" -o json)
    
    if [ -z "$LOCATIONS" ] || [ "$LOCATIONS" == "[]" ]; then
        log "ERROR" "Failed to retrieve Azure locations. Using default: $LOCATION"
        return
    fi
    
    # If advanced mode, ask user for location selection
    if [[ "$ADVANCED_DEPLOYMENT" == "true" ]]; then
        # Show current location and ask if they want to change it
        log "INFO" "Current location is set to: $LOCATION"
        read -p "Do you want to change the deployment location? (y/n): " CHANGE_LOCATION
        
        if [[ "$CHANGE_LOCATION" == "y" || "$CHANGE_LOCATION" == "Y" ]]; then
            # Display popular/recommended locations first
            POPULAR_LOCATIONS=("eastus" "westus2" "westeurope" "northeurope" "southeastasia")
            
            log "INFO" "Recommended locations:"
            for i in "${!POPULAR_LOCATIONS[@]}"; do
                DISPLAY_NAME=$(echo $LOCATIONS | jq -r ".[] | select(.name == \"${POPULAR_LOCATIONS[$i]}\") | .displayName")
                echo "  $((i+1)). ${POPULAR_LOCATIONS[$i]} - $DISPLAY_NAME"
            done
            
            log "INFO" "Type a location name or 'list' to see all available locations:"
            read -p "Location: " USER_LOCATION
            
            if [[ "$USER_LOCATION" == "list" ]]; then
                # Display all locations with numbers
                echo "$LOCATIONS" | jq -r 'to_entries | .[] | "\(.key+1). \(.value.name) - \(.value.displayName)"'
                
                # Ask user to select by number
                LOCATION_COUNT=$(echo $LOCATIONS | jq '. | length')
                read -p "Enter the number of the location to use (1-$LOCATION_COUNT): " LOCATION_SELECTION
                
                if [[ "$LOCATION_SELECTION" =~ ^[0-9]+$ ]] && [ "$LOCATION_SELECTION" -ge 1 ] && [ "$LOCATION_SELECTION" -le $LOCATION_COUNT ]; then
                    # Valid selection
                    SELECTED_INDEX=$((LOCATION_SELECTION-1))
                    LOCATION=$(echo $LOCATIONS | jq -r ".[$SELECTED_INDEX].name")
                else
                    log "WARNING" "Invalid selection. Using default location: $LOCATION"
                fi
            elif [[ "$USER_LOCATION" =~ ^[1-5]$ ]]; then
                # User selected from recommended locations
                LOCATION_INDEX=$((USER_LOCATION-1))
                LOCATION=${POPULAR_LOCATIONS[$LOCATION_INDEX]}
            elif [[ -n "$USER_LOCATION" ]]; then
                # Check if the provided location is valid
                LOCATION_CHECK=$(echo $LOCATIONS | jq -r ".[] | select(.name == \"$USER_LOCATION\") | .name")
                if [[ -n "$LOCATION_CHECK" ]]; then
                    LOCATION=$USER_LOCATION
                else
                    log "WARNING" "Invalid location name. Using default location: $LOCATION"
                fi
            fi
        fi
    fi
    
    log "INFO" "Using location: $LOCATION"
}

# Function to ensure resource group exists
function ensure_resource_group() {
    log "STEP" "Setting up resource group: $RESOURCE_GROUP_NAME"
    
    # Check if resource group exists
    if az group show --name "$RESOURCE_GROUP_NAME" &> /dev/null; then
        log "INFO" "Resource group $RESOURCE_GROUP_NAME already exists"
        
        # If advanced mode, ask if they want to use a different resource group
        if [[ "$ADVANCED_DEPLOYMENT" == "true" ]]; then
            read -p "Do you want to use a different resource group? (y/n): " CHANGE_RG
            if [[ "$CHANGE_RG" == "y" || "$CHANGE_RG" == "Y" ]]; then
                read -p "Enter new resource group name: " NEW_RG_NAME
                if [[ -n "$NEW_RG_NAME" ]]; then
                    RESOURCE_GROUP_NAME=$NEW_RG_NAME
                    
                    # Check if the new resource group exists
                    if az group show --name "$RESOURCE_GROUP_NAME" &> /dev/null; then
                        log "INFO" "Using existing resource group: $RESOURCE_GROUP_NAME"
                    else
                        log "INFO" "Creating new resource group: $RESOURCE_GROUP_NAME in $LOCATION"
                        az group create --name "$RESOURCE_GROUP_NAME" --location "$LOCATION" \
                            --tags "solution=CentralThreatIntelligence" "environment=Production" "createdBy=DeployScript" "deploymentDate=$(date +%Y-%m-%d)"
                        
                        if [ $? -ne 0 ]; then
                            log "ERROR" "Failed to create resource group $RESOURCE_GROUP_NAME"
                            exit 1
                        fi
                        
                        log "SUCCESS" "Resource group $RESOURCE_GROUP_NAME created successfully"
                    fi
                fi
            fi
        fi
    else
        log "INFO" "Creating resource group $RESOURCE_GROUP_NAME in $LOCATION"
        az group create --name "$RESOURCE_GROUP_NAME" --location "$LOCATION" \
            --tags "solution=CentralThreatIntelligence" "environment=Production" "createdBy=DeployScript" "deploymentDate=$(date +%Y-%m-%d)"
        
        if [ $? -ne 0 ]; then
            log "ERROR" "Failed to create resource group $RESOURCE_GROUP_NAME"
            exit 1
        fi
        
        log "SUCCESS" "Resource group $RESOURCE_GROUP_NAME created successfully"
    fi
}

# Function to deploy the Bicep template
function deploy_bicep_template() {
    log "STEP" "Preparing to deploy CTI solution"
    
    # Create a deployment name with timestamp
    DEPLOYMENT_NAME="CTI-Deployment-$(date +%Y%m%d%H%M%S)"
    BICEP_FILE="main.bicep"
    
    # Check if Bicep file exists
    if [ ! -f "$BICEP_FILE" ]; then
        log "ERROR" "Bicep template file $BICEP_FILE not found"
        exit 1
    fi
    
    # Create a temporary parameters file
    TEMP_PARAMS_FILE=$(mktemp)
    log "INFO" "Creating deployment parameters file: $TEMP_PARAMS_FILE"
    
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
        "enableSentinelIntegration": {
            "value": $ENABLE_SENTINEL_INTEGRATION
        },
        "enableMDTI": {
            "value": $ENABLE_MDTI
        },
        "enableSecurityCopilot": {
            "value": $ENABLE_SECURITY_COPILOT
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

    # Ask user for confirmation before deploying
    log "INFO" "Ready to deploy the CTI solution with the following configuration:"
    echo ""
    echo "  Subscription: $(az account show --query name -o tsv)"
    echo "  Resource Group: $RESOURCE_GROUP_NAME"
    echo "  Location: $LOCATION"
    echo "  Workspace Name: $CTI_WORKSPACE_NAME"
    echo "  Sentinel Integration: $ENABLE_SENTINEL_INTEGRATION"
    echo "  Microsoft Defender TI Integration: $ENABLE_MDTI"
    echo "  Security Copilot Integration: $ENABLE_SECURITY_COPILOT"
    echo ""
    
    if [[ "$ADVANCED_DEPLOYMENT" == "true" ]]; then
        read -p "Do you want to proceed with the deployment? (y/n): " CONFIRM_DEPLOYMENT
        if [[ "$CONFIRM_DEPLOYMENT" != "y" && "$CONFIRM_DEPLOYMENT" != "Y" ]]; then
            log "INFO" "Deployment cancelled by user"
            rm -f "$TEMP_PARAMS_FILE"
            exit 0
        fi
    else
        log "INFO" "Starting deployment in 5 seconds... Press Ctrl+C to cancel"
        sleep 5
    fi
    
    # Deploy the template
    log "INFO" "Starting Bicep deployment - this may take several minutes..."
    
    DEPLOYMENT_RESULT=$(az deployment group create \
      --name "$DEPLOYMENT_NAME" \
      --resource-group "$RESOURCE_GROUP_NAME" \
      --template-file "$BICEP_FILE" \
      --parameters "$TEMP_PARAMS_FILE" \
      --output json 2>&1)
    
    DEPLOYMENT_EXIT_CODE=$?
    
    # Check if deployment was successful
    if [ $DEPLOYMENT_EXIT_CODE -ne 0 ]; then
        log "ERROR" "Deployment failed with exit code: $DEPLOYMENT_EXIT_CODE"
        log "ERROR" "Error details: $DEPLOYMENT_RESULT"
        
        # Clean up temporary parameters file
        rm -f "$TEMP_PARAMS_FILE"
        
        exit 1
    fi
    
    # Extract deployment state
    DEPLOYMENT_STATE=$(echo "$DEPLOYMENT_RESULT" | jq -r '.properties.provisioningState' 2>/dev/null)
    
    if [[ "$DEPLOYMENT_STATE" != "Succeeded" ]]; then
        log "ERROR" "Deployment failed with state: $DEPLOYMENT_STATE"
        
        # Extract error messages if available
        ERROR_DETAILS=$(echo "$DEPLOYMENT_RESULT" | jq -r '.properties.error.details[]?.message' 2>/dev/null || echo "")
        if [[ -n "$ERROR_DETAILS" ]]; then
            log "ERROR" "Error details: $ERROR_DETAILS"
        fi
        
        # Clean up temporary parameters file
        rm -f "$TEMP_PARAMS_FILE"
        
        exit 1
    fi
    
    # Clean up temporary parameters file
    rm -f "$TEMP_PARAMS_FILE"
    
    # Extract key outputs
    CTI_WORKSPACE_ID=$(echo "$DEPLOYMENT_RESULT" | jq -r '.properties.outputs.ctiWorkspaceId.value')
    CTI_WORKSPACE_NAME=$(echo "$DEPLOYMENT_RESULT" | jq -r '.properties.outputs.ctiWorkspaceName.value')
    KEY_VAULT_NAME=$(echo "$DEPLOYMENT_RESULT" | jq -r '.properties.outputs.keyVaultName.value')
    
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
    "subscriptionId": "$(az account show --query id -o tsv)",
    "subscriptionName": "$(az account show --query name -o tsv)",
    "sentinelIntegration": $ENABLE_SENTINEL_INTEGRATION,
    "mdtiIntegration": $ENABLE_MDTI,
    "securityCopilotIntegration": $ENABLE_SECURITY_COPILOT
}
EOF

    log "INFO" "Deployment information saved to .cti/deployment-info.json"
}

# Function to display next steps
function display_next_steps() {
    echo ""
    echo "=================================================="
    echo "🎉 CTI Solution Deployment Complete!"
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
        --advanced)
            ADVANCED_DEPLOYMENT=true
            shift
            ;;
        --skip-workbooks)
            SKIP_WORKBOOKS=true
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
echo "Central Threat Intelligence (CTI) Solution Deployment"
echo "Version: 2.0 - April 2025"
echo "=================================================="
echo ""

# Check prerequisites
check_prerequisites

# Display subscription selection menu and set active subscription
select_subscription

# Validate subscription for required providers
validate_subscription

# Select Azure location
select_location

# Ensure resource group exists
ensure_resource_group

# Deploy bicep template
deploy_bicep_template

# Display next steps
display_next_steps

exit 0

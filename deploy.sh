#!/bin/bash
# Enhanced CTI Deployment Script with Subscription Selection
# Author: Claude
# Version: 2.1
# Date: April 2025

# IMPORTANT: Do NOT use "set -e" as it causes the script to exit on errors
# which can close the Cloud Shell session

# Set debugging to show commands (but comment out if too verbose)
# set -x

# Setup cleanup on exit
function cleanup() {
    # Remove any temporary files
    if [[ -f "$TEMP_PARAMS_FILE" ]]; then
        rm -f "$TEMP_PARAMS_FILE"
    fi
    echo ""
    log "INFO" "Script execution completed"
}

# Handle interruption gracefully
function handle_interrupt() {
    echo ""
    log "WARNING" "Script execution interrupted by user"
    cleanup
    exit 1
}

# Function to handle errors without exiting the shell
function handle_error() {
    local exit_code=$1
    local error_message=$2
    
    echo ""
    echo "==============================================="
    echo "❌ ${RED}ERROR DETECTED: $error_message${NC}"
    echo "==============================================="
    echo ""
    echo "Press ENTER to continue or Ctrl+C to stop the script..."
    read -r
    
    # Return the error code but don't exit the shell
    return $exit_code
}

# Register the cleanup function for normal exit and interrupts
# Don't use ERR trap as it can cause the shell to exit
trap cleanup EXIT
trap handle_interrupt SIGINT SIGTERM

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
REQUIRED_TOOLS=("jq" "az")
SCRIPT_VERSION="2.1"
MIN_AZ_CLI_VERSION="2.40.0"
TEMP_PARAMS_FILE=""

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

# Function to validate Azure CLI version
function validate_az_version() {
    log "STEP" "Checking Azure CLI version"
    
    local AZ_VERSION=$(az version --query '"azure-cli"' -o tsv)
    log "INFO" "Found Azure CLI version $AZ_VERSION"
    
    # Compare versions using version sort
    if [[ "$(printf '%s\n' "$MIN_AZ_CLI_VERSION" "$AZ_VERSION" | sort -V | head -n1)" != "$MIN_AZ_CLI_VERSION" ]]; then
        log "SUCCESS" "Azure CLI version $AZ_VERSION is compatible"
    else
        log "WARNING" "Azure CLI version $AZ_VERSION may be too old. Minimum recommended version is $MIN_AZ_CLI_VERSION"
        if [[ "$ADVANCED_DEPLOYMENT" == "true" ]]; then
            read -p "Continue anyway? (y/n): " CONTINUE
            if [[ "$CONTINUE" != "y" && "$CONTINUE" != "Y" ]]; then
                log "INFO" "Please update Azure CLI and try again"
                exit 0
            fi
        else
            log "INFO" "Continuing with available version. Update recommended for optimal experience"
        fi
    fi
}

# Function to check internet connectivity
function check_connectivity() {
    log "STEP" "Checking internet connectivity"
    
    # Try to connect to Microsoft Azure
    if curl -s --connect-timeout 5 https://management.azure.com > /dev/null; then
        log "SUCCESS" "Internet connectivity confirmed"
    else
        log "WARNING" "Could not connect to Azure. Check your internet connection"
        if [[ "$ADVANCED_DEPLOYMENT" == "true" ]]; then
            read -p "Continue anyway? (y/n): " CONTINUE
            if [[ "$CONTINUE" != "y" && "$CONTINUE" != "Y" ]]; then
                exit 0
            fi
        else
            log "INFO" "Continuing despite connectivity issues"
        fi
    fi
}

# Function to check prerequisites
function check_prerequisites() {
    log "STEP" "Checking prerequisites"
    
    # Check for required tools
    for tool in "${REQUIRED_TOOLS[@]}"; do
        if ! command -v $tool &> /dev/null; then
            log "ERROR" "$tool is not installed. Please install it before running this script."
            if [ "$tool" = "jq" ]; then
                log "INFO" "Install jq: https://stedolan.github.io/jq/download/"
            elif [ "$tool" = "az" ]; then
                log "INFO" "Install Azure CLI: https://docs.microsoft.com/en-us/cli/azure/install-azure-cli"
            fi
            exit 1
        fi
    done
    
    # Check if running in Azure Cloud Shell
    if [ -z "$AZURE_EXTENSION_DIR" ]; then
        # Only check for Azure CLI if not in Cloud Shell
        if ! command -v az &> /dev/null; then
            log "ERROR" "Azure CLI is not installed. Please install it first: https://docs.microsoft.com/en-us/cli/azure/install-azure-cli"
            exit 1
        fi
        
        # Validate Azure CLI version if not in Cloud Shell
        validate_az_version
    else
        log "INFO" "Running in Azure Cloud Shell, Azure CLI is available"
    fi
    
    # Check if Azure CLI is logged in
    if ! az account show &> /dev/null; then
        log "WARNING" "Not logged in to Azure. Please login."
        az login
        
        # Verify login was successful
        if ! az account show &> /dev/null; then
            log "ERROR" "Login failed. Please check your credentials and try again."
            exit 1
        fi
    fi
    
    # Verify main.bicep exists in the current directory
    if [ ! -f "main.bicep" ]; then
        log "ERROR" "main.bicep file not found in the current directory"
        exit 1
    fi
    
    # Check if we can create temporary files
    if ! touch "$(mktemp -u)" &> /dev/null; then
        log "ERROR" "Unable to create temporary files. Check your permissions."
        exit 1
    fi
    
    log "SUCCESS" "Prerequisites check completed"
}

# Function to validate resource name
function validate_resource_name() {
    local name=$1
    local resource_type=$2
    
    echo ""
    echo "▶️ VALIDATING RESOURCE NAME: '$name' (Type: $resource_type)"
    
    # Name must be between 3 and 63 characters
    if [[ ${#name} -lt 3 || ${#name} -gt 63 ]]; then
        echo "❌ ${RED}ERROR: $resource_type name must be between 3 and 63 characters${NC}"
        echo "❌ ${RED}Current length: ${#name} characters${NC}"
        return 1
    fi
    
    # Name must start with a letter or number and contain only lowercase letters, numbers, and hyphens
    if ! [[ $name =~ ^[a-z0-9][a-z0-9\-]{1,61}[a-z0-9]$ ]]; then
        echo "❌ ${RED}ERROR: $resource_type name validation failed${NC}"
        echo "   - ${RED}$resource_type name must contain only lowercase letters, numbers, and hyphens${NC}"
        echo "   - ${RED}$resource_type name must start and end with a letter or number${NC}"
        echo ""
        echo "❓ ${YELLOW}Does your resource name contain uppercase letters or special characters?${NC}"
        return 1
    fi
    
    echo "✅ ${GREEN}Name validation passed${NC}"
    return 0
}

# Function to select Azure subscription
function select_subscription() {
    log "STEP" "Fetching available Azure subscriptions"
    
    # Debug log file
    DEBUG_LOG="/tmp/cti_deploy_debug.log"
    echo "=== SUBSCRIPTION SELECTION DEBUG $(date) ===" >> "$DEBUG_LOG"
    
    # Get list of subscriptions with error trapping
    echo "Running: az account list" >> "$DEBUG_LOG"
    SUBSCRIPTION_RESULT=$(az account list --query "[?state=='Enabled'].{name:name, id:id, isDefault:isDefault}" -o json 2>&1)
    SUBSCRIPTION_EXIT_CODE=$?
    
    # Log the raw output
    echo "Exit code: $SUBSCRIPTION_EXIT_CODE" >> "$DEBUG_LOG"
    echo "Raw output length: $(echo "$SUBSCRIPTION_RESULT" | wc -c) bytes" >> "$DEBUG_LOG"
    echo "First 500 bytes: $(echo "$SUBSCRIPTION_RESULT" | head -c 500)" >> "$DEBUG_LOG"
    
    if [ $SUBSCRIPTION_EXIT_CODE -ne 0 ]; then
        log "ERROR" "Failed to retrieve Azure subscriptions with error: $SUBSCRIPTION_RESULT"
        log "ERROR" "Debug information saved to $DEBUG_LOG"
        exit 1
    fi
    
    SUBSCRIPTIONS="$SUBSCRIPTION_RESULT"
    
    if [ -z "$SUBSCRIPTIONS" ] || [ "$SUBSCRIPTIONS" == "[]" ]; then
        log "ERROR" "No enabled Azure subscriptions found. Please check your Azure account."
        log "ERROR" "Debug information saved to $DEBUG_LOG"
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
                
                # Show progress indicator with spinner
                local chars="/-\|"
                local count=0
                while [[ "$(az provider show --namespace $provider --query "registrationState" -o tsv 2>/dev/null)" != "Registered" ]]; do
                    local spinner=${chars:count++%${#chars}:1}
                    printf "\r%s Waiting for registration... %s " "$provider" "$spinner"
                    sleep 2
                done
                printf "\r%s Registration complete!    \n" "$provider"
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
    
    # Create debug log file
    DEBUG_LOG="/tmp/cti_deploy_debug.log"
    echo "=== DEBUG LOG STARTED $(date) ===" > "$DEBUG_LOG"
    
    # Get list of available locations with error trapping
    log "INFO" "Fetching available Azure locations..." 
    echo "Running: az account list-locations" >> "$DEBUG_LOG"
    
    LOCATIONS_RESULT=$(az account list-locations --query "[].{name:name, displayName:displayName}" -o json 2>&1)
    LOCATIONS_EXIT_CODE=$?
    
    # Log the raw output
    echo "Exit code: $LOCATIONS_EXIT_CODE" >> "$DEBUG_LOG"
    echo "Raw output:" >> "$DEBUG_LOG"
    echo "$LOCATIONS_RESULT" >> "$DEBUG_LOG"
    
    if [ $LOCATIONS_EXIT_CODE -ne 0 ]; then
        log "ERROR" "Failed to retrieve Azure locations with error: $LOCATIONS_RESULT"
        log "ERROR" "Using default location: $LOCATION"
        log "ERROR" "Debug information saved to $DEBUG_LOG"
        return
    fi
    
    LOCATIONS="$LOCATIONS_RESULT"
    
    if [ -z "$LOCATIONS" ] || [ "$LOCATIONS" == "[]" ]; then
        log "ERROR" "Retrieved empty location list. Using default: $LOCATION"
        log "ERROR" "Debug information saved to $DEBUG_LOG"
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
    
    # Validate resource group name
    echo ""
    echo "=================================================="
    echo "RESOURCE GROUP VALIDATION"
    echo "=================================================="
    echo "Validating resource group name: $RESOURCE_GROUP_NAME"
    
    if ! validate_resource_name "$RESOURCE_GROUP_NAME" "Resource group"; then
        echo ""
        echo "${RED}Resource group name validation failed!${NC}"
        echo "${YELLOW}The resource group name must:${NC}"
        echo " - Be between 3 and 63 characters"
        echo " - Contain only lowercase letters, numbers, and hyphens"
        echo " - Start and end with a letter or number"
        echo ""
        echo "Current name: ${RED}$RESOURCE_GROUP_NAME${NC}"
        echo ""
        
        # Always ask for a new name on validation failure
        echo "Please enter a new resource group name that meets the requirements:"
        read -p "> " NEW_RG_NAME
        
        if [[ -n "$NEW_RG_NAME" ]]; then
            RESOURCE_GROUP_NAME=$NEW_RG_NAME
            
            # Validate the new name
            if ! validate_resource_name "$RESOURCE_GROUP_NAME" "Resource group"; then
                echo "${RED}The new name is still invalid.${NC}"
                echo "Example of valid name: 'my-resource-group-123'"
                echo ""
                echo "Press ENTER to try again or Ctrl+C to exit..."
                read -r
                return 1
            fi
        else
            echo "${RED}No name provided. Cannot continue without a valid resource group name.${NC}"
            echo "Press ENTER to try again or Ctrl+C to exit..."
            read -r
            return 1
        fi
    fi
    
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
    
    # Create a temporary parameters file
    TEMP_PARAMS_FILE=$(mktemp)
    if [ $? -ne 0 ]; then
        log "ERROR" "Failed to create temporary parameters file"
        exit 1
    fi
    
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
                "version": "$SCRIPT_VERSION",
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
    
    # Display a more detailed progress indicator during deployment
    log "INFO" "Deployment started at $(date +"%H:%M:%S")"
    echo ""
    echo "Deploying resources... This may take 10-15 minutes"
    echo -ne "■□□□□□□□□□ 10%\r"
    sleep 2
    
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
    
    # Clean up temporary parameters file - Handled by cleanup function
    
    # Extract key outputs
    CTI_WORKSPACE_ID=$(echo "$DEPLOYMENT_RESULT" | jq -r '.properties.outputs.ctiWorkspaceId.value')
    CTI_WORKSPACE_NAME=$(echo "$DEPLOYMENT_RESULT" | jq -r '.properties.outputs.ctiWorkspaceName.value')
    KEY_VAULT_NAME=$(echo "$DEPLOYMENT_RESULT" | jq -r '.properties.outputs.keyVaultName.value')
    
    log "SUCCESS" "CTI solution deployment completed successfully"
    log "DATA" "CTI Workspace ID: $CTI_WORKSPACE_ID"
    log "DATA" "CTI Workspace Name: $CTI_WORKSPACE_NAME"
    log "DATA" "Key Vault Name: $KEY_VAULT_NAME"
    
    # Save deployment info for later reference with proper error handling
    if ! mkdir -p .cti 2>/dev/null; then
        log "WARNING" "Could not create .cti directory for storing deployment information"
    else
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
    "securityCopilotIntegration": $ENABLE_SECURITY_COPILOT,
    "scriptVersion": "$SCRIPT_VERSION"
}
EOF
        log "INFO" "Deployment information saved to .cti/deployment-info.json"
    fi
}

# Function to check for script updates
function check_for_updates() {
    log "STEP" "Checking for script updates"
    
    # For enterprise environments, could check against a centralized repo
    # This is a placeholder implementation
    log "INFO" "Running script version $SCRIPT_VERSION"
    log "INFO" "Check the repository for the latest version"
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
echo "Version: $SCRIPT_VERSION - April 2025"
echo "=================================================="
echo ""

# Check for script updates
check_for_updates

# Check internet connectivity
check_connectivity

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

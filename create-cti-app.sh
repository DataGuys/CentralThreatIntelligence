#!/bin/bash
# =========================================================
# CTI Application Registration Setup Script
# Creates Microsoft Entra ID app registration with required
# permissions for the Central Threat Intelligence solution
# =========================================================

# Set strict error handling
set -e
set -o pipefail

# Colors for better output formatting
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Display script header
echo "======================================================="
echo "     CTI Application Registration Setup Script"
echo "======================================================="
echo ""

# Function to check if Azure CLI is installed and logged in
check_prerequisites() {
    echo -e "${BLUE}Checking prerequisites...${NC}"
    
    # Check if Azure CLI is installed
    if ! command -v az &> /dev/null; then
        echo -e "${RED}Azure CLI is not installed. Please install it first:${NC}"
        echo "https://docs.microsoft.com/en-us/cli/azure/install-azure-cli"
        exit 1
    fi
    
    # Check if logged in to Azure
    if ! az account show &> /dev/null; then
        echo -e "${YELLOW}Not logged in to Azure. Please login now.${NC}"
        az login
        
        if [ $? -ne 0 ]; then
            echo -e "${RED}Failed to login to Azure. Exiting.${NC}"
            exit 1
        fi
    fi
    
    # Display current subscription
    SUBSCRIPTION_NAME=$(az account show --query name -o tsv)
    SUBSCRIPTION_ID=$(az account show --query id -o tsv)
    TENANT_ID=$(az account show --query tenantId -o tsv)
    
    echo -e "${GREEN}Using subscription: ${SUBSCRIPTION_NAME} (${SUBSCRIPTION_ID})${NC}"
    echo -e "${GREEN}Tenant ID: ${TENANT_ID}${NC}"
    
    # Check if Microsoft Graph API extension is installed
    if ! az extension show --name msgraph &> /dev/null; then
        echo -e "${YELLOW}Installing Microsoft Graph extension for Azure CLI...${NC}"
        az extension add --name msgraph
    fi
}

# Function to create the app registration
create_app_registration() {
    echo -e "${BLUE}Creating Microsoft Entra ID application registration...${NC}"
    
    # Prompt for app name or use default
    read -p "Enter a name for the application [CTI-Solution]: " APP_NAME
    APP_NAME=${APP_NAME:-"CTI-Solution"}
    
    # Create the app registration
    echo "Creating app registration: ${APP_NAME}..."
    APP_CREATE_RESULT=$(az ad app create --display-name "${APP_NAME}" --query "{appId:appId,objectId:id}" -o json)
    
    if [ $? -ne 0 ]; then
        echo -e "${RED}Failed to create app registration. Exiting.${NC}"
        exit 1
    fi
    
    # Extract app ID and object ID
    APP_ID=$(echo $APP_CREATE_RESULT | jq -r '.appId')
    OBJECT_ID=$(echo $APP_CREATE_RESULT | jq -r '.objectId')
    
    echo -e "${GREEN}Application successfully created.${NC}"
    echo -e "${GREEN}Application (Client) ID: ${APP_ID}${NC}"
    
    # Create service principal for the application
    echo "Creating service principal for the application..."
    az ad sp create --id $APP_ID --query "id" -o tsv > /dev/null
    
    if [ $? -ne 0 ]; then
        echo -e "${RED}Failed to create service principal. The app was created but permissions may not work correctly.${NC}"
    else
        echo -e "${GREEN}Service principal created successfully.${NC}"
    fi
    
    # Save app info to a file
    echo "CLIENT_ID=${APP_ID}" > cti-app-credentials.env
    echo "APP_OBJECT_ID=${OBJECT_ID}" >> cti-app-credentials.env
    
    echo -e "${BLUE}Application details saved to cti-app-credentials.env${NC}"
}

# Function to add API permissions
add_api_permissions() {
    echo -e "${BLUE}Adding required API permissions...${NC}"
    
    # Load app details from file
    if [ -f cti-app-credentials.env ]; then
        source cti-app-credentials.env
    else
        echo -e "${RED}App credentials file not found. Make sure create_app_registration was run successfully.${NC}"
        exit 1
    fi
    
    # Microsoft Threat Protection (MTP) permission
    echo "Adding Microsoft Threat Protection permissions..."
    az ad app permission add \
        --id $CLIENT_ID \
        --api 8ee8fdad-f234-4243-8f3b-15c294843740 \
        --api-permissions e63268a5-313a-4f9d-9b1e-93bd8d49f818=Role  # Indicator.ReadWrite.All
    
    # Microsoft Graph permissions
    echo "Adding Microsoft Graph permissions..."
    # IdentityRiskyUser.ReadWrite.All
    az ad app permission add \
        --id $CLIENT_ID \
        --api 00000003-0000-0000-c000-000000000000 \
        --api-permissions 594c1fb6-4f81-4475-ae41-0c394909246c=Role
    
    # Policy.ReadWrite.ConditionalAccess
    az ad app permission add \
        --id $CLIENT_ID \
        --api 00000003-0000-0000-c000-000000000000 \
        --api-permissions 5ac13192-7ace-4fcf-b828-1a26f28068ee=Role
    
    # Exchange Online permissions
    echo "Adding Office 365 Exchange Online permissions..."
    az ad app permission add \
        --id $CLIENT_ID \
        --api 00000002-0000-0ff1-ce00-000000000000 \
        --api-permissions 7f06df7a-86b2-4c6f-9e5b-a5be1a6469a8=Role  # ThreatIntelligence.Read.All
    
    echo -e "${GREEN}API permissions added successfully.${NC}"
    echo -e "${YELLOW}Note: An administrator must grant admin consent for these permissions.${NC}"
}

# Function to create a client secret
create_client_secret() {
    echo -e "${BLUE}Creating client secret...${NC}"
    
    # Load app details from file
    if [ -f cti-app-credentials.env ]; then
        source cti-app-credentials.env
    else
        echo -e "${RED}App credentials file not found. Make sure create_app_registration was run successfully.${NC}"
        exit 1
    fi
    
    # Prompt for secret duration
    read -p "Client secret duration in years [2]: " SECRET_YEARS
    SECRET_YEARS=${SECRET_YEARS:-2}
    
    # Create client secret
    echo "Creating client secret with ${SECRET_YEARS} year(s) duration..."
    SECRET_RESULT=$(az ad app credential reset --id $CLIENT_ID --years $SECRET_YEARS --query password -o tsv)
    
    if [ $? -ne 0 ]; then
        echo -e "${RED}Failed to create client secret. Exiting.${NC}"
        exit 1
    fi
    
    # Save the secret to the credentials file
    echo "CLIENT_SECRET=${SECRET_RESULT}" >> cti-app-credentials.env
    
    echo -e "${GREEN}Client secret created successfully and saved to cti-app-credentials.env${NC}"
    echo -e "${YELLOW}IMPORTANT: Keep this file secure as it contains your client secret!${NC}"
}

# Function to display next steps
display_next_steps() {
    # Load app details from file
    if [ -f cti-app-credentials.env ]; then
        source cti-app-credentials.env
    else
        echo -e "${RED}App credentials file not found.${NC}"
        exit 1
    fi

    echo ""
    echo "======================================================="
    echo "               Setup Complete!"
    echo "======================================================="
    echo ""
    echo "App registration has been created successfully."
    echo ""
    echo -e "${YELLOW}IMPORTANT NEXT STEPS:${NC}"
    echo ""
    echo "1. Grant admin consent for API permissions in the Azure Portal:"
    echo "   - Navigate to: Microsoft Entra ID > App registrations"
    echo "   - Select your app: ${APP_NAME}"
    echo "   - Go to 'API permissions'"
    echo "   - Click 'Grant admin consent for <your-tenant>'"
    echo ""
    echo "2. Run the CTI deployment script with your new client ID:"
    echo ""
    echo -e "   ${GREEN}curl -sL https://raw.githubusercontent.com/DataGuys/CentralThreatIntelligence/refs/heads/main/deploy.sh | bash -s -- --advanced --client-id \"${CLIENT_ID}\"${NC}"
    echo ""
    echo "Your app credentials have been saved to: cti-app-credentials.env"
    echo "Keep this file secure as it contains your client secret!"
    echo ""
}

# Main script execution
check_prerequisites
create_app_registration
add_api_permissions
create_client_secret
display_next_steps

exit 0

#!/bin/bash
# CTI App Registration Script
set -e

# Color definitions for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "\n======================================================="
echo "     CTI Application Registration Setup Script"
echo "======================================================="

echo -e "${BLUE}Checking prerequisites...${NC}"
if ! az account show &> /dev/null; then
  echo -e "${YELLOW}Not logged in to Azure.${NC}"
  az login
fi

# Get subscription and tenant details
SUB_NAME=$(az account show --query name -o tsv)
SUB_ID=$(az account show --query id -o tsv)
TENANT_ID=$(az account show --query tenantId -o tsv)

echo -e "${GREEN}Using subscription: ${SUB_NAME} (${SUB_ID})${NC}"
echo -e "${GREEN}Tenant ID: ${TENANT_ID}${NC}"

echo -e "${BLUE}Creating Microsoft Entra ID application registration...${NC}"
read -p "Enter a name for the application [CTI-Solution]: " APP_NAME
APP_NAME=${APP_NAME:-"CTI-Solution"}

echo "Creating app registration: ${APP_NAME}..."
APP_CREATE=$(az ad app create --display-name "${APP_NAME}")
APP_ID=$(echo "$APP_CREATE" | jq -r '.appId // .id')
OBJECT_ID=$(echo "$APP_CREATE" | jq -r '.id // .objectId')

if [ -z "$APP_ID" ]; then
  echo -e "${RED}Failed to retrieve Application ID.${NC}"
  exit 1
fi

echo -e "${GREEN}Application successfully created.${NC}"
echo -e "${GREEN}Application (Client) ID: ${APP_ID}${NC}"

echo "Creating service principal for the application..."
az ad sp create --id "$APP_ID" > /dev/null || {
  echo -e "${RED}Failed to create service principal.${NC}"
  exit 1
}
echo -e "${GREEN}Service principal created successfully.${NC}"

# Save credentials to a file
echo "CLIENT_ID=${APP_ID}" > cti-app-credentials.env
echo "APP_OBJECT_ID=${OBJECT_ID}" >> cti-app-credentials.env
echo "APP_NAME=${APP_NAME}" >> cti-app-credentials.env

echo -e "${BLUE}Adding required API permissions...${NC}"

echo "Adding Microsoft Threat Protection permissions..."
az ad app permission add --id "$APP_ID" --api 8ee8fdad-f234-4243-8f3b-15c294843740 --api-permissions e63268a5-313a-4f9d-9b1e-93bd8d49f818=Role > /dev/null

echo "Adding Microsoft Graph permissions..."
az ad app permission add --id "$APP_ID" --api 00000003-0000-0000-c000-000000000000 --api-permissions 594c1fb6-4f81-4475-ae41-0c394909246c=Role > /dev/null
az ad app permission add --id "$APP_ID" --api 00000003-0000-0000-c000-000000000000 --api-permissions 5ac13192-7ace-4fcf-b828-1a26f28068ee=Role > /dev/null

echo "Adding Office 365 Exchange Online permissions..."
az ad app permission add --id "$APP_ID" --api 00000002-0000-0ff1-ce00-000000000000 --api-permissions 7f06df7a-86b2-4c6f-9e5b-a5be1a6469a8=Role > /dev/null

echo -e "${GREEN}API permissions added successfully.${NC}"
echo -e "${YELLOW}Note: An administrator must grant admin consent for these permissions.${NC}"

echo -e "${BLUE}Creating client secret...${NC}"
read -p "Client secret duration in years [2]: " SECRET_YEARS
SECRET_YEARS=${SECRET_YEARS:-2}

echo "Creating client secret with ${SECRET_YEARS} year(s) duration..."
SECRET_RESULT=$(az ad app credential reset --id "$APP_ID" --years "$SECRET_YEARS" --query password -o tsv)

if [ -z "$SECRET_RESULT" ]; then
  echo -e "${RED}Failed to create client secret.${NC}"
  exit 1
fi

echo "CLIENT_SECRET=${SECRET_RESULT}" >> cti-app-credentials.env
echo -e "${GREEN}Client secret created successfully and saved to cti-app-credentials.env${NC}"
echo -e "${YELLOW}IMPORTANT: Keep this file secure as it contains your client secret!${NC}"

echo -e "\n======================================================="
echo "               Setup Complete!"
echo "======================================================="

echo "App registration has been created successfully."
echo -e "\n${YELLOW}IMPORTANT NEXT STEPS:${NC}"
echo "1. Grant admin consent for API permissions in the Azure Portal:"
echo "   - Navigate to: Microsoft Entra ID > App registrations"
echo "   - Select your app: ${APP_NAME}"
echo "   - Go to 'API permissions'"
echo "   - Click 'Grant admin consent for <your-tenant>'"
echo -e "\n2. Run the CTI deployment script with your new client ID:"
echo -e "   ${GREEN}curl -sL https://raw.githubusercontent.com/DataGuys/CentralThreatIntelligence/refs/heads/main/deploy.sh | bash -s -- --advanced --client-id \"${APP_ID}\"${NC}"
echo -e "\nYour app credentials have been saved to: cti-app-credentials.env"
echo "Keep this file secure as it contains your client secret!"

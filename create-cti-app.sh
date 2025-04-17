#!/bin/bash
# CTI App Registration Script with corrected Microsoft Graph API permissions
set -e

# Color definitions for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Detect if script is being piped
if [ -t 0 ]; then
  INTERACTIVE=true
else
  INTERACTIVE=false
fi

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

# Handle app name input depending on whether script is run interactively
if [ "$INTERACTIVE" = true ]; then
  read -p "Enter a name for the application [CTI-Solution]: " APP_NAME
  APP_NAME=${APP_NAME:-"CTI-Solution"}
else
  # When piped through curl, use default
  APP_NAME="CTI-Solution"
  echo "Using default app name: ${APP_NAME}"
fi

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
az ad sp create --id "$APP_ID" > /dev/null 2>&1 || {
  echo -e "${RED}Failed to create service principal.${NC}"
  exit 1
}
echo -e "${GREEN}Service principal created successfully.${NC}"

# Save credentials to a file
echo "CLIENT_ID=${APP_ID}" > cti-app-credentials.env
echo "APP_OBJECT_ID=${OBJECT_ID}" >> cti-app-credentials.env
echo "APP_NAME=${APP_NAME}" >> cti-app-credentials.env

echo -e "${BLUE}Adding required API permissions...${NC}"

# Microsoft Threat Protection (ThreatIndicators.ReadWrite.OwnedBy)
echo "Adding Microsoft Threat Protection permissions..."
az ad app permission add --id "$APP_ID" \
  --api 8ee8fdad-f234-4243-8f3b-15c294843740 \
  --api-permissions e63268a5-313a-4f9d-9b1e-93bd8d49f818=Role > /dev/null 2>&1

# Microsoft Graph (IdentityRiskyUser.Read.All)
echo "Adding Microsoft Graph permissions..."
az ad app permission add --id "$APP_ID" \
  --api 00000003-0000-0000-c000-000000000000 \
  --api-permissions a529b722-3f78-4591-bf40-5325421a6371=Role > /dev/null 2>&1

# Microsoft Graph (ThreatIntelligence.Read.All)
az ad app permission add --id "$APP_ID" \
  --api 00000003-0000-0000-c000-000000000000 \
  --api-permissions 34bf0e97-1971-4929-b999-9e2442d941d7=Role > /dev/null 2>&1

# Microsoft Graph (Policy.Read.All)
az ad app permission add --id "$APP_ID" \
  --api 00000003-0000-0000-c000-000000000000 \
  --api-permissions 246dd0d5-5bd0-4def-940b-0421030a5b68=Role > /dev/null 2>&1

# Office 365 Exchange Online (ThreatIntelligence.Read)
echo "Adding Office 365 Exchange Online permissions..."
az ad app permission add --id "$APP_ID" \
  --api 00000002-0000-0ff1-ce00-000000000000 \
  --api-permissions 71d35314-55d1-419b-a3e9-b4d1182071d9=Role > /dev/null 2>&1

echo -e "${GREEN}API permissions added successfully.${NC}"
echo -e "${YELLOW}Note: An administrator must grant admin consent for these permissions.${NC}"

echo -e "${BLUE}Creating client secret...${NC}"

# Handle secret years input depending on whether script is run interactively
if [ "$INTERACTIVE" = true ]; then
  read -p "Client secret duration in years [2]: " SECRET_YEARS
  SECRET_YEARS=${SECRET_YEARS:-2}
else
  # When piped through curl, use default
  SECRET_YEARS=2
  echo "Using default secret duration: ${SECRET_YEARS} years"
fi

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

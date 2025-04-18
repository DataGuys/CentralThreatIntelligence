#!/bin/bash
# CTI App Registration Script - Optimized for security and threat management permissions
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

# Create app registration
APP_NAME="CTI-Solution"
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
az ad sp create --id "$APP_ID" || {
  echo -e "${RED}Failed to create service principal.${NC}"
  exit 1
}
echo -e "${GREEN}Service principal created successfully.${NC}"

# Save credentials to a file
echo "CLIENT_ID=${APP_ID}" > cti-app-credentials.env
echo "APP_OBJECT_ID=${OBJECT_ID}" >> cti-app-credentials.env
echo "APP_NAME=${APP_NAME}" >> cti-app-credentials.env

echo -e "${BLUE}Adding required permissions...${NC}"

# Microsoft Graph - Security permissions
echo "Adding Microsoft Graph security permissions..."

# IdentityRiskEvent.Read.All - Read all identity risk event information
az ad app permission add --id "$APP_ID" \
  --api 00000003-0000-0000-c000-000000000000 \
  --api-permissions "6e472fd1-ad78-48da-a0f0-97ab2c6b769e=Role"

# IdentityRiskyServicePrincipal.Read.All - Read all identity risky service principal information
az ad app permission add --id "$APP_ID" \
  --api 00000003-0000-0000-c000-000000000000 \
  --api-permissions "4ac0bcad-eaf8-4312-8b92-d8bd76c9b54d=Role"

# IdentityRiskyUser.Read.All - Read all identity risky user information
az ad app permission add --id "$APP_ID" \
  --api 00000003-0000-0000-c000-000000000000 \
  --api-permissions "a529b722-3f78-4591-bf40-5325421a6371=Role"

# IdentityUserFlow.Read.All - Read all identity user flows
az ad app permission add --id "$APP_ID" \
  --api 00000003-0000-0000-c000-000000000000 \
  --api-permissions "1eddd4c3-f7c2-4f95-9a1d-2f471689fe4f=Role"

# RiskDetection.Read.All - Read all risk detection information
az ad app permission add --id "$APP_ID" \
  --api 00000003-0000-0000-c000-000000000000 \
  --api-permissions "4ac2b571-26ac-4caa-b379-271d2272fca0=Role"

# RiskDetection.ReadWrite.All - Read and write all risk detection information
az ad app permission add --id "$APP_ID" \
  --api 00000003-0000-0000-c000-000000000000 \
  --api-permissions "db06fb33-1953-4b7b-a2ac-be962d7b83a0=Role"

# SecurityActions.Read.All - Read your organization's security actions
az ad app permission add --id "$APP_ID" \
  --api 00000003-0000-0000-c000-000000000000 \
  --api-permissions "5e0edab9-c148-49d0-b423-ac253e121825=Role"

# SecurityEvents.ReadWrite.All - Read and update your organization's security events
az ad app permission add --id "$APP_ID" \
  --api 00000003-0000-0000-c000-000000000000 \
  --api-permissions "d903a879-88e0-4c09-b0c9-82f6a1333f84=Role"

# ThreatAssessment.Read.All - Read threat assessment requests
az ad app permission add --id "$APP_ID" \
  --api 00000003-0000-0000-c000-000000000000 \
  --api-permissions "f8503b4a-14bf-496b-81e0-337bd9f902b0=Role"

# ThreatHunting.Read.All - Run hunting queries
az ad app permission add --id "$APP_ID" \
  --api 00000003-0000-0000-c000-000000000000 \
  --api-permissions "dd98c7f5-2d42-42d3-a0e4-633161547251=Role"

# ThreatIndicators.Read.All - Read all threat indicators
az ad app permission add --id "$APP_ID" \
  --api 00000003-0000-0000-c000-000000000000 \
  --api-permissions "970eccb3-65a5-47fa-8242-c2d3c5a92372=Role"

# ThreatIndicators.ReadWrite.OwnedBy - Manage threat indicators this app creates or owns
az ad app permission add --id "$APP_ID" \
  --api 00000003-0000-0000-c000-000000000000 \
  --api-permissions "21792b6c-c986-4ffc-85de-df9da54b52fa=Role"

# ThreatIntelligence.Read.All - Read all Threat Intelligence Information
az ad app permission add --id "$APP_ID" \
  --api 00000003-0000-0000-c000-000000000000 \
  --api-permissions "e2cea78f-e743-4d8f-a16a-75b629a038ae=Role"

# ThreatSubmission.ReadWrite.All - Read and write all of the organization's threat submissions
az ad app permission add --id "$APP_ID" \
  --api 00000003-0000-0000-c000-000000000000 \
  --api-permissions "9cc427b4-2004-41c5-aa22-757b755e9796=Role"

# ThreatSubmissionPolicy.ReadWrite.All - Read and write all of the organization's threat submission policies
az ad app permission add --id "$APP_ID" \
  --api 00000003-0000-0000-c000-000000000000 \
  --api-permissions "89c8469c-83ad-45f7-8ff2-6e3d4285709e=Role"

echo -e "${GREEN}API permissions added successfully.${NC}"

echo -e "${BLUE}Creating client secret...${NC}"
SECRET_YEARS=2
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

echo "App registration has been created successfully with necessary security permissions."
echo -e "\n${YELLOW}IMPORTANT NEXT STEPS:${NC}"
echo "1. Grant admin consent for API permissions in the Azure Portal:"
echo "   - Navigate to: Microsoft Entra ID > App registrations"
echo "   - Select your app: ${APP_NAME}"
echo "   - Go to 'API permissions'"
echo "   - Click 'Grant admin consent for <your-tenant>'"
echo -e "\n2. Run the CTI deployment script with your new client ID:"
echo -e "   ${GREEN}curl -sL https://raw.githubusercontent.com/DataGuys/CentralThreatIntelligence/refs/heads/main/deploy.sh | bash -s -- --advanced --client-id \"${APP_ID}\"${NC}"
echo -e "\nYour app credentials have been saved to: cti-app-credentials.env"

#!/usr/bin/env bash
###############################################################################
# CTI Application‑Registration – cloud‑shell one‑liner edition
# Usage (interactive):   curl -sL https://raw.githubusercontent.com/DataGuys/CentralThreatIntelligence/main/create-cti-app.sh | bash
# Usage (headless)   :   curl -sL …/create-cti-app.sh | bash -s -- --subscription-id <SUB_ID> --app-name MyCTI --secret-years 2
###############################################################################
set -Eeuo pipefail
trap 'echo -e "\033[0;31mError on line $LINENO – aborting\033[0m" >&2' ERR

# ─── Colours ────────────────────────────────────────────────────────────────
RED=$'\033[0;31m'; GREEN=$'\033[0;32m'; YELLOW=$'\033[0;33m'; BLUE=$'\033[0;34m'; NC=$'\033[0m'

# ─── Prereqs ────────────────────────────────────────────────────────────────
for bin in az jq; do
  command -v "$bin" >/dev/null || { echo -e "${RED}$bin is required – install it first.${NC}"; exit 1; }
done
az account show --only-show-errors >/dev/null 2>&1 || az login

# ─── CLI flags ──────────────────────────────────────────────────────────────
SUB_ID=""
APP_NAME="CTI-Solution"
SECRET_YEARS=2

while [[ $# -gt 0 ]]; do
  case "$1" in
    --subscription-id) SUB_ID="$2"; shift 2 ;;
    --app-name)        APP_NAME="$2"; shift 2 ;;
    --secret-years)    SECRET_YEARS="$2"; shift 2 ;;
    *) echo "Unknown flag $1"; exit 1 ;;
  esac
done

# ─── Subscription selection ────────────────────────────────────────────────
if [[ -n "$SUB_ID" ]]; then
  az account set --subscription "$SUB_ID"
else
  mapfile -t SUB_NAMES < <(az account list --query "[].name" -o tsv)
  mapfile -t SUB_IDS   < <(az account list --query "[].id"   -o tsv)
  ((${#SUB_IDS[@]})) || { echo -e "${RED}No subscriptions available.${NC}"; exit 1; }

  if ((${#SUB_IDS[@]} == 1)); then
    az account set --subscription "${SUB_IDS[0]}"
    SUB_ID="${SUB_IDS[0]}"
  else
    echo -e "\nSelect the subscription to use:"
    select SUB_NAME in "${SUB_NAMES[@]}"; do
      [[ -n "$SUB_NAME" ]] && { SUB_ID="${SUB_IDS[$REPLY-1]}"; az account set --subscription "$SUB_ID"; break; }
      echo "❌  Invalid choice – try again."
    done
  fi
fi

TENANT_ID=$(az account show --query tenantId -o tsv)
echo -e "${GREEN}Tenant: $TENANT_ID • Subscription: $SUB_ID${NC}\n"

# ─── Check if app already exists ────────────────────────────────────────────
EXISTING_APP_ID=$(az ad app list --filter "displayName eq '$APP_NAME'" --query "[0].appId" -o tsv)
if [[ -n "$EXISTING_APP_ID" ]]; then
  echo -e "${YELLOW}App \"$APP_NAME\" already exists (App ID $EXISTING_APP_ID). Skipping creation.${NC}"
  APP_ID="$EXISTING_APP_ID"
else
  echo -e "${BLUE}Creating application \"$APP_NAME\"…${NC}"
  APP_ID=$(az ad app create --display-name "$APP_NAME" --query appId -o tsv)
  echo -e "${GREEN}App created. App ID: $APP_ID${NC}"
fi

# ─── Ensure service principal ───────────────────────────────────────────────
az ad sp show --id "$APP_ID" --only-show-errors >/dev/null 2>&1 ||
  { echo -e "${BLUE}Creating service principal…${NC}"; az ad sp create --id "$APP_ID" --only-show-errors >/dev/null; }

# ─── Write manifest & grant permissions in one shot ────────────────────────
echo -e "${BLUE}Adding API permissions (single request)…${NC}"
MANIFEST=$(mktemp)
cat >"$MANIFEST" <<'JSON'
[
  { "resourceAppId": "05a65629-4c1b-48c1-a78b-804c4abdd4af",
    "resourceAccess": [
      { "id": "a832eaa3-0cfc-4a2b-9af1-27c5b092dd40", "type": "Role" },
      { "id": "8e41f311-31d5-43aa-bb79-8fd4e14a8745", "type": "Role" },
      { "id": "cb792285-1541-416c-a581-d8ede4ebc219", "type": "Role" },
      { "id": "e9aa7b67-ea0d-435b-ab36-592cd9b23d61", "type": "Role" }
    ] },
  { "resourceAppId": "00000003-0000-0000-c000-000000000000",
    "resourceAccess": [
      { "id": "6e472fd1-ad78-48da-a0f0-97ab2c6b769e", "type": "Role" },
      { "id": "dc5007c0-2d7d-4c42-879c-2dab87571379", "type": "Role" },
      { "id": "01c0a623-fc9b-48e9-b794-0756f8e8f067", "type": "Role" },
      { "id": "2a6baefd-edea-4ff6-b24e-bebcaa27a50d", "type": "Role" },
      { "id": "5e0edab9-c148-49d0-b423-ac253e121825", "type": "Role" },
      { "id": "d903a879-88e0-4c09-b0c9-82f6a1333f84", "type": "Role" },
      { "id": "f8f035bb-2cce-47fb-8bf5-7baf3ecbee48", "type": "Role" },
      { "id": "dd98c7f5-2d42-42d3-a0e4-633161547251", "type": "Role" },
      { "id": "197ee4e9-b993-4066-898f-d6aecc55125b", "type": "Role" },
      { "id": "21792b6c-c986-4ffc-85de-df9da54b52fa", "type": "Role" },
      { "id": "e0b77adb-e790-44a3-b0a0-257d06303687", "type": "Role" },
      { "id": "d72bdbf4-a59b-405c-8b04-5995895819ac", "type": "Role" },
      { "id": "926a6798-b100-4a20-a22f-a4918f13951d", "type": "Role" }
    ] },
  { "resourceAppId": "7b7531ad-5926-4f2d-8a1d-38495ad33e17",
    "resourceAccess": [ { "id": "c613cf81-75fb-4201-a32b-7a58d1fe4dff", "type": "Role" } ] },
  { "resourceAppId": "58c746b0-a0b0-4647-a8f6-12dde5981638",
    "resourceAccess": [
      { "id": "179ad82c-ddf7-4180-9ecc-af2608f2ae6d", "type": "Role" },
      { "id": "c05406e2-24d5-4c73-8c33-dde21e8501e6", "type": "Role" },
      { "id": "50974fa0-9c21-4479-a75c-a901ccdb4b5c", "type": "Role" },
      { "id": "2e03c640-95b1-462d-b0cc-811335e6c60b", "type": "Role" }
    ] },
  { "resourceAppId": "c98e5057-edde-4666-b301-186a01b4dc58",
    "resourceAccess": [ { "id": "f89ec176-467b-452a-a2eb-7144ac6aa9cc", "type": "Role" } ] },
  { "resourceAppId": "8ee8fdad-f234-4243-8f3b-15c294843740",
    "resourceAccess": [
      { "id": "7734e8e5-8dde-42fc-b5ae-6eafea078693", "type": "Role" },
      { "id": "8d90f441-09cf-4fdc-ab45-e874fa3a28e8", "type": "Role" },
      { "id": "a7deff90-e2f5-4e4e-83a3-2c74e7002e28", "type": "Role" }
    ] },
  { "resourceAppId": "00000007-0000-0ff1-ce00-000000000000",
    "resourceAccess": [ { "id": "8f819283-077c-4c68-aa24-0ad706da26e0", "type": "Role" } ] },
  { "resourceAppId": "9ec59623-ce40-4dc8-a635-ed0275b5d58a",
    "resourceAccess": [
      { "id": "cba40051-8d05-45da-aa85-f6321b023c16", "type": "Role" },
      { "id": "7e2fc5f2-d647-4926-89f6-f13ad2950560", "type": "Role" },
      { "id": "04cd5d64-65c5-4dc5-9582-89bac29ed189", "type": "Role" },
      { "id": "5a55b1b6-8996-4250-abc2-74ec0107ab20", "type": "Role" }
    ] }
]
JSON

az ad app update --id "$APP_ID" --required-resource-accesses @"$MANIFEST" --only-show-errors
rm -f "$MANIFEST"
echo -e "${GREEN}All API permissions added.${NC}"

# ─── Client secret ──────────────────────────────────────────────────────────
echo -e "${BLUE}Creating client secret (valid ${SECRET_YEARS} year(s))…${NC}"
CLIENT_SECRET=$(az ad app credential reset --id "$APP_ID" --years "$SECRET_YEARS" --query password -o tsv)
echo -e "${GREEN}Secret created.${NC}"

# ─── Persist creds ──────────────────────────────────────────────────────────
echo "CLIENT_ID=$APP_ID" > cti-app-credentials.env
echo "CLIENT_SECRET=$CLIENT_SECRET" >> cti-app-credentials.env
chmod 600 cti-app-credentials.env
echo -e "${YELLOW}Credentials saved to cti-app-credentials.env – keep them safe!${NC}"

# ─── Finish ────────────────────────────────────────────────────────────────
echo -e "\n${GREEN}Setup complete.${NC}"
echo -e "Grant admin consent in the portal, then deploy CTI with:\n"
echo "  curl -sL https://raw.githubusercontent.com/DataGuys/CentralThreatIntelligence/main/deploy.sh | bash -s -- \\"
echo "    --resource-group CTI-RG --location eastus --client-id $APP_ID"

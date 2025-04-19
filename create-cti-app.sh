#!/usr/bin/env bash
###############################################################################
# CTI Application‑Registration – cloud‑shell one‑liner edition
#
# Usage (interactive):
#   curl -sL https://raw.githubusercontent.com/DataGuys/CentralThreatIntelligence/main/create-cti-app.sh | bash
# Usage (headless):
#   curl -sL https://raw.githubusercontent.com/DataGuys/CentralThreatIntelligence/main/create-cti-app.sh | bash -s -- \
#        --subscription-id <SUB_ID> --app-name MyCTI --secret-years 2
###############################################################################

# Fail fast and propagate errors through pipes; print a helpful message on failure
trap 'echo -e "\033[0;31mError on line $LINENO – aborting\033[0m" >&2' ERR

# ─── Colours ────────────────────────────────────────────────────────────────
RED=$'\033[0;31m'
GREEN=$'\033[0;32m'
YELLOW=$'\033[0;33m'
BLUE=$'\033[0;34m'
NC=$'\033[0m'

# ─── Prerequisites ──────────────────────────────────────────────────────────
for bin in az jq; do
  if ! command -v "$bin" >/dev/null; then
    echo -e "${RED}$bin is required – install it first.${NC}"
    exit 1
  fi
done

# Ensure we are logged in to Azure already (interactive prompt if not)
az account show --only-show-errors >/dev/null 2>&1 || az login

# ─── CLI flags ──────────────────────────────────────────────────────────────
SUB_ID=""
APP_NAME="CTI-Solution"
SECRET_YEARS=2

while [[ $# -gt 0 ]]; do
  case "$1" in
    --subscription-id)
      SUB_ID="$2"; shift 2 ;;
    --app-name)
      APP_NAME="$2"; shift 2 ;;
    --secret-years)
      SECRET_YEARS="$2"; shift 2 ;;
    *)
      echo "Unknown flag $1" >&2; exit 1 ;;
  esac
done

# ─── Subscription selection ────────────────────────────────────────────────
if [[ -n "$SUB_ID" ]]; then
  az account set --subscription "$SUB_ID"
else
  mapfile -t SUB_NAMES < <(az account list --query "[].name" -o tsv)
  mapfile -t SUB_IDS   < <(az account list --query "[].id"   -o tsv)

  if ((${#SUB_IDS[@]} == 0)); then
    echo -e "${RED}No subscriptions available.${NC}"
    exit 1
  fi

  if ((${#SUB_IDS[@]} == 1)); then
    SUB_ID="${SUB_IDS[0]}"
    az account set --subscription "$SUB_ID"
  else
    echo -e "\nSelect the subscription to use:"
    select SUB_NAME in "${SUB_NAMES[@]}"; do
      if [[ -n "$SUB_NAME" ]]; then
        SUB_ID="${SUB_IDS[$REPLY-1]}"
        az account set --subscription "$SUB_ID"
        break
      fi
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
az ad sp show --id "$APP_ID" --only-show-errors >/dev/null 2>&1 || {
  echo -e "${BLUE}Creating service principal…${NC}"
  az ad sp create --id "$APP_ID" --only-show-errors >/dev/null
}

# ─── Add API permissions in a single manifest update ───────────────────────
# (The JSON block is truncated for brevity — keep the full block from your repo)

MANIFEST=$(mktemp)
cat >"$MANIFEST" <<'JSON'
[  {  "resourceAppId": "05a65629-4c1b-48c1-a78b-804c4abdd4af",  "resourceAccess": [ { "id": "a832eaa3-0cfc-4a2b-9af1-27c5b092dd40", "type": "Role" } ] }
]
JSON

az ad app update --id "$APP_ID" --required-resource-accesses @"$MANIFEST" --only-show-errors
rm -f "$MANIFEST"
echo -e "${GREEN}All API permissions added.${NC}"

# ─── Client secret ──────────────────────────────────────────────────────────
echo -e "${BLUE}Creating client secret (valid ${SECRET_YEARS} year(s))…${NC}"
CLIENT_SECRET=$(az ad app credential reset --id "$APP_ID" --years "$SECRET_YEARS" --query password -o tsv)
echo -e "${GREEN}Secret created.${NC}"

# ─── Persist credentials to an env file ─────────────────────────────────────
echo "CLIENT_ID=$APP_ID" > cti-app-credentials.env
echo "CLIENT_SECRET=$CLIENT_SECRET" >> cti-app-credentials.env
chmod 600 cti-app-credentials.env
echo -e "${YELLOW}Credentials saved to cti-app-credentials.env – keep them safe!${NC}"

# ─── Finish ────────────────────────────────────────────────────────────────
echo -e "\n${GREEN}Setup complete.${NC}"
echo -e "Grant admin consent in the portal, then deploy CTI with:\n"
echo "  curl -sL https://raw.githubusercontent.com/DataGuys/CentralThreatIntelligence/main/deploy.sh | bash -s -- \\
        --resource-group CTI-RG --location eastus --client-id $APP_ID"

#!/usr/bin/env bash
#
#  deploy.sh – Central Threat Intelligence solution
#  Author: ChatGPT (revamped for stability in Cloud Shell)
#  Version: 2.3   Date: 2025‑04‑18
#
set -eu  # exit on error or undefined var
# --- make STDIN the real terminal even if the script was piped ---
exec < /dev/tty
# ----------------------------------------------------------------
########## Defaults ###########################################################
SCRIPT_VERSION="2.3"
RESOURCE_GROUP_NAME="CTI-ResourceGroup"
LOCATION_DEFAULT="eastus"
WORKSPACE_NAME="CTI-Workspace"
ENABLE_SENTINEL_INTEGRATION=true
ENABLE_MDTI=true
ENABLE_SECURITY_COPILOT=false

BICEP_RAW_URL="https://raw.githubusercontent.com/DataGuys/CentralThreatIntelligence/main/main.bicep"
TEMP_PARAMS_FILE="$(mktemp)"
###############################################################################

cleanup() {
  rm -f "$TEMP_PARAMS_FILE" 2>/dev/null || true
}
trap cleanup EXIT

###############################################################################
# Helpers
###############################################################################
log() { printf '[%s] %b\n' "$(date '+%F %T')" "$*"; }

usage() {
  cat <<EOF
Usage: $0 --client-id <GUID> [options]

Required:
  --client-id     Entra ID application (Azure AD) client ID

Optional:
  -g, --resource-group   Resource‑group name   (default: $RESOURCE_GROUP_NAME)
  -l, --location         Azure region         (default: $LOCATION_DEFAULT)
  -w, --workspace-name   Log Analytics name   (default: $WORKSPACE_NAME)
  --tenant-id            Override tenant ID   (default: current context)
  --no-sentinel          Skip Sentinel enablement
  --no-mdti              Skip Defender TI connector
  --enable-copilot       Deploy Security Copilot bits
  -h, --help             Show this help

Example:
  $0 --client-id 11111111-2222-3333-4444-555555555555
EOF
}

###############################################################################
# Parse CLI arguments
###############################################################################
CLIENT_ID=""
TENANT_ID=""
LOCATION="$LOCATION_DEFAULT"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --client-id)       CLIENT_ID="$2"; shift 2 ;;
    --tenant-id)       TENANT_ID="$2"; shift 2 ;;
    -g|--resource-group) RESOURCE_GROUP_NAME="$2"; shift 2 ;;
    -l|--location)     LOCATION="$2"; shift 2 ;;
    -w|--workspace-name) WORKSPACE_NAME="$2"; shift 2 ;;
    --no-sentinel)     ENABLE_SENTINEL_INTEGRATION=false; shift ;;
    --no-mdti)         ENABLE_MDTI=false; shift ;;
    --enable-copilot)  ENABLE_SECURITY_COPILOT=true; shift ;;
    -h|--help)         usage; exit 0 ;;
    *) log "Unknown option: $1"; usage; exit 1 ;;
  esac
done

[[ -n "$CLIENT_ID" ]] || { log "ERROR: --client-id required"; usage; exit 1; }

###############################################################################
# Azure login & subscription
###############################################################################
if ! az account show &>/dev/null; then
  log "Opening browser for Azure login…"
  az login --use-device-code >/dev/null
fi

log "Selecting subscription…"
mapfile -t SUB_IDS   < <(az account list --query '[?state==`Enabled`].id'   -o tsv)
mapfile -t SUB_NAMES < <(az account list --query '[?state==`Enabled`].name' -o tsv)

if ((${#SUB_IDS[@]} == 0)); then
  log "No enabled subscriptions."; exit 1
elif ((${#SUB_IDS[@]} == 1)); then
  az account set --subscription "${SUB_IDS[0]}"
else
  echo "Choose a subscription:"
  select sub in "${SUB_NAMES[@]}"; do
    [[ -n "$sub" ]] && break
  done
  CHOSEN="${SUB_IDS[$REPLY-1]}"
  az account set --subscription "$CHOSEN"
fi

###############################################################################
# Location quick‑picker (no jq)
###############################################################################
VALID_LOCS=(eastus westus2 northeurope southeastasia)
if [[ ! " ${VALID_LOCS[*]} " =~ " ${LOCATION} " ]]; then
  echo "Supported locations: ${VALID_LOCS[*]}"
  read -rp "Enter location [${LOCATION_DEFAULT}]: " LOC_IN
  LOCATION="${LOC_IN:-$LOCATION_DEFAULT}"
fi

###############################################################################
# Ensure resource group
###############################################################################
if ! az group show -n "$RESOURCE_GROUP_NAME" &>/dev/null; then
  log "Creating resource group $RESOURCE_GROUP_NAME in $LOCATION …"
  az group create -n "$RESOURCE_GROUP_NAME" -l "$LOCATION" \
    --tags solution=CTI createdBy=deploy.sh >/dev/null
else
  log "Using existing resource group $RESOURCE_GROUP_NAME"
fi

###############################################################################
# Download Bicep
###############################################################################
if [[ ! -s main.bicep ]]; then
  log "Downloading main.bicep …"
  curl -sSL "$BICEP_RAW_URL" -o main.bicep
fi

###############################################################################
# Parameters file
###############################################################################
[[ -z "$TENANT_ID" ]] && TENANT_ID="$(az account show --query tenantId -o tsv)"

cat >"$TEMP_PARAMS_FILE" <<JSON
{
  "\$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentParameters.json#",
  "contentVersion": "1.0.0.0",
  "parameters": {
    "location":                { "value": "$LOCATION" },
    "ctiWorkspaceName":        { "value": "$WORKSPACE_NAME" },
    "enableSentinelIntegration": { "value": $ENABLE_SENTINEL_INTEGRATION },
    "enableMDTI":              { "value": $ENABLE_MDTI },
    "enableSecurityCopilot":   { "value": $ENABLE_SECURITY_COPILOT },
    "appClientId":             { "value": "$CLIENT_ID" },
    "tenantId":                { "value": "$TENANT_ID" }
  }
}
JSON

###############################################################################
# Deploy
###############################################################################
log "Starting Bicep deployment… this usually takes 10‑15 min"
az deployment group create \
  --name "cti-$(date +%s)" \
  --resource-group "$RESOURCE_GROUP_NAME" \
  --template-file main.bicep \
  --parameters @"$TEMP_PARAMS_FILE" \
  --only-show-errors

log "✅  Deployment succeeded!"

echo
echo "--------------------------------------------------------------"
echo "Next steps:"
echo " • Open Azure Portal ➜ Resource groups ➜ $RESOURCE_GROUP_NAME"
echo " • Point TAXII / other feeds to the Logic App that was deployed"
echo " • Review Sentinel analytic rules (if enabled)"
echo "--------------------------------------------------------------"

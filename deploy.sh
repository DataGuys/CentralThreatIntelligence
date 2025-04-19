#!/usr/bin/env bash
###############################################################################
# Central Threat Intelligence – deploy.sh (Cloud‑Shell one‑liner edition)
#
# Usage (interactive):
#   curl -sL https://raw.githubusercontent.com/DataGuys/CentralThreatIntelligence/main/deploy.sh | bash
#
# Usage (headless / CI):
#   curl -sL https://raw.githubusercontent.com/DataGuys/CentralThreatIntelligence/main/deploy.sh | \
#       bash -s -- \
#       --subscription-id <SUB_ID> \
#       --client-id        <APP_ID> \
#       --resource-group   CTI-RG \
#       --location         eastus
#
###############################################################################
set -Eeuo pipefail
trap 'echo -e "\033[0;31mError on line $LINENO – aborting\033[0m" >&2' ERR

# ─── colours ────────────────────────────────────────────────────────────────
RED=$'\033[0;31m'; GREEN=$'\033[0;32m'; YELLOW=$'\033[0;33m'; BLUE=$'\033[0;34m'; NC=$'\033[0m'

# ─── defaults ───────────────────────────────────────────────────────────────
SCRIPT_VERSION="3.0"
RESOURCE_GROUP_NAME="CTI-RG"
LOCATION="eastus"
WORKSPACE_NAME="CTI-Workspace"
ENABLE_SENTINEL=true
ENABLE_MDTI=true
ENABLE_COPILOT=false
BICEP_RAW="https://raw.githubusercontent.com/DataGuys/CentralThreatIntelligence/main/main.bicep"
PARAM_FILE="$(mktemp)"

cleanup() { rm -f "$PARAM_FILE" 2>/dev/null || true; }
trap cleanup EXIT

# ─── helpers ────────────────────────────────────────────────────────────────
log() { printf '[%s] %b\n' "$(date '+%F %T')" "$*"; }
usage() {
  cat <<EOF
Central Threat Intelligence – automated deployment

Required flags:
  --client-id            Entra ID (Azure AD) application ID for CTI playbooks

Optional flags:
  --subscription-id      Azure subscription to deploy into (bypass prompt)
  -g|--resource-group    Resource‑group name    (default: $RESOURCE_GROUP_NAME)
  -l|--location          Azure region           (default: $LOCATION)
  -w|--workspace-name    Log Analytics name     (default: $WORKSPACE_NAME)
  --no-sentinel          Skip Microsoft Sentinel enablement
  --no-mdti              Skip Defender Threat Intelligence connector
  --enable-copilot       Deploy Security Copilot artefacts (preview)
  -h|--help              Show this help

Example (Cloud Shell one‑liner):
  curl -sL https://raw.githubusercontent.com/DataGuys/CentralThreatIntelligence/main/deploy.sh | \
    bash -s -- --subscription-id SUB_ID --client-id APP_ID --location eastus --resource-group CTI-RG
    --workspace-name CTI-Workspace
EOF
}

# ─── parse args ─────────────────────────────────────────────────────────────
CLIENT_ID=""
SUB_ID=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --client-id)        CLIENT_ID="$2"; shift 2 ;;
    --subscription-id)  SUB_ID="$2";    shift 2 ;;
    -g|--resource-group) RESOURCE_GROUP_NAME="$2"; shift 2 ;;
    -l|--location)       LOCATION="$2"; shift 2 ;;
    -w|--workspace-name) WORKSPACE_NAME="$2"; shift 2 ;;
    --no-sentinel)       ENABLE_SENTINEL=false; shift ;;
    --no-mdti)           ENABLE_MDTI=false;  shift ;;
    --enable-copilot)    ENABLE_COPILOT=true; shift ;;
    -h|--help)           usage; exit 0 ;;
    *) log "Unknown option $1"; usage; exit 1 ;;
  esac
done

[[ -n "$CLIENT_ID" ]] || { log "${RED}ERROR: --client-id is required${NC}"; usage; exit 1; }

# ─── prerequisites ──────────────────────────────────────────────────────────
for bin in az; do
  command -v "$bin" >/dev/null || { echo -e "${RED}$bin required but not found${NC}"; exit 1; }
done

if ! az account show --only-show-errors >/dev/null 2>&1; then
  log "Logging in to Azure…"
  az login --use-device-code --only-show-errors >/dev/null
fi

# ─── subscription selection ────────────────────────────────────────────────
if [[ -n "$SUB_ID" ]]; then
  az account set --subscription "$SUB_ID" --only-show-errors || { log "${RED}Invalid subscription ID${NC}"; exit 1; }
else
  mapfile -t SUB_IDS < <(az account list --query '[?state==`Enabled`].id' -o tsv)
  mapfile -t SUB_NAMES < <(az account list --query '[?state==`Enabled`].name' -o tsv)
  ((${#SUB_IDS[@]})) || { log "No enabled subscriptions"; exit 1; }
  if ((${#SUB_IDS[@]} == 1)) || [[ ! -t 0 ]]; then
    az account set --subscription "${SUB_IDS[0]}" --only-show-errors
    SUB_ID="${SUB_IDS[0]}"
  else
    echo -e "\nSelect the subscription to use:"
    select sub in "${SUB_NAMES[@]}"; do
      [[ -n "$sub" ]] && { SUB_ID="${SUB_IDS[$REPLY-1]}"; az account set --subscription "$SUB_ID"; break; }
      echo "❌  Invalid choice – try again."
    done
  fi
fi
TENANT_ID="$(az account show --query tenantId -o tsv)"
log "Deploying to tenant $TENANT_ID, subscription $SUB_ID (${GREEN}$LOCATION${NC})"

# ─── resource group ────────────────────────────────────────────────────────
if ! az group show -n "$RESOURCE_GROUP_NAME" --only-show-errors >/dev/null 2>&1; then
  log "Creating resource group $RESOURCE_GROUP_NAME…"
  az group create -n "$RESOURCE_GROUP_NAME" -l "$LOCATION" \
    --tags solution=CTI createdBy=deploy.sh --only-show-errors >/dev/null
else
  log "Using existing resource group $RESOURCE_GROUP_NAME"
fi

# ─── fetch Bicep ───────────────────────────────────────────────────────────
if [[ ! -s main.bicep ]]; then
  log "Downloading main.bicep…"
  curl -sSL "$BICEP_RAW" -o main.bicep
fi

# ─── build parameters file ────────────────────────────────────────────────
cat >"$PARAM_FILE" <<PARAMS
{
  "clientId":               {"value": "$CLIENT_ID"},
  "workspaceName":          {"value": "$WORKSPACE_NAME"},
  "enableSentinel":         {"value": $ENABLE_SENTINEL},
  "enableMDTI":             {"value": $ENABLE_MDTI},
  "enableSecurityCopilot":  {"value": $ENABLE_COPILOT}
}
PARAMS

log "⚙️  Launching deployment… this can take a few minutes."
az deployment group create \
  --only-show-errors \
  --name "cti-deploy-$(date +%s)" \
  --resource-group "$RESOURCE_GROUP_NAME" \
  --template-file main.bicep \
  --parameters "@$PARAM_FILE"

log "${GREEN}Deployment complete!${NC}"
log "Your Log Analytics workspace: $WORKSPACE_NAME in $RESOURCE_GROUP_NAME"

if \$ENABLE_SENTINEL; then
  echo -e "\n${YELLOW}Remember to grant admin consent to the CTI app if you haven’t already.${NC}"
fi

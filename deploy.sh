#!/usr/bin/env bash
set -Eeuo pipefail
trap 'echo -e "\e[31mError on line $LINENO\e[0m" >&2' ERR

RAW='https://raw.githubusercontent.com/DataGuys/CentralThreatIntelligence/main/main.bicep'
RG='CTI-ResourceGroup'         # default RG
LOC='eastus'                   # default region
WS='CTI-Workspace'             # default LA workspace name
ENABLE_SENTINEL=true
ENABLE_MDTI=true
ENABLE_COPILOT=false

usage() { cat <<EOF
Required:
  --client-id <AAD‑app‑id>
Optional:
  --subscription-id <sub>      (defaults to active az context)
  -g,--resource-group <name>   (default $RG)
  -l,--location <region>       (default $LOC)
  -w,--workspace-name <name>   (default $WS)
  --no-sentinel | --no-mdti | --enable-copilot
EOF
}

# ---------- parse args -------------------------------------------------------
SUB_ID="$(az account show --query id -o tsv 2>/dev/null || true)"
while [[ $# -gt 0 ]]; do
  case $1 in
    --client-id)       CLIENT_ID="$2"; shift 2 ;;
    --subscription-id) SUB_ID="$2";   shift 2 ;;
    -g|--resource-group) RG="$2";     shift 2 ;;
    -l|--location)     LOC="$2";       shift 2 ;;
    -w|--workspace-name) WS="$2";      shift 2 ;;
    --no-sentinel)     ENABLE_SENTINEL=false; shift ;;
    --no-mdti)         ENABLE_MDTI=false;     shift ;;
    --enable-copilot)  ENABLE_COPILOT=true;    shift ;;
    -h|--help)         usage; exit 0 ;;
    *) echo "Unknown option $1"; usage; exit 1 ;;
  esac
done
: "${CLIENT_ID:?--client-id is required}"

# ---------- Azure context ----------------------------------------------------
az account show >/dev/null 2>&1 || az login --use-device-code
[[ -n $SUB_ID ]] && az account set --subscription "$SUB_ID"

# ---------- deploy -----------------------------------------------------------
az group create -n "$RG" -l "$LOC" \
  --tags solution=CTI createdBy=deploy.sh --only-show-errors

curl -sSL "$RAW" -o main.bicep

az deployment group create -g "$RG" \
  --name "cti-$(date +%s)" \
  --template-file main.bicep \
  --parameters clientId="$CLIENT_ID" \
               workspaceName="$WS" \
               enableSentinel=$ENABLE_SENTINEL \
               enableMDTI=$ENABLE_MDTI \
               enableSecurityCopilot=$ENABLE_COPILOT

echo -e "\e[32m✔ CTI deployed to $RG ($WS)\e[0m"

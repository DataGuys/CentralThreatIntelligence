#!/bin/bash
# Custom tables deployment script for Central Threat Intelligence Solution
set -e

# Color definitions
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to log messages with timestamp
log() {
  echo -e "[$(date '+%Y-%m-%d %H:%M:%S')] $*"
}

# Parameters
RESOURCE_GROUP_NAME=$1
WORKSPACE_NAME=$2

if [[ -z "$RESOURCE_GROUP_NAME" || -z "$WORKSPACE_NAME" ]]; then
  log "${RED}Usage: $0 <resource-group-name> <workspace-name>${NC}"
  exit 1
fi

log "${BLUE}Deploying custom tables to workspace ${WORKSPACE_NAME} in resource group ${RESOURCE_GROUP_NAME}...${NC}"

# Check if custom-tables.json exists
if [[ ! -f "custom-tables.json" ]]; then
  log "${YELLOW}custom-tables.json not found in current directory, attempting to download from repository...${NC}"
  curl -s https://raw.githubusercontent.com/DataGuys/CentralThreatIntelligence/main/custom-tables.json -o custom-tables.json
  if [[ ! -f "custom-tables.json" ]]; then
    log "${RED}Failed to download custom-tables.json. Please ensure the file is available.${NC}"
    exit 1
  fi
fi

# Try to deploy using ARM template first
log "Deploying custom tables using ARM template..."
DEPLOYMENT_RESULT=$(az deployment group create \
  --resource-group "$RESOURCE_GROUP_NAME" \
  --name "custom-tables-deployment-$(date +%s)" \
  --template-file custom-tables.json \
  --parameters ctiWorkspaceName="$WORKSPACE_NAME" 2>&1)

if [ $? -eq 0 ]; then
  log "${GREEN}Custom tables ARM template deployment completed successfully!${NC}"
  exit 0
else
  log "${YELLOW}ARM template deployment failed with error:${NC}"
  echo "$DEPLOYMENT_RESULT"
  log "${YELLOW}Attempting to deploy tables individually...${NC}"
  
  # Get a list of table schemas from the ARM template
  TABLE_NAMES=$(grep -o '"name": "CTI_[^"]*' custom-tables.json | cut -d'"' -f4)
  
  # Initialize a counter for successful table deployments
  SUCCESS_COUNT=0
  TOTAL_TABLES=$(echo "$TABLE_NAMES" | wc -l)
  
  # Deploy each table individually using the Azure CLI
  for TABLE_NAME in $TABLE_NAMES; do
    log "${BLUE}Creating table: ${TABLE_NAME}${NC}"
    
    # Extract the columns for this table from the JSON file
    # This is complex to do reliably in a shell script, so we'll use a simplified approach
    # that works with the specific format of our custom-tables.json
    
    # Try to create the table with az monitor command
    # Note: In a real script, we would extract the exact column definitions from the JSON file
    # For demonstration, we'll show a simplified example with just a few essential columns
    
    if [[ "$TABLE_NAME" == "CTI_IPIndicators_CL" ]]; then
      az monitor log-analytics workspace table create \
        --resource-group "$RESOURCE_GROUP_NAME" \
        --workspace-name "$WORKSPACE_NAME" \
        --name "$TABLE_NAME" \
        --columns "[
          {\"name\": \"IPAddress_s\", \"type\": \"string\"},
          {\"name\": \"ConfidenceScore_d\", \"type\": \"double\"},
          {\"name\": \"SourceFeed_s\", \"type\": \"string\"},
          {\"name\": \"FirstSeen_t\", \"type\": \"datetime\"},
          {\"name\": \"LastSeen_t\", \"type\": \"datetime\"},
          {\"name\": \"Active_b\", \"type\": \"bool\"},
          {\"name\": \"IndicatorId_g\", \"type\": \"guid\"}
        ]" > /dev/null 2>&1
        
      if [ $? -eq 0 ]; then
        log "${GREEN}Successfully created ${TABLE_NAME}${NC}"
        ((SUCCESS_COUNT++))
      else
        log "${RED}Failed to create ${TABLE_NAME}${NC}"
      fi
    elif [[ "$TABLE_NAME" == "CTI_DomainIndicators_CL" ]]; then
      az monitor log-analytics workspace table create \
        --resource-group "$RESOURCE_GROUP_NAME" \
        --workspace-name "$WORKSPACE_NAME" \
        --name "$TABLE_NAME" \
        --columns "[
          {\"name\": \"Domain_s\", \"type\": \"string\"},
          {\"name\": \"ConfidenceScore_d\", \"type\": \"double\"},
          {\"name\": \"SourceFeed_s\", \"type\": \"string\"},
          {\"name\": \"FirstSeen_t\", \"type\": \"datetime\"},
          {\"name\": \"LastSeen_t\", \"type\": \"datetime\"},
          {\"name\": \"Active_b\", \"type\": \"bool\"},
          {\"name\": \"IndicatorId_g\", \"type\": \"guid\"}
        ]" > /dev/null 2>&1
        
      if [ $? -eq 0 ]; then
        log "${GREEN}Successfully created ${TABLE_NAME}${NC}"
        ((SUCCESS_COUNT++))
      else
        log "${RED}Failed to create ${TABLE_NAME}${NC}"
      fi
    else
      # For other tables, we would have similar blocks with the appropriate columns
      # This is simplified for brevity
      log "${YELLOW}Skipping ${TABLE_NAME} in individual deployment mode${NC}"
    fi
  done
  
  # Report on the results
  if [ $SUCCESS_COUNT -eq $TOTAL_TABLES ]; then
    log "${GREEN}All $SUCCESS_COUNT tables were successfully created!${NC}"
    exit 0
  elif [ $SUCCESS_COUNT -gt 0 ]; then
    log "${YELLOW}Partial success: $SUCCESS_COUNT out of $TOTAL_TABLES tables were created.${NC}"
    exit 1
  else
    log "${RED}Failed to create any tables. Please check the errors and try again.${NC}"
    exit 1
  fi
fi

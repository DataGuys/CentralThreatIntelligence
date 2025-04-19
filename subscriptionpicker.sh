# Fetch subscription names and IDs into arrays
# Using process substitution and mapfile (readarray)
mapfile -t sub_names < <(az account list --query "[].name" -o tsv)
mapfile -t sub_ids < <(az account list --query "[].id" -o tsv)

# Check if any subscriptions were found
if [ ${#sub_names[@]} -eq 0 ]; then
    echo "Error: No Azure subscriptions found or you are not logged in (run 'az login')." >&2
    exit 1
fi

# Build the menu options
options=()
for i in "${!sub_names[@]}"; do
    # Include the subscription ID in the menu option
    options+=("$(($i + 1))) ${sub_names[$i]} (${sub_ids[$i]})")
done
options+=("$((${#sub_names[@]} + 1))) Quit")

# Display the menu using select
PS3=$'\nPlease select the Azure subscription to use: '
select opt_display in "${options[@]}"; do
    # $REPLY contains the number chosen by the user
    choice_index=$(($REPLY - 1))

    # Handle Quit option
    if [ "$REPLY" -eq $((${#sub_names[@]} + 1)) ]; then
        echo "Exiting without setting subscription." >&2
        exit 0
    fi

    # Validate selection
    if [ "$REPLY" -ge 1 ] && [ "$REPLY" -le ${#sub_names[@]} ]; then
        # Get the corresponding subscription ID and name
        SUB_ID="${sub_ids[$choice_index]}"
        selected_name="${sub_names[$choice_index]}"
        # Display the selected name and ID immediately to stderr
        echo "You selected: $selected_name ($SUB_ID)" >&2
        break # Exit the select loop
    else
        echo "Invalid selection: $REPLY. Please try again." >&2
    fi
done

# Check if a subscription was actually selected before proceeding
if [[ -z "$SUB_ID" ]]; then
    echo "No subscription was selected. Exiting." >&2
    exit 1
fi

# Set the selected subscription as active
echo "Setting active subscription to '$selected_name'..." >&2
az account set --subscription "$SUB_ID" > /dev/null # Suppress az output unless error

# Verify the change (optional, output to stderr)
current_sub_name=$(az account show --query name -o tsv)
current_sub_id=$(az account show --query id -o tsv)
echo "Active subscription is now: $current_sub_name ($current_sub_id)" >&2

# Output ONLY the SUB_ID to stdout for capture
echo "$SUB_ID"
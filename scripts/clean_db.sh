#!/bin/bash
# Usage: ./clean_db.sh or scripts/clean_db.sh

print_message() {
  COLOR=$1
  TEXT=$2
  echo -e "\033[${COLOR}m${TEXT}\033[0m"
}

BASE_DIR=$(dirname "$0")/..
cd "$BASE_DIR/deployments" || exit

print_message "33" "Stopping all the services..."
docker-compose -p server_alpha down

VOLUME="server_alpha_db_data"
if docker volume ls -q | grep -w "$VOLUME" > /dev/null; then
    print_message "34" "Removing the specified volume: $VOLUME..."
    if docker volume rm "$VOLUME"; then
        print_message "32" "Volume removed successfully."
    else
        print_message "31" "Failed to remove volume. It might be in use or already removed."
    fi
else
    print_message "32" "No existing volume to remove. First-time execution detected."
fi

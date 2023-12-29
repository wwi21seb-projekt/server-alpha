#!/bin/bash
# Usage:
# ./scripts/run.sh build                # to build the Docker images
# ./scripts/run.sh up [app|db|all|""]   # to start the services
# ./scripts/run.sh down [app|db|all|""] # to stop the services
# ./scripts/run.sh status               # to get the status of the services
# ./scripts/run.sh clean                # to clean the database volume

APP_SERVICE_NAME="app"
DB_SERVICE_NAME="db"

COMMAND=$1
SERVICE=$2

## Print the message in the given color
print_message() {
  COLOR=$1
  TEXT=$2
  echo -e "\033[${COLOR}m${TEXT}\033[0m"
}

# Check if .env file exists
if [[ ! -e .env ]]; then
  print_message "31" "No .env file found. Running setup_env.sh..."
  ./scripts/setup_env.sh
fi

# Go to the base directory
BASE_DIR=$(dirname "$0")/..
cd "$BASE_DIR" || exit

case $COMMAND in
up)
    case $SERVICE in
    app)
        SERVICE_LIST="$APP_SERVICE_NAME"
        ;;
    db)
        SERVICE_LIST="$DB_SERVICE_NAME"
        ;;
    all | "")
        SERVICE_LIST="$APP_SERVICE_NAME $DB_SERVICE_NAME"
        ;;
    *)
        print_message "31" "Invalid service. Services are app, db or all"
        exit 1
        ;;
    esac
    print_message "33" "Starting the services: $SERVICE_LIST..."
    docker-compose --env-file .env -f deployments/docker-compose.yml -p server_alpha up -d $SERVICE_LIST
    ;;
down)
    case $SERVICE in
    app|db)
        print_message "33" "Stopping the service: $SERVICE..."
        docker-compose --env-file .env -f deployments/docker-compose.yml -p server_alpha stop $SERVICE
        ;;
    all | "")
        print_message "33" "Stopping all the services..."
        docker-compose --env-file .env -f deployments/docker-compose.yml -p server_alpha down
        ;;
    *)
        print_message "31" "Invalid service. Services are app, db or all"
        exit 1
        ;;
    esac
    ;;
status)
    print_message "33" "Getting the status of the services..."
    docker-compose --env-file .env -f deployments/docker-compose.yml -p server_alpha ps
    ;;
build)
    print_message "33" "Building the Docker image..."
    ./scripts/build.sh
    ;;
clean)
    print_message "33" "Cleaning the database volume..."
    ./scripts/clean_db.sh
    ;;
*)
    print_message "31" "Invalid command. Commands are up, down, status, build or clean"
    exit 1
    ;;
esac
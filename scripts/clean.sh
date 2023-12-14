#!/bin/bash
# Usage: ./scripts/clean.sh

# Set image and container names
IMAGE_NAME="server-alpha"
CONTAINER_NAME="server-alpha-container"

echo "What do you want to clean?"
echo "0. Everything"
echo "1. Image only"
echo "2. Container only"
echo "3. Cancel"

read -p "Enter your choice: " choice

# Clean everything
if [[ $choice == "0" ]]; then
    echo "Cleaning everything..."
    docker rm $CONTAINER_NAME
    docker rmi $IMAGE_NAME
    echo "Everything cleaned."
    exit 0
fi

# Clean image only
if [[ $choice == "1" ]]; then
    echo "Cleaning image..."
    docker rmi $IMAGE_NAME
    echo "Image cleaned."
    exit 0
fi

# Clean container only
if [[ $choice == "2" ]]; then
    echo "Cleaning container..."

    # Check if the container is already running
    if [[ "$(docker ps -q -f name=$CONTAINER_NAME -f status=running 2> /dev/null)" != "" ]]; then
        echo "Container is running. Stopping container..."
        docker stop $CONTAINER_NAME
    fi

    docker rm $CONTAINER_NAME
    echo "Container cleaned."
    exit 0
fi

# Cancel
if [[ $choice == "3" ]]; then
    echo "Canceling..."
    exit 0
fi


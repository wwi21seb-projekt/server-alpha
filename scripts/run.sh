#!/bin/bash
# Usage: ./scripts/run.sh

# Set image and container names
IMAGE_NAME="server-alpha"
CONTAINER_NAME="server-alpha-container"

# Check if image exists
if [[ "$(docker images -q $IMAGE_NAME 2> /dev/null)" == "" ]]; then
    echo "Image not found. Run ./scripts/build.sh first."
    exit 1
fi

# Check if the container is already running
if [[ "$(docker ps -q -f name=$CONTAINER_NAME -f status=running 2> /dev/null)" != "" ]]; then
    echo "Container is already running."
    exit 1
fi

# Check if the container exists (but not necessarily running)
if [[ "$(docker ps -q -a -f name=$CONTAINER_NAME 2> /dev/null)" != "" ]]; then
    echo "Container exists but is not running. Removing container..."
    docker rm $CONTAINER_NAME
fi

# Run the Docker image
docker run -d -p 8080:8080 --name $CONTAINER_NAME $IMAGE_NAME

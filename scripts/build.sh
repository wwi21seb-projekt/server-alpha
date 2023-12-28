#!/bin/bash
# Usage: ./scripts/build.sh

# Enable BuildKit
export DOCKER_BUILDKIT=1

#
BASE_DIR=$(dirname "$0")/..
cd "$BASE_DIR" || exit

# Build the Docker image
docker build -t server-alpha -f build/package/Dockerfile .

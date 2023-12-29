#!/bin/bash
# Usage: ./scripts/build.sh

# Enable BuildKit
export DOCKER_BUILDKIT=1

#
BASE_DIR=$(dirname "$0")/..
cd "$BASE_DIR" || exit

# Run the tests
go test ./... || exit

# Build the Docker image
docker build -t server-alpha -f build/package/Dockerfile .

#!/bin/bash
# Usage: ./scripts/build.sh

# Enable BuildKit
export DOCKER_BUILDKIT=1

# Get the current directory of the script
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

# Navigate to the root directory
cd "${SCRIPT_DIR}/.." || exit

# Build the Docker image
docker build -t server-alpha -f build/package/Dockerfile .

## Scripts

This directory contains convenience scripts to build, run and clean the project.

### `build.sh`

This script builds the project. It will create a docker image with the name `server-alpha`.

### `run.sh`

This script runs the project. It will run the docker image `server-alpha` in the container `server-alpha-container` and expose the port 8080.

### `clean.sh`

This script cleans the project. It will prompt for an input option to clean the docker image, the docker container or both.

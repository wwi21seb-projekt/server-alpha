# Scripts
This directory contains scripts that are used for local development and testing. They help with tasks such as setting up
your environment (setup.sh), running the application locally (run.sh), and others.

Please note that these scripts are not intended to be used in a production environment.

### `build.sh`

This script builds the project. It will create a docker image with the name `server-alpha`.

### `run.sh`

This script runs the project. It will run the Docker image `server-alpha` in the container `server-alpha-container` and expose the port 8080.

#### Usage of `run.sh`
  
- `./scripts/run.sh build`: to build the Docker images
- `./scripts/run.sh up [app|db|all]`: to start the services
- `./scripts/run.sh down [app|db|all]`: to stop the services
- `./scripts/run.sh status`: to get the status of the services
- `./scripts/run.sh clean`: to clean the database volume

### `clean.sh`

This script cleans the project. It will prompt for an input option to clean the Docker image, the Docker container or both.
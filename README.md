# Server-Alpha
Server Repository for the Alpha Group (1)

# Status Badges

CI and CD status badges for the main branch:

[![Continuous Integration](https://github.com/wwi21seb-projekt/server-alpha/actions/workflows/ci.yaml/badge.svg)](https://github.com/wwi21seb-projekt/server-alpha/actions/workflows/ci.yaml)
[![Continuous Delivery](https://github.com/wwi21seb-projekt/server-alpha/actions/workflows/cd.yaml/badge.svg)](https://github.com/wwi21seb-projekt/server-alpha/actions/workflows/cd.yaml)

DeepSource status badges for the main branch:

[![DeepSource](https://app.deepsource.com/gh/wwi21seb-projekt/server-alpha.svg/?label=active+issues&show_trend=true&token=mcwBM2kkvsdD-hJRi0y1quuC)](https://app.deepsource.com/gh/wwi21seb-projekt/server-alpha/)
[![DeepSource](https://app.deepsource.com/gh/wwi21seb-projekt/server-alpha.svg/?label=resolved+issues&show_trend=true&token=mcwBM2kkvsdD-hJRi0y1quuC)](https://app.deepsource.com/gh/wwi21seb-projekt/server-alpha/)

SonarCloud status badges for the main branch:

[![Quality gate](https://sonarcloud.io/api/project_badges/quality_gate?project=wwi21seb-projekt_server-alpha)](https://sonarcloud.io/summary/new_code?id=wwi21seb-projekt_server-alpha)

[![Reliability Rating](https://sonarcloud.io/api/project_badges/measure?project=wwi21seb-projekt_server-alpha&metric=reliability_rating)](https://sonarcloud.io/summary/new_code?id=wwi21seb-projekt_server-alpha)
[![Security Rating](https://sonarcloud.io/api/project_badges/measure?project=wwi21seb-projekt_server-alpha&metric=security_rating)](https://sonarcloud.io/summary/new_code?id=wwi21seb-projekt_server-alpha)
[![Maintainability Rating](https://sonarcloud.io/api/project_badges/measure?project=wwi21seb-projekt_server-alpha&metric=sqale_rating)](https://sonarcloud.io/summary/new_code?id=wwi21seb-projekt_server-alpha)

[![Code Smells](https://sonarcloud.io/api/project_badges/measure?project=wwi21seb-projekt_server-alpha&metric=code_smells)](https://sonarcloud.io/summary/new_code?id=wwi21seb-projekt_server-alpha)
[![Vulnerabilities](https://sonarcloud.io/api/project_badges/measure?project=wwi21seb-projekt_server-alpha&metric=vulnerabilities)](https://sonarcloud.io/summary/new_code?id=wwi21seb-projekt_server-alpha)
[![Bugs](https://sonarcloud.io/api/project_badges/measure?project=wwi21seb-projekt_server-alpha&metric=bugs)](https://sonarcloud.io/summary/new_code?id=wwi21seb-projekt_server-alpha)

[![Technical Debt](https://sonarcloud.io/api/project_badges/measure?project=wwi21seb-projekt_server-alpha&metric=sqale_index)](https://sonarcloud.io/summary/new_code?id=wwi21seb-projekt_server-alpha)
[![Lines of Code](https://sonarcloud.io/api/project_badges/measure?project=wwi21seb-projekt_server-alpha&metric=ncloc)](https://sonarcloud.io/summary/new_code?id=wwi21seb-projekt_server-alpha)
[![Duplicated Lines (%)](https://sonarcloud.io/api/project_badges/measure?project=wwi21seb-projekt_server-alpha&metric=duplicated_lines_density)](https://sonarcloud.io/summary/new_code?id=wwi21seb-projekt_server-alpha)

## Prerequisites

- [Docker](https://www.docker.com)
- [Docker Compose](https://docs.docker.com/compose/)

## Setup

1. Clone the repository.
2. Make sure Docker and Docker Compose are installed and running on your system.

This will start all the necessary containers for the service to run.

## Usage

### Start the Service

To start the service, navigate to the repository directory in your terminal and execute the following command:

```bash
./scripts/run.sh up
```

If you only want to start the database or the API, you can use the following commands:

```bash
./scripts/run.sh up db
```

```bash
./scripts/run.sh up app
```

### Clean up

To clean up the Docker volumes and containers, you can use the following command:

```bash
./scripts/run.sh clean
```

### Reset environment variables

If you want to reset the environment variables to their default values, you can use the following command:

```bash
./scripts/run.sh setup
```

### Stop the service

To stop the service, you can use the following command:

```bash
./scripts/run.sh down
```

or be more specific and only stop the database or the API:

```bash
./scripts/run.sh down db
```

```bash
./scripts/run.sh down app
```


## Configuration

The service can be configured via environment variables. The following variables are available:

| Variable          | Description                          | Default Value                                |
|-------------------|--------------------------------------|----------------------------------------------|
| `DB_HOST`         | The host of the database.            | `localhost`                                  |
| `DB_PORT`         | The port of the database.            | `5432`                                       |
| `DB_NAME`         | The name of the database.            | `server_alpha_db`                            |
| `DB_USER`         | The user of the database.            | `alpha`                                      |
| `DB_PASSWORD`     | The password of the database.        | `secret`                                     |
| `APP_PORT`        | The port of the API.                 | `8080`                                       |
| `ENVIRONMENT`     | The environment of the service.      | `development`                                |
| `JWT_PRIVATE_KEY` | The private key for JWT signing.     | `secret`                                     |
| `JWT_PUBLIC_KEY`  | The public key for JWT verification. | `secret`                                     |
| `MAILGUN_API_KEY` | The API key for Mailgun.             | `secret`                                     |
| `SERVER_IMAGE`    | The image of the server.             | `ghcr.io/wwi21seb-projekt/server-alpha:main` |
| `KEYS_DIR`        | The directory for the keys.          | `./keys`                                     |
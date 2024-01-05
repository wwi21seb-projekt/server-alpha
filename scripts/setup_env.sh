#!/bin/bash

## Print the message in the given color
print_message() {
  COLOR=$1
  TEXT=$2
  echo -e "\033[${COLOR}m${TEXT}\033[0m"
}

# Function for generating random password
generate_password() {
  tr -dc 'a-zA-Z0-9' < /dev/urandom | fold -w 32 | head -n 1
}

# Remove the .env file if it exists
if [[ -e .env ]]; then
  rm .env
fi

# Environment variables with default values
{
  echo "APP_HOST=localhost"
  echo "APP_PORT=8080"
  echo "DB_HOST=localhost"
  echo "DB_NAME=server_alpha_db"
  echo "DB_PORT=5432"
  echo "DB_USER=alpha"
  echo "DB_PASS=$(generate_password)"  # Generate a random password for DB_PASS
} > .env

if [[ ! -e private_key.pem ]]; then
  openssl genpkey -algorithm ed25519 -out private_key.pem
fi

if [[ ! -e public_key.pem ]]; then
  openssl pkey -in private_key.pem -pubout -out public_key.pem
fi

print_message "32" "Environment variables are written to .env file:"
grep -v -e "DB_PASS" < .env

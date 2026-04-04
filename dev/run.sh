#!/usr/bin/env bash
set -e

# Check if Docker is running
if ! docker info >/dev/null 2>&1; then
  echo "Error: Docker is not running. Please start Docker first." >&2
  exit 1
fi

cleanup() {
  echo "Stopping Mailpit..."
  docker compose -f dev/mailpit/docker-compose.yml down
}
trap cleanup EXIT

# Start Mailpit if not already running
if ! docker ps --format '{{.Names}}' | grep -q mailpit; then
  echo "Starting Mailpit..."
  docker compose -f dev/mailpit/docker-compose.yml up -d
fi

cargo run

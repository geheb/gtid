$ErrorActionPreference = "Stop"

# Check if Docker is running
try {
    docker info | Out-Null
} catch {
    Write-Host "Error: Docker is not running. Please start Docker first." -ForegroundColor Red
    exit 1
}

# Start Mailpit if not already running
if (-not (docker ps --format '{{.Names}}' | Select-String -Quiet 'mailpit')) {
    Write-Host "Starting Mailpit..."
    docker compose -f dev/mailpit/docker-compose.yml up -d
}

try {
    cargo run
} finally {
    Write-Host "Stopping Mailpit..."
    docker compose -f dev/mailpit/docker-compose.yml down
}

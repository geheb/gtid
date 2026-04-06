$ErrorActionPreference = "Stop"

# Check if Docker is running
docker info | Out-Null
if ($LASTEXITCODE -ne 0) {
    Write-Host "Error: Docker is not running. Please start Docker first." -ForegroundColor Red
    exit 1
}

try {
    Write-Host "Starting Mailpit..."
    docker compose -f dev/mailpit/docker-compose.yml up -d

    Write-Host "Staring GT Id..."
    cargo run

} finally {
    Write-Host "Stopping Mailpit..."
    docker compose -f dev/mailpit/docker-compose.yml down
}

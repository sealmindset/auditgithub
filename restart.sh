#!/bin/bash

# AuditGitHub Container Restart Script
# Quickly restarts just the AuditGitHub containers without touching Docker Desktop

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}  AuditGitHub Container Restart${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

# Proceeding with restart (Docker Desktop GUI is running)
print_info "Restarting containers..."
echo ""

# Step 1: Stop containers
print_info "[1/2] Stopping AuditGitHub containers..."
if docker-compose down --remove-orphans 2>&1; then
    print_success "Containers stopped"
else
    print_error "Failed to stop containers"
    exit 1
fi
echo ""

# Wait a moment for cleanup
sleep 2

# Step 2: Start containers
print_info "[2/2] Starting AuditGitHub containers..."
if docker-compose up -d 2>&1; then
    print_success "Containers started"
else
    print_error "Failed to start containers"
    exit 1
fi
echo ""

# Wait for services to initialize
print_info "Waiting for services to initialize..."
sleep 5

# Show container status
print_info "Container status:"
docker-compose ps --format table
echo ""

# Check API health
print_info "Checking API health..."
max_attempts=30
attempt=1

while [ $attempt -le $max_attempts ]; do
    if curl -f -s http://localhost:8000/health > /dev/null 2>&1; then
        print_success "API is healthy"
        echo ""
        echo -e "${GREEN}========================================${NC}"
        echo -e "${GREEN}  AuditGitHub is ready!${NC}"
        echo -e "${GREEN}========================================${NC}"
        echo ""
        print_info "Services:"
        echo "  • Web UI:    http://localhost:3000"
        echo "  • API:       http://localhost:8000"
        echo "  • API Docs:  http://localhost:8000/docs"
        echo ""
        exit 0
    fi

    echo -ne "  Attempt $attempt/$max_attempts: Waiting for API...\r"
    sleep 2
    ((attempt++))
done

echo ""
print_error "API health check failed"
print_info "Check logs with: docker-compose logs -f api"
exit 1

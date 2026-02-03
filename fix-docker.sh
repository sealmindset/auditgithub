#!/bin/bash

# Fix Docker Desktop when GUI is running but daemon is not
# This happens when Docker Desktop starts but the engine fails to start

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
echo -e "${BLUE}  Fix Docker Desktop Engine${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

print_info "This script will restart Docker Desktop's engine"
echo ""

# Step 1: Check current state
print_info "[1/4] Checking Docker state..."
if docker ps > /dev/null 2>&1; then
    print_success "Docker is already working!"
    echo "If you're still having issues, try:"
    echo "  1. Quit Docker Desktop completely"
    echo "  2. Wait 10 seconds"
    echo "  3. Open Docker Desktop again"
    exit 0
else
    print_info "Docker daemon is not responding (this is expected)"
fi
echo ""

# Step 2: Quit Docker Desktop completely
print_info "[2/4] Quitting Docker Desktop..."
osascript -e 'quit app "Docker"' 2>/dev/null || killall "Docker Desktop" 2>/dev/null || true
sleep 2

# Force kill if still running
killall -9 "Docker Desktop" 2>/dev/null || true
killall -9 "com.docker.backend" 2>/dev/null || true
killall -9 "com.docker.vpnkit" 2>/dev/null || true
killall -9 "com.docker.supervisor" 2>/dev/null || true

print_success "Docker Desktop stopped"
echo ""

# Step 3: Wait for complete shutdown
print_info "[3/4] Waiting for Docker to fully shut down..."
sleep 5

# Clean up socket if it exists but is stale
if [ -S "/Users/$USER/.docker/run/docker.sock" ]; then
    rm -f "/Users/$USER/.docker/run/docker.sock" 2>/dev/null || true
fi

print_success "Shutdown complete"
echo ""

# Step 4: Start Docker Desktop
print_info "[4/4] Starting Docker Desktop..."
open -a Docker

echo ""
print_info "Waiting for Docker daemon to start..."
echo "This usually takes 30-60 seconds..."
echo ""

# Wait for daemon with progress
max_attempts=60
attempt=1

while [ $attempt -le $max_attempts ]; do
    if docker info > /dev/null 2>&1; then
        echo ""
        print_success "Docker daemon is responding!"

        # Additional verification
        sleep 2
        if docker ps > /dev/null 2>&1; then
            echo ""
            echo -e "${GREEN}========================================${NC}"
            echo -e "${GREEN}  Docker Desktop is ready!${NC}"
            echo -e "${GREEN}========================================${NC}"
            echo ""

            # Show Docker version
            docker version | head -15

            echo ""
            print_success "You can now run: ./start.sh or ./restart.sh"
            exit 0
        fi
    fi

    echo -ne "  [$attempt/$max_attempts] Waiting for Docker daemon...\r"
    sleep 2
    ((attempt++))
done

echo ""
print_error "Docker daemon did not start within 2 minutes"
echo ""
echo "Troubleshooting steps:"
echo "  1. Open Docker Desktop manually"
echo "  2. Look for error messages in Docker Desktop"
echo "  3. Check Docker Desktop settings:"
echo "     - General → Start Docker Desktop when you log in (should be on)"
echo "     - Resources → Advanced → Check CPU/Memory allocations"
echo "  4. Try running: ./fix-docker.sh again"
echo ""
echo "If problems persist:"
echo "  - Restart your Mac"
echo "  - Reinstall Docker Desktop"
echo ""
exit 1

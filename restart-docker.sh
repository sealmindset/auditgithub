#!/bin/bash

# Docker Desktop Restart Script for macOS
# Handles the issue where Docker Desktop becomes unresponsive

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}  Docker Desktop Restart${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

# Step 1: Quit Docker Desktop
echo -e "${YELLOW}[1/4]${NC} Quitting Docker Desktop..."
osascript -e 'quit app "Docker"' 2>/dev/null || killall Docker 2>/dev/null
sleep 2

# Step 2: Force kill if still running
echo -e "${YELLOW}[2/4]${NC} Ensuring Docker is completely stopped..."
killall -9 "Docker Desktop" 2>/dev/null
killall -9 "com.docker.backend" 2>/dev/null
killall -9 "com.docker.supervisor" 2>/dev/null
sleep 3

# Step 3: Wait for socket to disappear
echo -e "${YELLOW}[3/4]${NC} Waiting for Docker to fully shut down..."
max_wait=30
waited=0
while [ -S "$HOME/.docker/run/docker.sock" ] && [ $waited -lt $max_wait ]; do
    echo -ne "  Waiting for socket to close... ($waited/$max_wait)s\r"
    sleep 1
    ((waited++))
done

if [ -S "$HOME/.docker/run/docker.sock" ]; then
    echo -e "${YELLOW}Warning:${NC} Socket still exists, but continuing..."
fi
echo ""

# Step 4: Start Docker Desktop
echo -e "${YELLOW}[4/4]${NC} Starting Docker Desktop..."
open -a Docker

# Wait for Docker to be ready
echo ""
echo "Waiting for Docker to start..."
max_attempts=60
attempt=1

while [ $attempt -le $max_attempts ]; do
    if docker info > /dev/null 2>&1; then
        echo -e "\n${GREEN}✓ Docker is responding${NC}"

        # Additional stability check
        sleep 3
        if docker ps > /dev/null 2>&1; then
            echo -e "${GREEN}✓ Docker is fully operational${NC}"
            echo ""
            echo -e "${GREEN}========================================${NC}"
            echo -e "${GREEN}  Docker Desktop is ready!${NC}"
            echo -e "${GREEN}========================================${NC}"
            echo ""

            # Ask if user wants to run start.sh
            echo -e "${BLUE}Run ./start.sh now? (y/n)${NC}"
            read -r response
            if [[ "$response" =~ ^[Yy]$ ]]; then
                echo ""
                exec ./start.sh
            else
                echo "You can run ./start.sh when ready"
            fi
            exit 0
        fi
    fi

    echo -ne "  Attempt $attempt/$max_attempts: Docker not ready yet...\r"
    sleep 2
    ((attempt++))
done

echo ""
echo -e "${RED}✗ Docker failed to start after 2 minutes${NC}"
echo ""
echo "Please check:"
echo "  1. Open Docker Desktop manually"
echo "  2. Check for error messages in Docker Desktop"
echo "  3. Try running: ./restart-docker.sh again"
exit 1

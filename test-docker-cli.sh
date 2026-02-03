#!/bin/bash

# Docker CLI Diagnostic Script
# Run this to see what's wrong with Docker CLI access

echo "======================================"
echo "  Docker CLI Diagnostic"
echo "======================================"
echo ""

# Test 1: Check if docker command exists
echo "Test 1: Checking if 'docker' command exists..."
if command -v docker &> /dev/null; then
    echo "✓ 'docker' command found at: $(which docker)"
else
    echo "✗ 'docker' command not found"
    echo "  Fix: Add Docker to PATH or create symlink (see FIX_DOCKER_CLI.md)"
fi
echo ""

# Test 2: Check if docker-compose exists
echo "Test 2: Checking if 'docker-compose' command exists..."
if command -v docker-compose &> /dev/null; then
    echo "✓ 'docker-compose' command found at: $(which docker-compose)"
else
    echo "✗ 'docker-compose' command not found"
    echo "  Fix: Add Docker to PATH or create symlink (see FIX_DOCKER_CLI.md)"
fi
echo ""

# Test 3: Check PATH
echo "Test 3: Checking PATH for Docker..."
if echo $PATH | grep -q "Docker"; then
    echo "✓ Docker found in PATH"
    echo "  PATH includes: $(echo $PATH | tr ':' '\n' | grep -i docker)"
else
    echo "✗ Docker not in PATH"
    echo "  Current PATH: $PATH"
    echo "  Fix: Add '/Applications/Docker.app/Contents/Resources/bin' to PATH"
fi
echo ""

# Test 4: Check if Docker.app exists
echo "Test 4: Checking if Docker.app is installed..."
if [ -d "/Applications/Docker.app" ]; then
    echo "✓ Docker.app found"
    if [ -f "/Applications/Docker.app/Contents/Resources/bin/docker" ]; then
        echo "✓ Docker CLI binary exists"
    else
        echo "✗ Docker CLI binary not found in Docker.app"
    fi
else
    echo "✗ Docker.app not found in /Applications"
    echo "  Fix: Install Docker Desktop from https://docker.com"
fi
echo ""

# Test 5: Try to run docker
echo "Test 5: Attempting to run 'docker version'..."
if docker version &> /dev/null; then
    echo "✓ 'docker version' works!"
    docker version | head -10
else
    echo "✗ 'docker version' failed"
    echo "  Error output:"
    docker version 2>&1 | head -5
fi
echo ""

# Test 6: Check Docker context
echo "Test 6: Checking Docker context..."
if docker context ls &> /dev/null; then
    echo "✓ Docker context list:"
    docker context ls
else
    echo "✗ Cannot list Docker contexts"
fi
echo ""

# Test 7: Check for Docker socket
echo "Test 7: Checking for Docker socket..."
sockets=(
    "/var/run/docker.sock"
    "$HOME/.docker/run/docker.sock"
)

found_socket=false
for socket in "${sockets[@]}"; do
    if [ -S "$socket" ]; then
        echo "✓ Socket found: $socket"
        found_socket=true
    fi
done

if [ "$found_socket" = false ]; then
    echo "✗ No Docker socket found"
    echo "  Checked:"
    for socket in "${sockets[@]}"; do
        echo "    - $socket"
    done
fi
echo ""

echo "======================================"
echo "  Summary"
echo "======================================"
echo ""
echo "If you see ✗ marks above, follow the fixes in FIX_DOCKER_CLI.md"
echo ""
echo "Quick fix to try right now:"
echo "  1. Close this terminal"
echo "  2. Open a new terminal"
echo "  3. Run this script again: ./test-docker-cli.sh"
echo ""
echo "If that doesn't work, try:"
echo "  sudo ln -sf /Applications/Docker.app/Contents/Resources/bin/docker /usr/local/bin/docker"
echo "  sudo ln -sf /Applications/Docker.app/Contents/Resources/bin/docker-compose /usr/local/bin/docker-compose"
echo ""

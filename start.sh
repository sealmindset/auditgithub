#!/bin/bash

# AuditGitHub Startup Script
# This script handles clean startup across different operating systems

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Print colored output
print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Detect operating system
detect_os() {
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        OS="linux"
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        OS="macos"
    elif [[ "$OSTYPE" == "cygwin" ]] || [[ "$OSTYPE" == "msys" ]] || [[ "$OSTYPE" == "win32" ]]; then
        OS="windows"
    else
        OS="unknown"
    fi
    print_info "Detected OS: $OS"
}

# Kill processes on specified ports
kill_ports() {
    local ports=("3000" "3001")

    print_info "Checking for processes on ports ${ports[*]}..."

    for port in "${ports[@]}"; do
        if [[ "$OS" == "macos" ]] || [[ "$OS" == "linux" ]]; then
            # Use lsof for macOS and Linux
            if command -v lsof &> /dev/null; then
                local pids=$(lsof -ti:$port 2>/dev/null || true)
                if [[ -n "$pids" ]]; then
                    print_warning "Killing process(es) on port $port: $pids"
                    echo "$pids" | xargs kill -9 2>/dev/null || true
                    sleep 1
                fi
            else
                print_warning "lsof not found, skipping port cleanup"
            fi
        elif [[ "$OS" == "windows" ]]; then
            # Use netstat for Windows
            local pids=$(netstat -ano | grep ":$port " | awk '{print $5}' | sort -u 2>/dev/null || true)
            if [[ -n "$pids" ]]; then
                print_warning "Killing process(es) on port $port: $pids"
                for pid in $pids; do
                    taskkill //PID $pid //F 2>/dev/null || true
                done
                sleep 1
            fi
        fi
    done

    print_success "Port cleanup complete"
}

# Stop existing containers
stop_containers() {
    print_info "Stopping existing Docker containers..."
    docker-compose down --remove-orphans 2>/dev/null || true
    print_success "Containers stopped"
}

# Build containers with latest code
build_containers() {
    print_info "Building Docker containers with latest code..."
    if docker-compose build --no-cache; then
        print_success "Containers built successfully"
    else
        print_error "Failed to build containers"
        exit 1
    fi
}

# Start containers
start_containers() {
    print_info "Starting Docker containers..."
    if docker-compose up -d; then
        print_success "Containers started"
    else
        print_error "Failed to start containers"
        exit 1
    fi
}

# Wait for a service to be healthy
wait_for_service() {
    local service_name=$1
    local max_attempts=$2
    local attempt=1

    print_info "Waiting for $service_name to be healthy..."

    while [ $attempt -le $max_attempts ]; do
        local status=$(docker-compose ps --format json | jq -r ".[] | select(.Service==\"$service_name\") | .Health" 2>/dev/null || echo "unknown")

        if [[ "$status" == "healthy" ]]; then
            print_success "$service_name is healthy"
            return 0
        fi

        # Fallback: check if container is running if health check not available
        local state=$(docker-compose ps --format json | jq -r ".[] | select(.Service==\"$service_name\") | .State" 2>/dev/null || echo "unknown")
        if [[ "$state" == "running" ]] && [[ "$status" == "" ]]; then
            print_success "$service_name is running (no health check)"
            return 0
        fi

        echo -ne "  Attempt $attempt/$max_attempts: $service_name status=$status, state=$state\r"
        sleep 2
        ((attempt++))
    done

    print_error "$service_name failed to become healthy"
    print_info "Checking logs..."
    docker-compose logs --tail=50 $service_name
    return 1
}

# Check API health endpoint
check_api_health() {
    local max_attempts=30
    local attempt=1

    print_info "Checking API health endpoint..."

    while [ $attempt -le $max_attempts ]; do
        if curl -f -s http://localhost:8000/health > /dev/null 2>&1; then
            print_success "API health endpoint responding"
            return 0
        fi

        echo -ne "  Attempt $attempt/$max_attempts: Waiting for API...\r"
        sleep 2
        ((attempt++))
    done

    print_error "API health check failed"
    print_info "Checking API logs..."
    docker-compose logs --tail=50 api
    return 1
}

# Main execution
main() {
    clear
    echo "========================================"
    echo "  AuditGitHub Startup Script"
    echo "========================================"
    echo ""

    # Detect OS
    detect_os

    # Kill any processes on ports 3000 and 3001
    kill_ports

    # Stop existing containers
    stop_containers

    # Build containers
    build_containers

    # Start containers
    start_containers

    echo ""
    print_info "Verifying services..."
    echo ""

    # Wait for database to be healthy
    if ! wait_for_service "db" 60; then
        print_error "Database failed to start properly"
        exit 1
    fi

    # Wait for Redis to be healthy
    if ! wait_for_service "redis" 30; then
        print_warning "Redis check failed, but continuing..."
    fi

    # Wait for API to be healthy
    if ! wait_for_service "api" 60; then
        print_error "API failed to start properly"
        exit 1
    fi

    # Additional check: API health endpoint
    if ! check_api_health; then
        print_error "API health endpoint check failed"
        exit 1
    fi

    echo ""
    echo "========================================"
    print_success "AuditGitHub is running!"
    echo "========================================"
    echo ""
    print_info "Services:"
    echo "  • Web UI:    http://localhost:3000"
    echo "  • API:       http://localhost:8000"
    echo "  • API Docs:  http://localhost:8000/docs"
    echo "  • MinIO:     http://localhost:9001"
    echo "  • Database:  localhost:5432"
    echo ""
    print_info "Useful commands:"
    echo "  • View logs:        docker-compose logs -f"
    echo "  • View API logs:    docker-compose logs -f api"
    echo "  • Stop services:    docker-compose down"
    echo "  • Restart services: ./start.sh"
    echo ""
    print_info "Container status:"
    docker-compose ps
}

# Run main function
main

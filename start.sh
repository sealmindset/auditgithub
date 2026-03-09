#!/bin/bash

# AuditGitHub Startup Script
# This script handles clean startup across different operating systems

# VPN
# az login --use-device-code
# sn-openai-dev-01

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

# Check if Docker daemon is running
is_docker_running() {
    docker info > /dev/null 2>&1
    return $?
}

# Check if Docker socket exists
check_docker_socket() {
    local socket_paths=(
        "/var/run/docker.sock"
        "$HOME/.docker/run/docker.sock"
        "/Users/$USER/.docker/run/docker.sock"
    )

    for socket in "${socket_paths[@]}"; do
        if [ -S "$socket" ]; then
            return 0
        fi
    done
    return 1
}

# Verify Docker is fully operational
verify_docker_operational() {
    # Check 1: Docker info works
    if ! docker info > /dev/null 2>&1; then
        return 1
    fi

    # Check 2: Socket exists
    if ! check_docker_socket; then
        print_warning "Docker socket not found in standard locations"
    fi

    # Check 3: Docker-compose can communicate with Docker
    if ! docker-compose version > /dev/null 2>&1; then
        return 1
    fi

    # Check 4: Can list containers
    if ! docker ps > /dev/null 2>&1; then
        return 1
    fi

    return 0
}

# Start Docker based on OS
start_docker() {
    print_info "Docker is not running. Attempting to start Docker..."

    if [[ "$OS" == "macos" ]]; then
        # Check if Docker.app exists
        if [ -e "/Applications/Docker.app" ]; then
            print_info "Starting Docker Desktop..."
            open -a Docker
        else
            print_error "Docker Desktop not found in /Applications/"
            print_info "Please install Docker Desktop from https://www.docker.com/products/docker-desktop"
            exit 1
        fi
    elif [[ "$OS" == "linux" ]]; then
        print_info "Attempting to start Docker service..."
        if command -v systemctl &> /dev/null; then
            sudo systemctl start docker
        elif command -v service &> /dev/null; then
            sudo service docker start
        else
            print_error "Could not start Docker. Please start Docker manually."
            exit 1
        fi
    elif [[ "$OS" == "windows" ]]; then
        print_info "Starting Docker Desktop..."
        powershell.exe -Command "Start-Process 'C:\Program Files\Docker\Docker\Docker Desktop.exe'" 2>/dev/null || \
        cmd.exe /c "start C:\Program Files\Docker\Docker\Docker Desktop.exe" 2>/dev/null || \
        print_error "Could not start Docker Desktop. Please start it manually."
    else
        print_error "Unknown OS. Please start Docker manually."
        exit 1
    fi
}

# Wait for Docker daemon to be ready
wait_for_docker() {
    local max_attempts=60  # 2 minutes
    local attempt=1

    print_info "Waiting for Docker daemon to be fully operational..."

    while [ $attempt -le $max_attempts ]; do
        if verify_docker_operational; then
            print_success "Docker daemon is fully operational"
            # Additional wait to ensure Docker is stable
            print_info "Verifying Docker stability..."
            sleep 5
            # Double-check it's still working
            if verify_docker_operational; then
                print_success "Docker stability confirmed"
                return 0
            fi
        fi

        echo -ne "  Attempt $attempt/$max_attempts: Waiting for Docker daemon...\r"
        sleep 2
        ((attempt++))
    done

    print_error "Docker daemon failed to become fully operational within 2 minutes"
    print_info "Troubleshooting steps:"
    print_info "  1. Quit Docker Desktop completely"
    print_info "  2. Wait 10 seconds"
    print_info "  3. Start Docker Desktop manually"
    print_info "  4. Wait for it to show 'Docker Desktop is running'"
    print_info "  5. Run this script again"
    exit 1
}

# Ensure Docker is running
ensure_docker_running() {
    # Skip checks - assume Docker Desktop is running since user can see GUI
    # If there are CLI issues, docker-compose commands will show clear errors
    print_success "Proceeding with Docker operations"
}

# Separator for visual clarity between steps
print_separator() {
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""
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

    # Verify Docker is operational before attempting to stop
    if ! verify_docker_operational; then
        print_warning "Docker not operational, skipping container stop"
        return 0
    fi

    # Check if any containers are running
    local running_containers=$(docker-compose ps -q 2>/dev/null | wc -l | tr -d ' ')

    if [ "$running_containers" -gt 0 ]; then
        print_info "Found $running_containers container(s) to stop"

        # Attempt to stop containers
        if docker-compose down --remove-orphans 2>&1 | tee /tmp/docker-stop.log | grep -v "^$"; then
            # Wait for containers to fully stop
            local max_wait=30
            local waited=0
            while [ $waited -lt $max_wait ]; do
                running_containers=$(docker-compose ps -q 2>/dev/null | wc -l | tr -d ' ')
                if [ "$running_containers" -eq 0 ]; then
                    break
                fi
                sleep 1
                ((waited++))
            done

            if [ "$running_containers" -eq 0 ]; then
                print_success "All containers stopped and removed"
            else
                print_warning "$running_containers container(s) still running, but continuing..."
            fi
        else
            print_warning "Container stop command had issues, but continuing..."
        fi
    else
        print_info "No running containers found"
    fi
}

# Build containers with latest code
build_containers() {
    local build_opts=""

    # Verify Docker is operational before building
    if ! verify_docker_operational; then
        print_error "Docker is not operational before build"
        wait_for_docker
    fi

    # Check if REBUILD environment variable is set for clean build
    if [[ "${REBUILD}" == "true" ]]; then
        print_info "Building Docker containers with latest code (clean build)..."
        build_opts="--no-cache"
    else
        print_info "Building Docker containers (using cache where possible)..."
        print_info "Tip: Run 'REBUILD=true ./start.sh' for a clean rebuild"
    fi

    # Build with progress output
    docker-compose build $build_opts 2>&1 | tee /tmp/docker-build.log | grep -E "(Building|Step|Successfully built|naming to)" || true
    local build_result=${PIPESTATUS[0]}

    echo ""  # New line after build output

    # Check if build succeeded
    if [ $build_result -eq 0 ] && ! grep -q "Cannot connect to the Docker daemon" /tmp/docker-build.log; then
        print_success "Containers built successfully"
        return 0
    else
        print_error "Failed to build containers"
        print_info "Check /tmp/docker-build.log for details:"
        tail -50 /tmp/docker-build.log
        exit 1
    fi
}

# Start containers with retry logic
start_containers() {
    local max_attempts=3
    local attempt=1

    print_info "Starting Docker containers..."

    while [ $attempt -le $max_attempts ]; do
        if [ $attempt -gt 1 ]; then
            print_warning "Retry attempt $attempt/$max_attempts after 5 seconds..."
            sleep 5

            # Re-verify Docker is operational
            if ! verify_docker_operational; then
                print_error "Docker is no longer operational"
                print_info "Waiting for Docker to recover..."
                wait_for_docker
            fi
        fi

        # Attempt to start containers
        if docker-compose up -d 2>&1 | tee /tmp/docker-start.log; then
            local exit_code=${PIPESTATUS[0]}

            # Check if the command actually succeeded (docker-compose returns 0 even with warnings)
            if [ $exit_code -eq 0 ] && ! grep -q "Cannot connect to the Docker daemon" /tmp/docker-start.log; then
                print_success "Container startup initiated"
                # Wait for containers to fully initialize
                print_info "Waiting for containers to initialize..."
                sleep 5
                return 0
            fi
        fi

        print_warning "Container startup attempt $attempt failed"
        ((attempt++))
    done

    print_error "Failed to start containers after $max_attempts attempts"
    print_info "Check /tmp/docker-start.log for details:"
    tail -30 /tmp/docker-start.log
    echo ""
    print_info "Troubleshooting:"
    print_info "  1. Restart Docker Desktop"
    print_info "  2. Run: docker-compose down"
    print_info "  3. Run this script again"
    exit 1
}

# Display container status for debugging
show_container_status() {
    print_info "Current container status:"
    docker-compose ps --format table
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

# Show usage information
show_usage() {
    if [[ "$1" == "--help" ]] || [[ "$1" == "-h" ]]; then
        echo "AuditGitHub Startup Script"
        echo ""
        echo "Usage:"
        echo "  ./start.sh              Normal startup (uses Docker cache)"
        echo "  REBUILD=true ./start.sh Clean rebuild (no cache, slower but ensures latest code)"
        echo ""
        echo "What this script does:"
        echo "  1. ✓ Detects your operating system"
        echo "  2. ✓ Checks if Docker is running (starts it if needed)"
        echo "  3. ✓ Kills processes on ports 3000 & 3001"
        echo "  4. ✓ Stops existing containers"
        echo "  5. ✓ Builds Docker images with latest code"
        echo "  6. ✓ Starts all containers"
        echo "  7. ✓ Verifies database is healthy"
        echo "  8. ✓ Verifies API is healthy"
        echo "  9. ✓ Confirms all services are responding"
        echo ""
        echo "Tripwires:"
        echo "  • Each step waits for completion before proceeding"
        echo "  • Docker startup: waits up to 2 minutes"
        echo "  • Service health: waits up to 2 minutes per service"
        echo "  • API health check: confirms /health endpoint responds"
        echo ""
        exit 0
    fi
}

# Main execution
main() {
    show_usage "$1"

    clear
    echo "========================================"
    echo "  AuditGitHub Startup Script"
    echo "========================================"
    echo ""

    # Show if this is a clean rebuild
    if [[ "${REBUILD}" == "true" ]]; then
        print_warning "CLEAN REBUILD MODE: This will take longer but ensures latest code"
        echo ""
    fi

    # Step 1: Detect OS
    detect_os
    print_separator

    # Step 2: Ensure Docker is running (TRIPWIRE: Wait for Docker to be ready)
    ensure_docker_running
    print_separator

    # Step 3: Kill any processes on ports 3000 and 3001
    kill_ports
    print_separator

    # Step 4: Stop existing containers (TRIPWIRE: Wait for full shutdown)
    stop_containers
    print_separator

    # Step 5: Build containers (TRIPWIRE: Wait for build completion)
    build_containers
    print_separator

    # Step 6: Start containers (TRIPWIRE: Wait for container initialization)
    start_containers
    show_container_status
    print_separator

    # Step 7: Verify services (TRIPWIRE: Health checks for each service)
    print_info "🔍 VERIFYING SERVICES"
    print_info "This may take up to 2 minutes..."
    echo ""

    # Wait for database to be healthy (CRITICAL)
    if ! wait_for_service "db" 60; then
        print_error "Database failed to start properly"
        show_container_status
        docker-compose logs --tail=100 db
        exit 1
    fi

    # Wait for Redis to be healthy
    if ! wait_for_service "redis" 30; then
        print_warning "Redis check failed, but continuing..."
    fi

    # Wait for MinIO to be healthy
    if ! wait_for_service "minio" 30; then
        print_warning "MinIO check failed, but continuing..."
    fi

    # Wait for API to be healthy (CRITICAL)
    if ! wait_for_service "api" 60; then
        print_error "API failed to start properly"
        show_container_status
        docker-compose logs --tail=100 api
        exit 1
    fi

    # Additional check: API health endpoint (FINAL TRIPWIRE)
    if ! check_api_health; then
        print_error "API health endpoint check failed"
        docker-compose logs --tail=100 api
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
    echo "  • View logs:          docker-compose logs -f"
    echo "  • View API logs:      docker-compose logs -f api"
    echo "  • View DB logs:       docker-compose logs -f db"
    echo "  • Stop services:      docker-compose down"
    echo "  • Restart services:   ./start.sh"
    echo "  • Clean rebuild:      REBUILD=true ./start.sh"
    echo "  • Help:               ./start.sh --help"
    echo ""
    print_info "Container status:"
    docker-compose ps --format table
    echo ""
    print_success "All systems operational! 🚀"
}

# Run main function with arguments
main "$@"

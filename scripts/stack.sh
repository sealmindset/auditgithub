#!/bin/bash
# stack.sh - Manage the AuditGH Docker stack (UI, API, DB)
#
# Usage:
#   ./stack.sh              # Start with logs
#   ./stack.sh up           # Start services in background
#   ./stack.sh down         # Stop all services
#   ./stack.sh restart      # Restart services
#   ./stack.sh rebuild      # Rebuild and restart
#   ./stack.sh logs         # Follow logs
#   ./stack.sh status       # Show container status
#   ./stack.sh clean        # Remove orphan containers and restart

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

SERVICES="web-ui api db"

log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[OK]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# Clean up orphan containers that cause conflicts
cleanup_orphans() {
    log_info "Cleaning up orphan containers..."
    docker rm -f auditgh_api auditgh_ui auditgh_db 2>/dev/null || true
    docker-compose down --remove-orphans 2>/dev/null || true
    log_success "Cleanup complete"
}

# Check if services are running
check_status() {
    echo ""
    log_info "Container Status:"
    docker-compose ps
    echo ""
}

# Wait for services to be healthy
wait_for_services() {
    log_info "Waiting for services to start..."
    sleep 3
    
    # Check API
    if curl -s http://localhost:8000/health > /dev/null 2>&1; then
        log_success "API is healthy at http://localhost:8000"
    else
        log_warn "API may still be starting..."
    fi
    
    # Check UI
    if curl -s http://localhost:3000 > /dev/null 2>&1; then
        log_success "UI is ready at http://localhost:3000"
    else
        log_warn "UI may still be starting..."
    fi
}

# Start services
do_up() {
    local detach=${1:-true}
    
    log_info "Starting stack services: $SERVICES"
    
    if [ "$detach" = true ]; then
        docker-compose up -d $SERVICES
        wait_for_services
        check_status
        echo ""
        log_success "Stack is running!"
        echo "  UI:  http://localhost:3000"
        echo "  API: http://localhost:8000"
        echo ""
        echo "Run './stack.sh logs' to follow logs"
    else
        docker-compose up $SERVICES
    fi
}

# Stop services
do_down() {
    log_info "Stopping stack services..."
    docker-compose down
    log_success "Stack stopped"
}

# Restart services
do_restart() {
    log_info "Restarting stack services..."
    docker-compose restart $SERVICES
    wait_for_services
    check_status
    log_success "Stack restarted!"
}

# Rebuild and restart
do_rebuild() {
    log_info "Rebuilding stack images..."
    cleanup_orphans
    docker-compose build --no-cache api web-ui
    log_success "Build complete"
    do_up
}

# Follow logs
do_logs() {
    log_info "Following logs (Ctrl+C to exit)..."
    docker-compose logs -f $SERVICES
}

# Clean and restart
do_clean() {
    log_warn "Cleaning and restarting stack..."
    cleanup_orphans
    do_up
}

# Main command handler
case "${1:-}" in
    up)
        do_up true
        ;;
    down)
        do_down
        ;;
    restart)
        do_restart
        ;;
    rebuild)
        do_rebuild
        ;;
    logs)
        do_logs
        ;;
    status)
        check_status
        ;;
    clean)
        do_clean
        ;;
    "")
        # Default: clean start with logs
        cleanup_orphans
        log_info "Starting stack with logs (Ctrl+C to exit)..."
        do_up false
        ;;
    *)
        echo "Usage: $0 {up|down|restart|rebuild|logs|status|clean}"
        echo ""
        echo "Commands:"
        echo "  (none)    Clean start with attached logs"
        echo "  up        Start services in background"
        echo "  down      Stop all services"
        echo "  restart   Restart services"
        echo "  rebuild   Rebuild images and restart"
        echo "  logs      Follow container logs"
        echo "  status    Show container status"
        echo "  clean     Remove orphans and restart"
        exit 1
        ;;
esac

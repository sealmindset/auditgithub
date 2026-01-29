#!/bin/bash
#
# org.sh - Organization Management CLI
#
# A command-line tool for managing GitHub organizations in the AuditGH system.
# Provides create, read, update, delete operations, plus repository import/sync.
#
# Usage:
#   ./org.sh list                              # List all organizations
#   ./org.sh show <org-name>                   # Show organization details
#   ./org.sh create <name> <github-org> <token> # Create new organization
#   ./org.sh update <name> [options]           # Update organization
#   ./org.sh delete <name> [--force]           # Delete organization
#   ./org.sh import <name>                     # Import repositories from GitHub
#   ./org.sh set-default <name>                # Set as default organization
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Helper functions
print_usage() {
    cat << EOF
Usage: ./org.sh <command> [arguments]

Commands:
  list                                       List all organizations
  show <org-name>                           Show organization details
  create <name> <github-org> <token>        Create new organization
  update <name> [options]                   Update organization properties
  delete <name> [--force]                   Delete organization
  import <name> [--token <token>]           Import repositories from GitHub
  set-default <name>                        Set organization as default

Examples:
  # List all organizations
  ./org.sh list

  # Show organization details
  ./org.sh show sleepnumber

  # Create new organization
  ./org.sh create sleepnumber sleepnumber ghp_token123 --display-name "Sleep Number"

  # Import repositories
  ./org.sh import sleepnumber

  # Set as default
  ./org.sh set-default sleepnumber

  # Delete organization
  ./org.sh delete oldorg --force

Options:
  --include-inactive    Include inactive organizations in list
  --json                Output as JSON
  --display-name NAME   Set display name (for create/update)
  --set-default         Set as default organization (for create/update)
  --active true|false   Set active status (for update)
  --force               Skip confirmation prompts (for delete)
  --token TOKEN         GitHub token (for import)

EOF
}

error() {
    echo -e "${RED}✗ Error: $1${NC}" >&2
}

success() {
    echo -e "${GREEN}✓ $1${NC}"
}

info() {
    echo -e "${BLUE}$1${NC}"
}

warning() {
    echo -e "${YELLOW}⚠ $1${NC}"
}

# Check if Docker is available
check_docker() {
    if command -v docker-compose &> /dev/null && docker-compose ps api &> /dev/null 2>&1; then
        return 0
    else
        return 1
    fi
}

# Run command via Docker or local Python
run_command() {
    if check_docker; then
        docker-compose exec -T api python org_manager.py "$@"
    else
        # Try local Python with venv
        if [ -d "$SCRIPT_DIR/venv" ]; then
            source "$SCRIPT_DIR/venv/bin/activate"
            python "$SCRIPT_DIR/org_manager.py" "$@"
        else
            python3 "$SCRIPT_DIR/org_manager.py" "$@"
        fi
    fi
}

# Main command handling
main() {
    if [ $# -eq 0 ]; then
        print_usage
        exit 1
    fi

    COMMAND=$1
    shift

    case $COMMAND in
        list)
            run_command list "$@"
            ;;

        show)
            if [ $# -eq 0 ]; then
                error "Organization name required"
                echo "Usage: ./org.sh show <org-name>"
                exit 1
            fi
            run_command show "$@"
            ;;

        create)
            if [ $# -lt 3 ]; then
                error "Missing required arguments"
                echo "Usage: ./org.sh create <name> <github-org> <token> [--display-name NAME] [--set-default]"
                exit 1
            fi

            NAME=$1
            GITHUB_ORG=$2
            TOKEN=$3
            shift 3

            run_command create "$NAME" "$GITHUB_ORG" "$TOKEN" "$@"
            ;;

        update)
            if [ $# -eq 0 ]; then
                error "Organization name required"
                echo "Usage: ./org.sh update <name> [--display-name NAME] [--active true|false] [--set-default]"
                exit 1
            fi
            run_command update "$@"
            ;;

        delete)
            if [ $# -eq 0 ]; then
                error "Organization name required"
                echo "Usage: ./org.sh delete <name> [--force]"
                exit 1
            fi

            NAME=$1
            shift

            # Check for --force flag
            FORCE_FLAG=""
            if [[ "$@" == *"--force"* ]]; then
                FORCE_FLAG="--force"
            else
                # Confirmation prompt
                warning "This will delete organization '$NAME' and all its data"
                read -p "Are you sure? (y/N): " -n 1 -r
                echo
                if [[ ! $REPLY =~ ^[Yy]$ ]]; then
                    info "Cancelled"
                    exit 0
                fi
                FORCE_FLAG="--force"
            fi

            run_command delete "$NAME" $FORCE_FLAG
            ;;

        import)
            if [ $# -eq 0 ]; then
                error "Organization name required"
                echo "Usage: ./org.sh import <name> [--token TOKEN]"
                exit 1
            fi
            run_command import "$@"
            ;;

        set-default)
            if [ $# -eq 0 ]; then
                error "Organization name required"
                echo "Usage: ./org.sh set-default <name>"
                exit 1
            fi

            NAME=$1
            run_command update "$NAME" --set-default
            ;;

        help|--help|-h)
            print_usage
            ;;

        *)
            error "Unknown command: $COMMAND"
            print_usage
            exit 1
            ;;
    esac
}

main "$@"

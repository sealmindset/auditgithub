#!/bin/bash
#
# manage-orgs.sh - Interactive Organization Management Menu
#
# Provides a user-friendly interactive menu for managing GitHub organizations
# in the AuditGH system.
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ORG_SH="$SCRIPT_DIR/org.sh"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# Helper functions
print_header() {
    clear
    echo -e "${BOLD}${BLUE}=========================================${NC}"
    echo -e "${BOLD}${BLUE}    Organization Management System${NC}"
    echo -e "${BOLD}${BLUE}=========================================${NC}"
    echo ""
}

print_menu() {
    echo -e "${CYAN}Main Menu:${NC}"
    echo "  1) List all organizations"
    echo "  2) Show organization details"
    echo "  3) Create new organization"
    echo "  4) Update organization"
    echo "  5) Delete organization"
    echo "  6) Import repositories from GitHub"
    echo "  7) Set default organization"
    echo "  8) Exit"
    echo ""
}

read_input() {
    echo -n -e "${GREEN}> ${NC}"
    read -r INPUT
    echo "$INPUT"
}

press_enter() {
    echo ""
    read -p "Press Enter to continue..." -r
}

error() {
    echo -e "${RED}✗ Error: $1${NC}"
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

# Menu functions
list_organizations() {
    print_header
    echo -e "${CYAN}List Organizations${NC}"
    echo "=================="
    echo ""

    echo "Include inactive organizations? (y/N)"
    INCLUDE_INACTIVE=$(read_input)

    echo ""

    if [[ "$INCLUDE_INACTIVE" =~ ^[Yy]$ ]]; then
        "$ORG_SH" list --include-inactive
    else
        "$ORG_SH" list
    fi

    press_enter
}

show_organization() {
    print_header
    echo -e "${CYAN}Show Organization Details${NC}"
    echo "========================="
    echo ""

    echo "Enter organization name:"
    ORG_NAME=$(read_input)

    if [ -z "$ORG_NAME" ]; then
        error "Organization name cannot be empty"
        press_enter
        return
    fi

    echo ""
    "$ORG_SH" show "$ORG_NAME" || true

    press_enter
}

create_organization() {
    print_header
    echo -e "${CYAN}Create New Organization${NC}"
    echo "======================="
    echo ""

    echo "Enter organization name (lowercase, alphanumeric):"
    echo "  Example: sleepnumber"
    ORG_NAME=$(read_input)

    if [ -z "$ORG_NAME" ]; then
        error "Organization name cannot be empty"
        press_enter
        return
    fi

    echo ""
    echo "Enter GitHub organization name:"
    echo "  Example: sleepnumber"
    GITHUB_ORG=$(read_input)

    if [ -z "$GITHUB_ORG" ]; then
        error "GitHub organization name cannot be empty"
        press_enter
        return
    fi

    echo ""
    echo "Enter GitHub personal access token:"
    echo "  Example: ghp_xxxxxxxxxxxxxxxxxxxx"
    echo -n -e "${GREEN}> ${NC}"
    read -s GITHUB_TOKEN  # Read token silently
    echo ""

    if [ -z "$GITHUB_TOKEN" ]; then
        error "GitHub token cannot be empty"
        press_enter
        return
    fi

    echo ""
    echo "Enter display name (optional, press Enter to skip):"
    echo "  Example: Sleep Number"
    DISPLAY_NAME=$(read_input)

    echo ""
    echo "Set as default organization? (y/N)"
    SET_DEFAULT=$(read_input)

    echo ""
    info "Creating organization..."

    if [[ "$SET_DEFAULT" =~ ^[Yy]$ ]]; then
        if [ -n "$DISPLAY_NAME" ]; then
            "$ORG_SH" create "$ORG_NAME" "$GITHUB_ORG" "$GITHUB_TOKEN" --display-name "$DISPLAY_NAME" --set-default
        else
            "$ORG_SH" create "$ORG_NAME" "$GITHUB_ORG" "$GITHUB_TOKEN" --set-default
        fi
    else
        if [ -n "$DISPLAY_NAME" ]; then
            "$ORG_SH" create "$ORG_NAME" "$GITHUB_ORG" "$GITHUB_TOKEN" --display-name "$DISPLAY_NAME"
        else
            "$ORG_SH" create "$ORG_NAME" "$GITHUB_ORG" "$GITHUB_TOKEN"
        fi
    fi

    echo ""
    echo "Import repositories now? (Y/n)"
    IMPORT_NOW=$(read_input)

    if [[ ! "$IMPORT_NOW" =~ ^[Nn]$ ]]; then
        echo ""
        info "Importing repositories..."
        "$ORG_SH" import "$ORG_NAME" --token "$GITHUB_TOKEN"
    fi

    press_enter
}

update_organization() {
    print_header
    echo -e "${CYAN}Update Organization${NC}"
    echo "==================="
    echo ""

    echo "Enter organization name:"
    ORG_NAME=$(read_input)

    if [ -z "$ORG_NAME" ]; then
        error "Organization name cannot be empty"
        press_enter
        return
    fi

    # Show current details
    echo ""
    info "Current organization details:"
    "$ORG_SH" show "$ORG_NAME" || {
        press_enter
        return
    }

    echo ""
    echo "What would you like to update?"
    echo "  1) Display name"
    echo "  2) Active status"
    echo "  3) Set as default"
    echo "  4) Cancel"
    echo ""
    UPDATE_CHOICE=$(read_input)

    case $UPDATE_CHOICE in
        1)
            echo ""
            echo "Enter new display name:"
            DISPLAY_NAME=$(read_input)

            if [ -n "$DISPLAY_NAME" ]; then
                "$ORG_SH" update "$ORG_NAME" --display-name "$DISPLAY_NAME"
                success "Display name updated"
            fi
            ;;

        2)
            echo ""
            echo "Set as active? (true/false)"
            ACTIVE=$(read_input)

            if [ -n "$ACTIVE" ]; then
                "$ORG_SH" update "$ORG_NAME" --active "$ACTIVE"
                success "Active status updated"
            fi
            ;;

        3)
            "$ORG_SH" set-default "$ORG_NAME"
            success "Set as default organization"
            ;;

        4|*)
            info "Cancelled"
            ;;
    esac

    press_enter
}

delete_organization() {
    print_header
    echo -e "${CYAN}Delete Organization${NC}"
    echo "==================="
    echo ""

    echo "Enter organization name:"
    ORG_NAME=$(read_input)

    if [ -z "$ORG_NAME" ]; then
        error "Organization name cannot be empty"
        press_enter
        return
    fi

    # Show organization details
    echo ""
    info "Organization to delete:"
    "$ORG_SH" show "$ORG_NAME" || {
        press_enter
        return
    }

    echo ""
    warning "This will permanently delete the organization and all its data!"
    echo "Are you sure you want to delete '$ORG_NAME'? (type 'yes' to confirm)"
    CONFIRM=$(read_input)

    if [ "$CONFIRM" == "yes" ]; then
        "$ORG_SH" delete "$ORG_NAME" --force
        success "Organization deleted"
    else
        info "Cancelled"
    fi

    press_enter
}

import_repositories() {
    print_header
    echo -e "${CYAN}Import Repositories from GitHub${NC}"
    echo "================================"
    echo ""

    echo "Enter organization name:"
    ORG_NAME=$(read_input)

    if [ -z "$ORG_NAME" ]; then
        error "Organization name cannot be empty"
        press_enter
        return
    fi

    echo ""
    echo "Use GITHUB_TOKEN from environment? (Y/n)"
    USE_ENV=$(read_input)

    if [[ "$USE_ENV" =~ ^[Nn]$ ]]; then
        echo ""
        echo "Enter GitHub token:"
        echo -n -e "${GREEN}> ${NC}"
        read -s GITHUB_TOKEN
        echo ""

        if [ -z "$GITHUB_TOKEN" ]; then
            error "GitHub token cannot be empty"
            press_enter
            return
        fi

        echo ""
        info "Importing repositories..."
        "$ORG_SH" import "$ORG_NAME" --token "$GITHUB_TOKEN"
    else
        echo ""
        info "Importing repositories..."
        "$ORG_SH" import "$ORG_NAME"
    fi

    press_enter
}

set_default_organization() {
    print_header
    echo -e "${CYAN}Set Default Organization${NC}"
    echo "========================"
    echo ""

    echo "Enter organization name:"
    ORG_NAME=$(read_input)

    if [ -z "$ORG_NAME" ]; then
        error "Organization name cannot be empty"
        press_enter
        return
    fi

    "$ORG_SH" set-default "$ORG_NAME"
    success "Set '$ORG_NAME' as default organization"

    press_enter
}

# Main loop
main() {
    while true; do
        print_header
        print_menu

        echo "Choose an option (1-8):"
        CHOICE=$(read_input)

        case $CHOICE in
            1)
                list_organizations
                ;;
            2)
                show_organization
                ;;
            3)
                create_organization
                ;;
            4)
                update_organization
                ;;
            5)
                delete_organization
                ;;
            6)
                import_repositories
                ;;
            7)
                set_default_organization
                ;;
            8)
                print_header
                success "Goodbye!"
                exit 0
                ;;
            *)
                error "Invalid choice. Please select 1-8."
                press_enter
                ;;
        esac
    done
}

# Check if org.sh exists
if [ ! -f "$ORG_SH" ]; then
    echo -e "${RED}✗ Error: org.sh not found at $ORG_SH${NC}"
    exit 1
fi

main

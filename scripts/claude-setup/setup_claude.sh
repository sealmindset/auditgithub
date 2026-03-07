#!/bin/bash
# Claude CLI Setup - Shell Wrapper
# Simple wrapper around the Python script for convenience

# Get the directory where this script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Run the Python script with all arguments passed through
python3 "${SCRIPT_DIR}/setup_claude.py" "$@"

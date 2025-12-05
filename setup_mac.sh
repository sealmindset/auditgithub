#!/bin/bash

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${GREEN}Starting AuditGH Setup for macOS...${NC}"

# 1. Check/Install Homebrew
if ! command -v brew &> /dev/null; then
    echo -e "${YELLOW}Homebrew not found. Installing...${NC}"
    /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
    
    # Add Homebrew to PATH for Apple Silicon
    if [[ "$(uname -m)" == "arm64" ]]; then
        echo 'eval "$(/opt/homebrew/bin/brew shellenv)"' >> ~/.zprofile
        eval "$(/opt/homebrew/bin/brew shellenv)"
    fi
else
    echo -e "${GREEN}Homebrew is already installed.${NC}"
fi

# 2. Install System Dependencies via Homebrew
echo -e "${GREEN}Installing system dependencies...${NC}"
brew update

# List of casks (GUI apps)
CASKS=(
    "docker"
)

# List of formulae (CLI tools)
FORMULAE=(
    "git"
    "python@3.11"
    "node"
    "jq"
)

for cask in "${CASKS[@]}"; do
    if ! brew list --cask "$cask" &> /dev/null; then
        echo -e "${YELLOW}Installing $cask...${NC}"
        brew install --cask "$cask"
    else
        echo -e "${GREEN}$cask is already installed.${NC}"
    fi
done

for formula in "${FORMULAE[@]}"; do
    if ! brew list --formula "$formula" &> /dev/null; then
        echo -e "${YELLOW}Installing $formula...${NC}"
        brew install "$formula"
    else
        echo -e "${GREEN}$formula is already installed.${NC}"
    fi
done

# 3. Start Docker
echo -e "${GREEN}Checking Docker status...${NC}"
if ! docker info > /dev/null 2>&1; then
    echo -e "${YELLOW}Docker is not running. Starting Docker...${NC}"
    open -a Docker
    echo "Waiting for Docker to start..."
    while ! docker info > /dev/null 2>&1; do
        sleep 2
        echo -n "."
    done
    echo -e "\n${GREEN}Docker started!${NC}"
fi

# 4. Setup Environment
echo -e "${GREEN}Setting up environment...${NC}"
if [ ! -f .env ]; then
    echo -e "${YELLOW}Creating .env from .env.sample...${NC}"
    cp .env.sample .env
    echo -e "${RED}IMPORTANT: Please edit .env and add your GITHUB_TOKEN and GITHUB_ORG!${NC}"
    open .env
else
    echo -e "${GREEN}.env file already exists.${NC}"
fi

# 5. Build Docker Containers
echo -e "${GREEN}Building Docker containers...${NC}"
docker-compose build

# 6. Optional: Install Local Dependencies
echo -e "${YELLOW}Do you want to install local scanning tools (trivy, gitleaks, etc.) for CLI usage? (y/n)${NC}"
read -r response
if [[ "$response" =~ ^([yY][eE][sS]|[yY])+$ ]]; then
    chmod +x install_dependencies.sh
    ./install_dependencies.sh
fi

echo -e "${GREEN}Setup Complete!${NC}"
echo -e "To run a scan using Docker (recommended):"
echo -e "  ${YELLOW}./run_scan.sh${NC}"
echo -e "To start the Web UI:"
echo -e "  ${YELLOW}docker-compose up -d${NC}"
echo -e "  Then visit http://localhost:3000"

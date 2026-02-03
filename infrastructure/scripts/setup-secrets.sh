#!/bin/bash

# Setup AWS Secrets Manager secrets for AuditGitHub
# This script creates all required secrets in AWS Secrets Manager

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Configuration
ENVIRONMENT=${ENVIRONMENT:-prod}
AWS_REGION=${AWS_REGION:-us-east-1}
SECRETS_PREFIX="auditgithub/${ENVIRONMENT}"

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}  Setup AWS Secrets Manager${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""
echo "Environment: ${ENVIRONMENT}"
echo "Region: ${AWS_REGION}"
echo "Secrets Prefix: ${SECRETS_PREFIX}"
echo ""

# Function to create or update secret
create_secret() {
  local secret_name=$1
  local secret_value=$2
  local description=$3

  # Check if secret exists
  if aws secretsmanager describe-secret \
    --secret-id "${secret_name}" \
    --region ${AWS_REGION} > /dev/null 2>&1; then

    echo "  Updating existing secret: ${secret_name}"
    aws secretsmanager update-secret \
      --secret-id "${secret_name}" \
      --secret-string "${secret_value}" \
      --region ${AWS_REGION} > /dev/null
  else
    echo "  Creating new secret: ${secret_name}"
    aws secretsmanager create-secret \
      --name "${secret_name}" \
      --description "${description}" \
      --secret-string "${secret_value}" \
      --region ${AWS_REGION} > /dev/null
  fi
}

# Database credentials
echo -e "${YELLOW}[1/6]${NC} Setting up database credentials..."

read -p "Enter database username (default: postgres): " DB_USER
DB_USER=${DB_USER:-postgres}

read -sp "Enter database password (leave empty to auto-generate): " DB_PASSWORD
echo ""

if [ -z "${DB_PASSWORD}" ]; then
  DB_PASSWORD=$(openssl rand -base64 32)
  echo "  Auto-generated database password"
fi

create_secret "${SECRETS_PREFIX}/db/username" "${DB_USER}" "Database username"
create_secret "${SECRETS_PREFIX}/db/password" "${DB_PASSWORD}" "Database password"

echo "✓ Database credentials configured"
echo ""

# Redis credentials
echo -e "${YELLOW}[2/6]${NC} Setting up Redis credentials..."

read -sp "Enter Redis password (leave empty to auto-generate): " REDIS_PASSWORD
echo ""

if [ -z "${REDIS_PASSWORD}" ]; then
  REDIS_PASSWORD=$(openssl rand -base64 32 | tr -d '/+=')  # Remove special chars for Redis
  echo "  Auto-generated Redis password"
fi

create_secret "${SECRETS_PREFIX}/redis/password" "${REDIS_PASSWORD}" "Redis auth token"

echo "✓ Redis credentials configured"
echo ""

# GitHub token
echo -e "${YELLOW}[3/6]${NC} Setting up GitHub token..."

read -sp "Enter GitHub Personal Access Token: " GITHUB_TOKEN
echo ""

if [ -z "${GITHUB_TOKEN}" ]; then
  echo -e "${RED}Error: GitHub token is required${NC}"
  exit 1
fi

create_secret "${SECRETS_PREFIX}/github/token" "${GITHUB_TOKEN}" "GitHub Personal Access Token"

echo "✓ GitHub token configured"
echo ""

# Application secret key
echo -e "${YELLOW}[4/6]${NC} Setting up application secret key..."

SECRET_KEY=$(openssl rand -base64 32)
create_secret "${SECRETS_PREFIX}/app/secret-key" "${SECRET_KEY}" "Application secret key"

echo "✓ Application secret key configured"
echo ""

# Semgrep API key (optional)
echo -e "${YELLOW}[5/6]${NC} Setting up Semgrep API key (optional)..."

read -p "Enter Semgrep API key (leave empty to skip): " SEMGREP_KEY
echo ""

if [ ! -z "${SEMGREP_KEY}" ]; then
  create_secret "${SECRETS_PREFIX}/semgrep/api-key" "${SEMGREP_KEY}" "Semgrep API key"
  echo "✓ Semgrep API key configured"
else
  echo "⊘ Skipped Semgrep API key"
fi
echo ""

# Summary
echo -e "${YELLOW}[6/6]${NC} Summary of configured secrets..."
echo ""
echo "Secrets created in AWS Secrets Manager:"
echo "  - ${SECRETS_PREFIX}/db/username"
echo "  - ${SECRETS_PREFIX}/db/password"
echo "  - ${SECRETS_PREFIX}/redis/password"
echo "  - ${SECRETS_PREFIX}/github/token"
echo "  - ${SECRETS_PREFIX}/app/secret-key"
if [ ! -z "${SEMGREP_KEY}" ]; then
  echo "  - ${SECRETS_PREFIX}/semgrep/api-key"
fi
echo ""

echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}  Secrets Setup Complete!${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""
echo "Next steps:"
echo "  1. Update Terraform variables with these secrets"
echo "  2. Deploy infrastructure: cd ../terraform && terraform apply"
echo "  3. Run migrations: ./run-migrations.sh"
echo "  4. Deploy application: ./deploy.sh"
echo ""

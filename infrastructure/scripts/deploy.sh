#!/bin/bash

# AuditGitHub AWS ECS Deployment Script
# Builds and deploys containers to AWS ECS

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
AWS_ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}  AuditGitHub AWS ECS Deployment${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""
echo "Environment: ${ENVIRONMENT}"
echo "Region: ${AWS_REGION}"
echo "Account: ${AWS_ACCOUNT_ID}"
echo ""

# Get Terraform outputs
cd ../terraform
echo -e "${YELLOW}[1/6]${NC} Retrieving infrastructure details..."
API_REPO=$(terraform output -raw api_ecr_repository_url)
WEBUI_REPO=$(terraform output -raw webui_ecr_repository_url)
ECS_CLUSTER=$(terraform output -raw ecs_cluster_name)
API_SERVICE=$(terraform output -raw api_service_name)
WEBUI_SERVICE=$(terraform output -raw webui_service_name)
cd -

echo "✓ Infrastructure details retrieved"
echo ""

# Login to ECR
echo -e "${YELLOW}[2/6]${NC} Logging in to Amazon ECR..."
aws ecr get-login-password --region ${AWS_REGION} | \
  docker login --username AWS --password-stdin \
  ${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com

echo "✓ Logged in to ECR"
echo ""

# Build and push API image
echo -e "${YELLOW}[3/6]${NC} Building API image..."
cd ../../
docker build -f Dockerfile.api -t auditgithub-api:latest .

echo "✓ API image built"
echo ""

echo -e "${YELLOW}[4/6]${NC} Pushing API image to ECR..."
GIT_SHA=$(git rev-parse --short HEAD)
docker tag auditgithub-api:latest ${API_REPO}:latest
docker tag auditgithub-api:latest ${API_REPO}:${GIT_SHA}
docker push ${API_REPO}:latest
docker push ${API_REPO}:${GIT_SHA}

echo "✓ API image pushed: ${API_REPO}:${GIT_SHA}"
echo ""

# Build and push Web UI image
echo -e "${YELLOW}[5/6]${NC} Building and pushing Web UI image..."
docker build -f Dockerfile.ui -t auditgithub-webui:latest .
docker tag auditgithub-webui:latest ${WEBUI_REPO}:latest
docker tag auditgithub-webui:latest ${WEBUI_REPO}:${GIT_SHA}
docker push ${WEBUI_REPO}:latest
docker push ${WEBUI_REPO}:${GIT_SHA}

echo "✓ Web UI image pushed: ${WEBUI_REPO}:${GIT_SHA}"
echo ""

# Deploy to ECS
echo -e "${YELLOW}[6/6]${NC} Deploying to ECS..."
echo "Updating API service..."
aws ecs update-service \
  --cluster ${ECS_CLUSTER} \
  --service ${API_SERVICE} \
  --force-new-deployment \
  --region ${AWS_REGION} \
  > /dev/null

echo "Updating Web UI service..."
aws ecs update-service \
  --cluster ${ECS_CLUSTER} \
  --service ${WEBUI_SERVICE} \
  --force-new-deployment \
  --region ${AWS_REGION} \
  > /dev/null

echo "✓ Deployment initiated"
echo ""

echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}  Deployment Complete!${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""
echo "Monitor deployment status:"
echo "  aws ecs describe-services --cluster ${ECS_CLUSTER} --services ${API_SERVICE} ${WEBUI_SERVICE}"
echo ""
echo "View logs:"
echo "  aws logs tail /ecs/auditgithub-${ENVIRONMENT}/api --follow"
echo "  aws logs tail /ecs/auditgithub-${ENVIRONMENT}/web-ui --follow"
echo ""

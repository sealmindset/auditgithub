#!/bin/bash

# Check health of deployed AuditGitHub services on AWS ECS
# This script verifies all services are running and healthy

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

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}  AuditGitHub Health Check${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

# Get Terraform outputs
cd ../terraform
echo -e "${YELLOW}[1/5]${NC} Retrieving infrastructure details..."
ECS_CLUSTER=$(terraform output -raw ecs_cluster_name)
API_SERVICE=$(terraform output -raw api_service_name)
WEBUI_SERVICE=$(terraform output -raw webui_service_name)
ALB_DNS=$(terraform output -raw alb_dns_name)
DB_ENDPOINT=$(terraform output -raw rds_endpoint)
REDIS_ENDPOINT=$(terraform output -raw redis_endpoint)
cd -

echo "✓ Infrastructure details retrieved"
echo ""

# Check ECS cluster
echo -e "${YELLOW}[2/5]${NC} Checking ECS cluster status..."
CLUSTER_STATUS=$(aws ecs describe-clusters \
  --clusters ${ECS_CLUSTER} \
  --region ${AWS_REGION} \
  --query 'clusters[0].status' \
  --output text)

if [ "${CLUSTER_STATUS}" == "ACTIVE" ]; then
  echo -e "  ${GREEN}✓${NC} Cluster: ${ECS_CLUSTER} is ACTIVE"
else
  echo -e "  ${RED}✗${NC} Cluster: ${ECS_CLUSTER} is ${CLUSTER_STATUS}"
fi
echo ""

# Check API service
echo -e "${YELLOW}[3/5]${NC} Checking API service..."
API_STATUS=$(aws ecs describe-services \
  --cluster ${ECS_CLUSTER} \
  --services ${API_SERVICE} \
  --region ${AWS_REGION} \
  --query 'services[0]')

API_DESIRED=$(echo ${API_STATUS} | jq -r '.desiredCount')
API_RUNNING=$(echo ${API_STATUS} | jq -r '.runningCount')
API_PENDING=$(echo ${API_STATUS} | jq -r '.pendingCount')

echo "  API Service: ${API_SERVICE}"
echo "    Desired: ${API_DESIRED}"
echo "    Running: ${API_RUNNING}"
echo "    Pending: ${API_PENDING}"

if [ "${API_RUNNING}" -eq "${API_DESIRED}" ]; then
  echo -e "    ${GREEN}✓${NC} Service is healthy"
else
  echo -e "    ${YELLOW}⚠${NC} Service is not at desired count"
fi
echo ""

# Check Web UI service
echo -e "${YELLOW}[4/5]${NC} Checking Web UI service..."
WEBUI_STATUS=$(aws ecs describe-services \
  --cluster ${ECS_CLUSTER} \
  --services ${WEBUI_SERVICE} \
  --region ${AWS_REGION} \
  --query 'services[0]')

WEBUI_DESIRED=$(echo ${WEBUI_STATUS} | jq -r '.desiredCount')
WEBUI_RUNNING=$(echo ${WEBUI_STATUS} | jq -r '.runningCount')
WEBUI_PENDING=$(echo ${WEBUI_STATUS} | jq -r '.pendingCount')

echo "  Web UI Service: ${WEBUI_SERVICE}"
echo "    Desired: ${WEBUI_DESIRED}"
echo "    Running: ${WEBUI_RUNNING}"
echo "    Pending: ${WEBUI_PENDING}"

if [ "${WEBUI_RUNNING}" -eq "${WEBUI_DESIRED}" ]; then
  echo -e "    ${GREEN}✓${NC} Service is healthy"
else
  echo -e "    ${YELLOW}⚠${NC} Service is not at desired count"
fi
echo ""

# Check application endpoints
echo -e "${YELLOW}[5/5]${NC} Checking application endpoints..."

echo "  Testing ALB endpoint: http://${ALB_DNS}"
if curl -f -s -o /dev/null -w "%{http_code}" "http://${ALB_DNS}/health" | grep -q "200"; then
  echo -e "    ${GREEN}✓${NC} API health check passed"
else
  echo -e "    ${RED}✗${NC} API health check failed"
fi

if curl -f -s -o /dev/null -w "%{http_code}" "http://${ALB_DNS}/" | grep -q "200"; then
  echo -e "    ${GREEN}✓${NC} Web UI is accessible"
else
  echo -e "    ${YELLOW}⚠${NC} Web UI may still be starting"
fi
echo ""

# Summary
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}  Health Check Complete!${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""
echo "Application URLs:"
echo "  Web UI: http://${ALB_DNS}"
echo "  API: http://${ALB_DNS}/api"
echo "  API Docs: http://${ALB_DNS}/docs"
echo ""
echo "Backend Services:"
echo "  Database: ${DB_ENDPOINT}"
echo "  Redis: ${REDIS_ENDPOINT}"
echo ""
echo "View logs:"
echo "  API: aws logs tail /ecs/auditgithub-${ENVIRONMENT}/api --follow --region ${AWS_REGION}"
echo "  Web UI: aws logs tail /ecs/auditgithub-${ENVIRONMENT}/web-ui --follow --region ${AWS_REGION}"
echo ""
echo "Monitor services:"
echo "  aws ecs describe-services --cluster ${ECS_CLUSTER} --services ${API_SERVICE} ${WEBUI_SERVICE} --region ${AWS_REGION}"
echo ""

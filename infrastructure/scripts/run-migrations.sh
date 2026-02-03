#!/bin/bash

# Run database migrations on AWS ECS
# This script runs migrations as a one-off ECS task

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
echo -e "${BLUE}  Running Database Migrations${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

# Get Terraform outputs
cd ../terraform
echo -e "${YELLOW}[1/4]${NC} Retrieving infrastructure details..."
ECS_CLUSTER=$(terraform output -raw ecs_cluster_name)
PRIVATE_SUBNETS=$(terraform output -json private_subnet_ids | jq -r '.[]' | tr '\n' ',' | sed 's/,$//')
ECS_SG=$(terraform output -raw ecs_security_group_id)
EXECUTION_ROLE=$(terraform output -raw ecs_execution_role_arn)
TASK_ROLE=$(terraform output -raw ecs_task_role_arn)
API_REPO=$(terraform output -raw api_ecr_repository_url)
DB_HOST=$(terraform output -raw rds_endpoint | cut -d: -f1)
REDIS_HOST=$(terraform output -raw redis_endpoint)
REPORTS_BUCKET=$(terraform output -raw reports_bucket_name)
cd -

echo "✓ Infrastructure details retrieved"
echo ""

# Create task definition for migrations
echo -e "${YELLOW}[2/4]${NC} Creating migration task definition..."
cat > /tmp/migration-task-def.json <<EOF
{
  "family": "auditgithub-${ENVIRONMENT}-migration",
  "networkMode": "awsvpc",
  "requiresCompatibilities": ["FARGATE"],
  "cpu": "512",
  "memory": "1024",
  "executionRoleArn": "${EXECUTION_ROLE}",
  "taskRoleArn": "${TASK_ROLE}",
  "containerDefinitions": [
    {
      "name": "migration",
      "image": "${API_REPO}:latest",
      "essential": true,
      "command": ["python", "-m", "alembic", "upgrade", "head"],
      "environment": [
        {
          "name": "DB_HOST",
          "value": "${DB_HOST}"
        },
        {
          "name": "DB_PORT",
          "value": "5432"
        },
        {
          "name": "DB_NAME",
          "value": "auditgithub"
        }
      ],
      "secrets": [
        {
          "name": "DB_USER",
          "valueFrom": "auditgithub/${ENVIRONMENT}/db/username"
        },
        {
          "name": "DB_PASSWORD",
          "valueFrom": "auditgithub/${ENVIRONMENT}/db/password"
        }
      ],
      "logConfiguration": {
        "logDriver": "awslogs",
        "options": {
          "awslogs-group": "/ecs/auditgithub-${ENVIRONMENT}/migration",
          "awslogs-region": "${AWS_REGION}",
          "awslogs-stream-prefix": "migration"
        }
      }
    }
  ]
}
EOF

# Register task definition
TASK_DEF_ARN=$(aws ecs register-task-definition \
  --cli-input-json file:///tmp/migration-task-def.json \
  --region ${AWS_REGION} \
  --query 'taskDefinition.taskDefinitionArn' \
  --output text)

echo "✓ Task definition registered: ${TASK_DEF_ARN}"
echo ""

# Run migration task
echo -e "${YELLOW}[3/4]${NC} Running migration task..."
TASK_ARN=$(aws ecs run-task \
  --cluster ${ECS_CLUSTER} \
  --task-definition ${TASK_DEF_ARN} \
  --launch-type FARGATE \
  --network-configuration "awsvpcConfiguration={subnets=[${PRIVATE_SUBNETS}],securityGroups=[${ECS_SG}],assignPublicIp=DISABLED}" \
  --region ${AWS_REGION} \
  --query 'tasks[0].taskArn' \
  --output text)

echo "✓ Migration task started: ${TASK_ARN}"
echo ""

# Wait for task to complete
echo -e "${YELLOW}[4/4]${NC} Waiting for migration to complete..."
echo "Task ARN: ${TASK_ARN}"
echo ""

aws ecs wait tasks-stopped \
  --cluster ${ECS_CLUSTER} \
  --tasks ${TASK_ARN} \
  --region ${AWS_REGION}

# Check task exit code
EXIT_CODE=$(aws ecs describe-tasks \
  --cluster ${ECS_CLUSTER} \
  --tasks ${TASK_ARN} \
  --region ${AWS_REGION} \
  --query 'tasks[0].containers[0].exitCode' \
  --output text)

if [ "${EXIT_CODE}" == "0" ]; then
  echo -e "${GREEN}✓ Migration completed successfully${NC}"
  echo ""
  echo -e "${GREEN}========================================${NC}"
  echo -e "${GREEN}  Migration Complete!${NC}"
  echo -e "${GREEN}========================================${NC}"
  exit 0
else
  echo -e "${RED}✗ Migration failed with exit code: ${EXIT_CODE}${NC}"
  echo ""
  echo "Check logs:"
  echo "  aws logs tail /ecs/auditgithub-${ENVIRONMENT}/migration --follow"
  exit 1
fi

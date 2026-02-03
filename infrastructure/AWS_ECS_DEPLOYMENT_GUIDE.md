# AWS ECS Deployment Guide for AuditGitHub

## 📋 Table of Contents

1. [Prerequisites](#prerequisites)
2. [Architecture Overview](#architecture-overview)
3. [Phase 1: Prepare AWS Account](#phase-1-prepare-aws-account)
4. [Phase 2: Create Infrastructure](#phase-2-create-infrastructure)
5. [Phase 3: Build and Push Images](#phase-3-build-and-push-images)
6. [Phase 4: Deploy to ECS](#phase-4-deploy-to-ecs)
7. [Phase 5: Configure CI/CD](#phase-5-configure-cicd)
8. [Cost Estimation](#cost-estimation)
9. [Troubleshooting](#troubleshooting)

---

## Prerequisites

### Required Tools
```bash
# Install AWS CLI
brew install awscli  # macOS
# Configure AWS credentials
aws configure

# Install Terraform
brew install terraform

# Install jq (JSON processor)
brew install jq

# Install Docker (already have)
# Docker Desktop installed ✓
```

### AWS Account Requirements
- AWS Account with admin access
- AWS CLI configured with credentials
- Terraform installed (v1.5+)
- Docker installed and running

### Estimated Costs
- **Development**: $100-200/month
- **Staging**: $200-400/month
- **Production**: $500-1000/month

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                        Route 53                             │
│                     auditgithub.com                         │
└────────────────────────┬────────────────────────────────────┘
                         │
┌────────────────────────▼────────────────────────────────────┐
│              Application Load Balancer (ALB)                 │
│  - SSL/TLS Termination (ACM Certificate)                    │
│  - Health Checks                                            │
│  - Port 80 → 443 redirect                                  │
└──────┬─────────────────────────┬────────────────────────────┘
       │                         │
┌──────▼─────────┐        ┌──────▼─────────┐
│  ECS Service   │        │  ECS Service   │
│     (API)      │        │   (Web UI)     │
│  - Fargate     │        │  - Fargate     │
│  - 2-4 tasks   │        │  - 2-4 tasks   │
│  - Auto-scale  │        │  - Auto-scale  │
└───────┬────────┘        └────────────────┘
        │
┌───────▼──────────────────────────────────────┐
│            Backend Services                   │
│  ┌────────────────────────────────────────┐  │
│  │  RDS PostgreSQL (Multi-AZ)             │  │
│  │  - db.t3.medium                        │  │
│  │  - 100GB storage                       │  │
│  │  - Automated backups                   │  │
│  └────────────────────────────────────────┘  │
│                                               │
│  ┌────────────────────────────────────────┐  │
│  │  ElastiCache Redis                     │  │
│  │  - cache.t3.micro                      │  │
│  │  - 1 node (dev) / 2 nodes (prod)      │  │
│  └────────────────────────────────────────┘  │
│                                               │
│  ┌────────────────────────────────────────┐  │
│  │  S3 Buckets                            │  │
│  │  - Vulnerability reports               │  │
│  │  - Application logs                    │  │
│  │  - Terraform state                     │  │
│  └────────────────────────────────────────┘  │
│                                               │
│  ┌────────────────────────────────────────┐  │
│  │  Secrets Manager                       │  │
│  │  - Database credentials                │  │
│  │  - GitHub tokens                       │  │
│  │  - API keys                            │  │
│  └────────────────────────────────────────┘  │
└───────────────────────────────────────────────┘
```

### Service Architecture

| Component | Local | AWS ECS |
|-----------|-------|---------|
| API | Docker container | ECS Fargate (2-4 tasks) |
| Web UI | Docker container | ECS Fargate (2-4 tasks) |
| Database | PostgreSQL container | RDS PostgreSQL Multi-AZ |
| Cache | Redis container | ElastiCache Redis |
| Storage | MinIO container | S3 |
| Secrets | .env file | Secrets Manager |

---

## Phase 1: Prepare AWS Account

### 1.1 Create S3 Bucket for Terraform State

```bash
# Set your unique bucket name
export TF_STATE_BUCKET="auditgithub-terraform-state-$(aws sts get-caller-identity --query Account --output text)"
export AWS_REGION="us-east-1"  # or your preferred region

# Create bucket
aws s3 mb s3://${TF_STATE_BUCKET} --region ${AWS_REGION}

# Enable versioning
aws s3api put-bucket-versioning \
  --bucket ${TF_STATE_BUCKET} \
  --versioning-configuration Status=Enabled

# Enable encryption
aws s3api put-bucket-encryption \
  --bucket ${TF_STATE_BUCKET} \
  --server-side-encryption-configuration '{
    "Rules": [{
      "ApplyServerSideEncryptionByDefault": {
        "SSEAlgorithm": "AES256"
      }
    }]
  }'

# Block public access
aws s3api put-public-access-block \
  --bucket ${TF_STATE_BUCKET} \
  --public-access-block-configuration \
    "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"
```

### 1.2 Store Secrets in AWS Secrets Manager

```bash
# Create database master password
aws secretsmanager create-secret \
  --name auditgithub/prod/db/master-password \
  --secret-string "$(openssl rand -base64 32)" \
  --region ${AWS_REGION}

# Store GitHub token
aws secretsmanager create-secret \
  --name auditgithub/prod/github/token \
  --secret-string "YOUR_GITHUB_TOKEN" \
  --region ${AWS_REGION}

# Store other secrets
aws secretsmanager create-secret \
  --name auditgithub/prod/secrets/master-key \
  --secret-string "$(openssl rand -base64 32)" \
  --region ${AWS_REGION}
```

### 1.3 Request SSL Certificate (ACM)

```bash
# Request certificate for your domain
aws acm request-certificate \
  --domain-name "auditgithub.yourdomain.com" \
  --subject-alternative-names "*.auditgithub.yourdomain.com" \
  --validation-method DNS \
  --region ${AWS_REGION}

# Note the CertificateArn from output
# Follow DNS validation instructions in ACM console
```

---

## Phase 2: Create Infrastructure

I've created the Terraform infrastructure in `infrastructure/terraform/`. Here's how to use it:

### 2.1 Initialize Terraform Backend

Create `infrastructure/terraform/backend.tf`:

```hcl
terraform {
  backend "s3" {
    bucket         = "auditgithub-terraform-state-ACCOUNT_ID"
    key            = "prod/terraform.tfstate"
    region         = "us-east-1"
    encrypt        = true
    dynamodb_table = "terraform-state-lock"
  }
}
```

### 2.2 Create DynamoDB Table for State Locking

```bash
aws dynamodb create-table \
  --table-name terraform-state-lock \
  --attribute-definitions AttributeName=LockID,AttributeType=S \
  --key-schema AttributeName=LockID,KeyType=HASH \
  --billing-mode PAY_PER_REQUEST \
  --region ${AWS_REGION}
```

### 2.3 Configure Terraform Variables

Create `infrastructure/terraform/terraform.tfvars`:

```hcl
# Environment
environment = "prod"
aws_region  = "us-east-1"
owner_email = "your-email@company.com"

# Network Configuration
vpc_cidr            = "10.0.0.0/16"
availability_zones  = ["us-east-1a", "us-east-1b", "us-east-1c"]

# Domain Configuration
domain_name = "auditgithub.yourdomain.com"
certificate_arn = "arn:aws:acm:us-east-1:ACCOUNT:certificate/CERT_ID"

# Database Configuration
db_instance_class = "db.t3.medium"
db_allocated_storage = 100
db_name = "auditgithub"

# Cache Configuration
cache_node_type = "cache.t3.micro"
cache_num_nodes = 2

# ECS Configuration
api_task_cpu = 1024
api_task_memory = 2048
api_desired_count = 2
api_max_count = 4

webui_task_cpu = 512
webui_task_memory = 1024
webui_desired_count = 2
webui_max_count = 4

# Tags
tags = {
  Project     = "AuditGitHub"
  Environment = "Production"
  ManagedBy   = "Terraform"
}
```

### 2.4 Deploy Infrastructure

```bash
cd infrastructure/terraform

# Initialize Terraform
terraform init

# Validate configuration
terraform validate

# Plan deployment (review changes)
terraform plan -out=tfplan

# Apply (create infrastructure)
terraform apply tfplan

# Save outputs
terraform output -json > outputs.json
```

This will take 15-20 minutes to create:
- VPC with public/private subnets
- RDS PostgreSQL database
- ElastiCache Redis cluster
- ECS cluster
- Application Load Balancer
- Security groups
- IAM roles
- ECR repositories
- S3 buckets

---

## Phase 3: Build and Push Images

### 3.1 Login to ECR

```bash
# Get ECR login token
aws ecr get-login-password --region ${AWS_REGION} | \
  docker login --username AWS --password-stdin \
  $(aws sts get-caller-identity --query Account --output text).dkr.ecr.${AWS_REGION}.amazonaws.com
```

### 3.2 Build and Push API Image

```bash
# Get ECR repository URLs from Terraform output
export API_REPO=$(terraform output -raw api_ecr_repository_url)
export WEBUI_REPO=$(terraform output -raw webui_ecr_repository_url)

# Build API image
docker build -f Dockerfile.api -t auditgithub-api:latest .

# Tag for ECR
docker tag auditgithub-api:latest ${API_REPO}:latest
docker tag auditgithub-api:latest ${API_REPO}:$(git rev-parse --short HEAD)

# Push to ECR
docker push ${API_REPO}:latest
docker push ${API_REPO}:$(git rev-parse --short HEAD)
```

### 3.3 Build and Push Web UI Image

```bash
# Build Web UI image
docker build -f Dockerfile.ui -t auditgithub-webui:latest .

# Tag for ECR
docker tag auditgithub-webui:latest ${WEBUI_REPO}:latest
docker tag auditgithub-webui:latest ${WEBUI_REPO}:$(git rev-parse --short HEAD)

# Push to ECR
docker push ${WEBUI_REPO}:latest
docker push ${WEBUI_REPO}:$(git rev-parse --short HEAD)
```

---

## Phase 4: Deploy to ECS

### 4.1 Run Database Migrations

```bash
# Get RDS endpoint
export DB_ENDPOINT=$(terraform output -raw rds_endpoint)

# Run migrations using ECS task
aws ecs run-task \
  --cluster auditgithub-prod \
  --task-definition auditgithub-migration \
  --launch-type FARGATE \
  --network-configuration "awsvpcConfiguration={
    subnets=[$(terraform output -raw private_subnet_ids)],
    securityGroups=[$(terraform output -raw ecs_security_group_id)],
    assignPublicIp=DISABLED
  }"
```

### 4.2 Verify Services

```bash
# Check ECS services
aws ecs list-services --cluster auditgithub-prod

# Check task status
aws ecs list-tasks --cluster auditgithub-prod \
  --service-name auditgithub-api-service

# Check service health
export ALB_DNS=$(terraform output -raw alb_dns_name)
curl -f https://${ALB_DNS}/health
```

### 4.3 Configure DNS

```bash
# Get ALB DNS name
terraform output alb_dns_name

# Create Route 53 record (or use your DNS provider)
aws route53 change-resource-record-sets \
  --hosted-zone-id YOUR_ZONE_ID \
  --change-batch file://dns-change.json
```

Example `dns-change.json`:
```json
{
  "Changes": [{
    "Action": "UPSERT",
    "ResourceRecordSet": {
      "Name": "auditgithub.yourdomain.com",
      "Type": "A",
      "AliasTarget": {
        "HostedZoneId": "Z35SXDOTRQ7X7K",
        "DNSName": "auditgithub-alb-123456.us-east-1.elb.amazonaws.com",
        "EvaluateTargetHealth": true
      }
    }
  }]
}
```

---

## Phase 5: Configure CI/CD

The GitHub Actions workflow in `.github/workflows/deploy-ecs.yml` automates:

1. Build Docker images
2. Push to ECR
3. Update ECS task definitions
4. Deploy to ECS
5. Wait for deployment completion

### 5.1 Configure GitHub Secrets

Add these secrets to your GitHub repository (Settings → Secrets and variables → Actions):

```
AWS_ACCESS_KEY_ID
AWS_SECRET_ACCESS_KEY
AWS_REGION
ECR_API_REPOSITORY
ECR_WEBUI_REPOSITORY
ECS_CLUSTER_NAME
ECS_API_SERVICE_NAME
ECS_WEBUI_SERVICE_NAME
```

### 5.2 Trigger Deployment

```bash
# Push to main branch triggers automatic deployment
git push origin main

# Or manually trigger via GitHub Actions UI
```

---

## Cost Estimation

### Monthly Costs (Production)

| Service | Configuration | Monthly Cost |
|---------|--------------|--------------|
| ECS Fargate (API) | 2 tasks @ 1vCPU, 2GB | $60 |
| ECS Fargate (Web UI) | 2 tasks @ 0.5vCPU, 1GB | $30 |
| RDS PostgreSQL | db.t3.medium Multi-AZ | $180 |
| ElastiCache Redis | cache.t3.micro x2 | $50 |
| Application Load Balancer | Standard | $25 |
| NAT Gateway | 2 AZ | $65 |
| S3 Storage | 100GB | $3 |
| Data Transfer | 500GB | $45 |
| CloudWatch Logs | 50GB | $25 |
| Secrets Manager | 10 secrets | $4 |
| **Total** | | **~$487/month** |

### Development Environment (Lower Cost)

- Single-AZ RDS: $85/month
- Single Redis node: $25/month
- 1 task per service: $45/month
- **Total**: ~$200/month

---

## Troubleshooting

### Issue: ECS Tasks Failing to Start

```bash
# Check task logs
aws ecs describe-tasks \
  --cluster auditgithub-prod \
  --tasks TASK_ARN

# Check CloudWatch logs
aws logs tail /ecs/auditgithub-api --follow
```

### Issue: Cannot Connect to RDS

```bash
# Verify security groups
aws ec2 describe-security-groups \
  --group-ids $(terraform output -raw rds_security_group_id)

# Test connection from ECS task
aws ecs run-task \
  --cluster auditgithub-prod \
  --task-definition auditgithub-debug \
  --overrides '{
    "containerOverrides": [{
      "name": "debug",
      "command": ["psql", "-h", "DB_ENDPOINT", "-U", "postgres"]
    }]
  }'
```

### Issue: High Costs

```bash
# Check cost by service
aws ce get-cost-and-usage \
  --time-period Start=2024-01-01,End=2024-01-31 \
  --granularity MONTHLY \
  --metrics BlendedCost \
  --group-by Type=SERVICE

# Optimize:
# - Reduce ECS task count during off-hours
# - Use Spot instances for dev/staging
# - Enable S3 lifecycle policies
# - Review CloudWatch log retention
```

---

## Next Steps

1. **Set up monitoring**: Configure CloudWatch dashboards and alarms
2. **Enable auto-scaling**: Configure ECS service auto-scaling policies
3. **Implement backups**: Configure RDS automated backups and snapshots
4. **Security hardening**: Enable AWS GuardDuty, Security Hub, Config
5. **Cost optimization**: Review AWS Cost Explorer and set up budgets

---

## Quick Commands Reference

```bash
# View all resources
terraform state list

# Get specific output
terraform output alb_dns_name

# Update ECS service
aws ecs update-service \
  --cluster auditgithub-prod \
  --service auditgithub-api-service \
  --force-new-deployment

# Scale service
aws ecs update-service \
  --cluster auditgithub-prod \
  --service auditgithub-api-service \
  --desired-count 4

# View logs
aws logs tail /ecs/auditgithub-api --follow --since 10m

# SSH into Fargate task (requires Session Manager)
aws ecs execute-command \
  --cluster auditgithub-prod \
  --task TASK_ID \
  --container api \
  --interactive \
  --command "/bin/bash"
```

---

## Support

For issues or questions:
- Check CloudWatch Logs: `/ecs/auditgithub-*`
- Review ECS Events in AWS Console
- Check Application Load Balancer Target Health
- Review RDS Performance Insights

**Emergency Rollback**:
```bash
# Revert to previous task definition
aws ecs update-service \
  --cluster auditgithub-prod \
  --service auditgithub-api-service \
  --task-definition auditgithub-api:PREVIOUS_VERSION
```

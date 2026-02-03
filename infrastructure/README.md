# AuditGitHub Infrastructure

This directory contains all infrastructure-as-code (Terraform) and deployment tooling for running AuditGitHub on AWS ECS.

## 📁 Directory Structure

```
infrastructure/
├── AWS_ECS_DEPLOYMENT_GUIDE.md    # Complete deployment guide
├── README.md                       # This file
├── terraform/                      # Terraform infrastructure code
│   ├── main.tf                    # Main infrastructure configuration
│   ├── variables.tf               # Input variables
│   ├── outputs.tf                 # Output values
│   ├── versions.tf                # Provider versions
│   ├── backend.tf                 # S3 backend configuration (create this)
│   └── modules/                   # Reusable Terraform modules
│       ├── vpc/                   # VPC with public/private subnets
│       ├── security-groups/       # Security groups for all services
│       ├── iam/                   # IAM roles and policies
│       ├── ecr/                   # ECR container repositories
│       ├── s3/                    # S3 buckets for reports and logs
│       ├── rds/                   # RDS PostgreSQL database
│       ├── elasticache/           # ElastiCache Redis cluster
│       ├── alb/                   # Application Load Balancer
│       ├── ecs-cluster/           # ECS cluster configuration
│       └── ecs-service/           # Reusable ECS service module
├── task-definitions/              # ECS task definitions
│   ├── api-task-definition.json
│   ├── webui-task-definition.json
│   └── scanner-task-definition.json
└── scripts/                       # Deployment helper scripts
    ├── setup-secrets.sh           # Configure AWS Secrets Manager
    ├── deploy.sh                  # Deploy application to ECS
    ├── run-migrations.sh          # Run database migrations
    └── check-health.sh            # Verify deployment health
```

## 🚀 Quick Start

### 1. Prerequisites

Install required tools:
```bash
# AWS CLI
brew install awscli
aws configure

# Terraform
brew install terraform

# jq (JSON processor)
brew install jq

# Docker
# Already installed ✓
```

### 2. Setup AWS Infrastructure

Follow the [AWS ECS Deployment Guide](./AWS_ECS_DEPLOYMENT_GUIDE.md) for complete instructions.

**Quick steps:**

```bash
# 1. Create Terraform backend bucket
export TF_STATE_BUCKET="auditgithub-terraform-state-$(aws sts get-caller-identity --query Account --output text)"
aws s3 mb s3://${TF_STATE_BUCKET} --region us-east-1

# 2. Configure secrets
cd scripts
./setup-secrets.sh

# 3. Deploy infrastructure
cd ../terraform
terraform init
terraform plan -out=tfplan
terraform apply tfplan

# 4. Run database migrations
cd ../scripts
./run-migrations.sh

# 5. Deploy application
./deploy.sh

# 6. Check health
./check-health.sh
```

## 📋 Terraform Modules

### Core Infrastructure Modules

#### VPC Module
Creates VPC with public and private subnets across 3 availability zones:
- Public subnets for ALB
- Private subnets for ECS tasks and databases
- NAT gateways for outbound connectivity
- VPC Flow Logs for network monitoring

**Key Outputs:** `vpc_id`, `public_subnets`, `private_subnets`

#### Security Groups Module
Configures security groups with least-privilege access:
- ALB: Allows HTTP/HTTPS from internet
- ECS: Allows traffic from ALB only
- RDS: Allows PostgreSQL from ECS only
- Redis: Allows Redis from ECS only

**Key Outputs:** `alb_sg_id`, `ecs_sg_id`, `rds_sg_id`, `redis_sg_id`

#### IAM Module
Creates IAM roles with appropriate permissions:
- ECS Execution Role: Pull images, retrieve secrets, write logs
- ECS Task Role: Access S3, Secrets Manager, CloudWatch
- GitHub Actions Role (optional): Deploy from CI/CD

**Key Outputs:** `ecs_execution_role_arn`, `ecs_task_role_arn`

### Data Layer Modules

#### RDS Module
PostgreSQL database with production features:
- Multi-AZ deployment for high availability
- Automated backups (7-day retention)
- Encryption at rest with KMS
- Performance Insights enabled
- CloudWatch alarms for CPU, memory, storage

**Key Outputs:** `endpoint`, `port`, `database_name`

#### ElastiCache Module
Redis cluster for caching and job queues:
- Multi-node with automatic failover
- Encryption at rest and in transit
- AUTH token authentication
- Automated snapshots
- CloudWatch alarms

**Key Outputs:** `endpoint`, `port`

#### S3 Module
S3 buckets with lifecycle policies:
- Reports bucket with versioning
- Logs bucket for ALB and application logs
- Backups bucket (optional)
- Lifecycle transitions to IA and Glacier

**Key Outputs:** `reports_bucket_name`, `logs_bucket_name`

### Application Layer Modules

#### ALB Module
Application Load Balancer with SSL/TLS:
- HTTP to HTTPS redirect
- Path-based routing (/ → Web UI, /api → API)
- Health checks for both services
- Access logs to S3

**Key Outputs:** `alb_dns_name`, `api_target_group_arn`, `webui_target_group_arn`

#### ECS Cluster Module
ECS cluster with Fargate capacity providers:
- FARGATE and FARGATE_SPOT support
- Container Insights enabled
- CloudWatch alarms for cluster metrics

**Key Outputs:** `cluster_name`, `cluster_arn`

#### ECS Service Module (Reusable)
Generic ECS service module used for API, Web UI, and Scanner:
- Fargate launch type
- Auto-scaling based on CPU/memory
- Circuit breaker for deployment rollback
- CloudWatch Logs integration
- Health checks and grace periods

**Key Outputs:** `service_name`, `task_definition_arn`

### ECR Module
ECR repositories for container images:
- Scan on push enabled
- Lifecycle policy (keep last 30 images)
- Encryption at rest

**Key Outputs:** `repository_urls` (map of service → URL)

## 🛠️ Helper Scripts

### setup-secrets.sh
Interactive script to configure AWS Secrets Manager:
- Database credentials
- Redis password
- GitHub token
- Application secret key
- Semgrep API key (optional)

**Usage:**
```bash
cd scripts
ENVIRONMENT=prod ./setup-secrets.sh
```

### deploy.sh
Builds and deploys application to ECS:
- Logs in to ECR
- Builds Docker images
- Tags with git SHA and latest
- Pushes to ECR
- Forces new ECS deployment

**Usage:**
```bash
cd scripts
ENVIRONMENT=prod ./deploy.sh
```

### run-migrations.sh
Runs database migrations as ECS task:
- Creates one-off migration task
- Runs Alembic migrations
- Waits for completion
- Reports success/failure

**Usage:**
```bash
cd scripts
ENVIRONMENT=prod ./run-migrations.sh
```

### check-health.sh
Verifies deployment health:
- Checks ECS cluster status
- Verifies service task counts
- Tests ALB endpoints
- Shows logs and monitoring commands

**Usage:**
```bash
cd scripts
ENVIRONMENT=prod ./check-health.sh
```

## 🔐 Secrets Management

All secrets are stored in AWS Secrets Manager with the naming convention:
```
auditgithub/{environment}/{service}/{secret-name}
```

**Example secrets:**
- `auditgithub/prod/db/username`
- `auditgithub/prod/db/password`
- `auditgithub/prod/redis/password`
- `auditgithub/prod/github/token`
- `auditgithub/prod/app/secret-key`

Secrets are automatically injected into ECS tasks via task definitions.

## 📊 Cost Estimation

### Production Environment (~$487/month)
- ECS Fargate (API): 2 tasks @ 1vCPU, 2GB = $60
- ECS Fargate (Web UI): 2 tasks @ 0.5vCPU, 1GB = $30
- RDS PostgreSQL: db.t3.medium Multi-AZ = $180
- ElastiCache Redis: cache.t3.micro x2 = $50
- Application Load Balancer = $25
- NAT Gateway (2 AZ) = $65
- S3 Storage (100GB) = $3
- Data Transfer (500GB) = $45
- CloudWatch Logs (50GB) = $25
- Secrets Manager (10 secrets) = $4

### Development Environment (~$200/month)
- Single-AZ RDS: $85
- Single Redis node: $25
- 1 task per service: $45
- Other services: $45

## 🔧 Terraform Variables

Key variables you need to configure in `terraform.tfvars`:

```hcl
# Environment
environment = "prod"
aws_region  = "us-east-1"
owner_email = "your-email@company.com"

# Network
vpc_cidr           = "10.0.0.0/16"
availability_zones = ["us-east-1a", "us-east-1b", "us-east-1c"]

# Domain (optional)
domain_name     = "auditgithub.yourdomain.com"
certificate_arn = "arn:aws:acm:us-east-1:ACCOUNT:certificate/CERT_ID"

# Database
db_instance_class    = "db.t3.medium"
db_allocated_storage = 100

# Cache
cache_node_type = "cache.t3.micro"
cache_num_nodes = 2

# ECS
api_task_cpu      = 1024
api_task_memory   = 2048
api_desired_count = 2

webui_task_cpu      = 512
webui_task_memory   = 1024
webui_desired_count = 2
```

## 🔄 CI/CD Pipeline

GitHub Actions workflow automatically deploys on push to main:

**Workflow:** [`.github/workflows/deploy-ecs.yml`](../.github/workflows/deploy-ecs.yml)

**Required GitHub Secrets:**
- `AWS_ACCESS_KEY_ID`
- `AWS_SECRET_ACCESS_KEY`
- `AWS_REGION`
- `ECR_API_REPOSITORY`
- `ECR_WEBUI_REPOSITORY`
- `ECS_CLUSTER_NAME`
- `ECS_API_SERVICE_NAME`
- `ECS_WEBUI_SERVICE_NAME`
- `ECS_API_TASK_DEFINITION`
- `ECS_WEBUI_TASK_DEFINITION`

**Deployment Flow:**
1. Build Docker images
2. Push to ECR with git SHA tag
3. Update ECS task definitions
4. Deploy to ECS services
5. Wait for service stability
6. Verify deployment health

## 📚 Additional Resources

- [AWS ECS Deployment Guide](./AWS_ECS_DEPLOYMENT_GUIDE.md) - Complete step-by-step guide
- [Terraform AWS Provider Docs](https://registry.terraform.io/providers/hashicorp/aws/latest/docs)
- [ECS Best Practices](https://docs.aws.amazon.com/AmazonECS/latest/bestpracticesguide/intro.html)
- [Fargate Task Definitions](https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task_definitions.html)

## 🆘 Troubleshooting

### Infrastructure Issues

**Terraform errors:**
```bash
terraform init -upgrade
terraform plan -out=tfplan
terraform apply tfplan
```

**State lock issues:**
```bash
# View locks
aws dynamodb scan --table-name terraform-state-lock

# Force unlock (use with caution)
terraform force-unlock LOCK_ID
```

### Deployment Issues

**ECS tasks not starting:**
```bash
# Check service events
aws ecs describe-services --cluster CLUSTER --services SERVICE

# Check task logs
aws logs tail /ecs/auditgithub-prod/api --follow
```

**Database connection errors:**
```bash
# Verify security groups
aws ec2 describe-security-groups --group-ids SG_ID

# Test from ECS task
aws ecs execute-command --cluster CLUSTER --task TASK_ID \
  --container api --interactive --command "/bin/bash"
```

**Health check failures:**
```bash
# Check ALB target health
aws elbv2 describe-target-health --target-group-arn TG_ARN

# Test health endpoint
curl -v http://ALB_DNS/health
```

## 📝 Maintenance

### Regular Tasks

**Weekly:**
- Review CloudWatch alarms
- Check RDS backup retention
- Monitor ECS service metrics

**Monthly:**
- Review AWS Cost Explorer
- Update Docker base images
- Rotate secrets

**Quarterly:**
- Review security group rules
- Update Terraform modules
- Test disaster recovery

### Updates

**Infrastructure changes:**
```bash
cd terraform
terraform plan -out=tfplan
terraform apply tfplan
```

**Application deployment:**
```bash
cd scripts
./deploy.sh
```

**Database migrations:**
```bash
cd scripts
./run-migrations.sh
```

## 🔒 Security Best Practices

1. **Never commit secrets** to git - use AWS Secrets Manager
2. **Use Multi-AZ** for production databases
3. **Enable encryption** at rest and in transit
4. **Implement least-privilege** IAM policies
5. **Enable CloudWatch Logs** and monitoring
6. **Use private subnets** for ECS tasks and databases
7. **Configure VPC Flow Logs** for network visibility
8. **Enable Container Insights** for ECS monitoring
9. **Use ACM certificates** for SSL/TLS
10. **Implement automated backups** and test restores

---

For detailed deployment instructions, see [AWS_ECS_DEPLOYMENT_GUIDE.md](./AWS_ECS_DEPLOYMENT_GUIDE.md).

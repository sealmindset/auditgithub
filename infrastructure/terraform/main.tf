# AuditGitHub AWS ECS Infrastructure
# This is a starter template - expand modules as needed

locals {
  name_prefix = "${var.project_name}-${var.environment}"

  common_tags = merge(var.tags, {
    Environment = var.environment
    Project     = var.project_name
    ManagedBy   = "Terraform"
  })
}

#==============================================================================
# VPC and Networking
#==============================================================================

module "vpc" {
  source = "./modules/vpc"

  name_prefix        = local.name_prefix
  vpc_cidr           = var.vpc_cidr
  availability_zones = var.availability_zones

  tags = local.common_tags
}

#==============================================================================
# Security Groups
#==============================================================================

module "security_groups" {
  source = "./modules/security-groups"

  name_prefix = local.name_prefix
  vpc_id      = module.vpc.vpc_id

  tags = local.common_tags
}

#==============================================================================
# Application Load Balancer
#==============================================================================

module "alb" {
  source = "./modules/alb"

  name_prefix      = local.name_prefix
  vpc_id           = module.vpc.vpc_id
  public_subnets   = module.vpc.public_subnets
  security_groups  = [module.security_groups.alb_sg_id]
  certificate_arn  = var.certificate_arn

  tags = local.common_tags
}

#==============================================================================
# RDS PostgreSQL Database
#==============================================================================

module "rds" {
  source = "./modules/rds"

  name_prefix         = local.name_prefix
  vpc_id              = module.vpc.vpc_id
  private_subnets     = module.vpc.private_subnets
  security_groups     = [module.security_groups.rds_sg_id]

  instance_class      = var.db_instance_class
  allocated_storage   = var.db_allocated_storage
  database_name       = var.db_name
  master_username     = var.db_master_username
  multi_az            = var.environment == "prod"

  backup_retention_period = var.environment == "prod" ? 30 : 7

  tags = local.common_tags
}

#==============================================================================
# ElastiCache Redis
#==============================================================================

module "elasticache" {
  source = "./modules/elasticache"

  name_prefix     = local.name_prefix
  vpc_id          = module.vpc.vpc_id
  private_subnets = module.vpc.private_subnets
  security_groups = [module.security_groups.redis_sg_id]

  node_type       = var.cache_node_type
  num_cache_nodes = var.cache_num_nodes

  tags = local.common_tags
}

#==============================================================================
# S3 Buckets
#==============================================================================

module "s3" {
  source = "./modules/s3"

  name_prefix = local.name_prefix
  environment = var.environment

  tags = local.common_tags
}

#==============================================================================
# ECR Repositories
#==============================================================================

module "ecr" {
  source = "./modules/ecr"

  name_prefix = local.name_prefix

  repositories = ["api", "web-ui", "scanner"]

  tags = local.common_tags
}

#==============================================================================
# IAM Roles and Policies
#==============================================================================

module "iam" {
  source = "./modules/iam"

  name_prefix = local.name_prefix
  environment = var.environment

  s3_bucket_arns = [
    module.s3.reports_bucket_arn,
    module.s3.logs_bucket_arn
  ]

  tags = local.common_tags
}

#==============================================================================
# ECS Cluster
#==============================================================================

module "ecs_cluster" {
  source = "./modules/ecs-cluster"

  name_prefix = local.name_prefix
  environment = var.environment

  tags = local.common_tags
}

#==============================================================================
# ECS Services
#==============================================================================

# API Service
module "ecs_api_service" {
  source = "./modules/ecs-service"

  name_prefix     = local.name_prefix
  service_name    = "api"
  cluster_id      = module.ecs_cluster.cluster_id
  cluster_name    = module.ecs_cluster.cluster_name

  # Container configuration
  container_image = "${module.ecr.repository_urls["api"]}:latest"
  container_port  = 8000
  task_cpu        = var.api_task_cpu
  task_memory     = var.api_task_memory

  # Networking
  vpc_id          = module.vpc.vpc_id
  private_subnets = module.vpc.private_subnets
  security_groups = [module.security_groups.ecs_sg_id]

  # Load balancer
  alb_target_group_arn = module.alb.api_target_group_arn

  # Scaling
  desired_count = var.api_desired_count
  min_count     = var.api_min_count
  max_count     = var.api_max_count

  # IAM
  execution_role_arn = module.iam.ecs_execution_role_arn
  task_role_arn      = module.iam.ecs_task_role_arn

  # Environment variables
  environment = {
    ENVIRONMENT     = var.environment
    POSTGRES_HOST   = module.rds.endpoint
    POSTGRES_DB     = var.db_name
    REDIS_HOST      = module.elasticache.endpoint
    S3_BUCKET       = module.s3.reports_bucket_name
  }

  # Secrets from Secrets Manager
  secrets = {
    POSTGRES_PASSWORD = "${local.name_prefix}/db/password"
    GITHUB_TOKEN      = "${local.name_prefix}/github/token"
    SECRETS_MASTER_KEY = "${local.name_prefix}/secrets/master-key"
  }

  tags = local.common_tags
}

# Web UI Service
module "ecs_webui_service" {
  source = "./modules/ecs-service"

  name_prefix     = local.name_prefix
  service_name    = "web-ui"
  cluster_id      = module.ecs_cluster.cluster_id
  cluster_name    = module.ecs_cluster.cluster_name

  # Container configuration
  container_image = "${module.ecr.repository_urls["web-ui"]}:latest"
  container_port  = 3000
  task_cpu        = var.webui_task_cpu
  task_memory     = var.webui_task_memory

  # Networking
  vpc_id          = module.vpc.vpc_id
  private_subnets = module.vpc.private_subnets
  security_groups = [module.security_groups.ecs_sg_id]

  # Load balancer
  alb_target_group_arn = module.alb.webui_target_group_arn

  # Scaling
  desired_count = var.webui_desired_count
  min_count     = var.webui_min_count
  max_count     = var.webui_max_count

  # IAM
  execution_role_arn = module.iam.ecs_execution_role_arn
  task_role_arn      = module.iam.ecs_task_role_arn

  # Environment variables
  environment = {
    ENVIRONMENT   = var.environment
    API_BASE_URL  = "http://${module.alb.dns_name}"
    NEXT_PUBLIC_API_URL = "https://${var.domain_name}/api"
  }

  tags = local.common_tags
}

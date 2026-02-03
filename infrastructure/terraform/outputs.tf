# AuditGitHub Terraform Outputs

#==============================================================================
# VPC Outputs
#==============================================================================

output "vpc_id" {
  description = "ID of the VPC"
  value       = module.vpc.vpc_id
}

output "public_subnet_ids" {
  description = "IDs of public subnets"
  value       = module.vpc.public_subnets
}

output "private_subnet_ids" {
  description = "IDs of private subnets"
  value       = module.vpc.private_subnets
}

#==============================================================================
# Load Balancer Outputs
#==============================================================================

output "alb_dns_name" {
  description = "DNS name of the Application Load Balancer"
  value       = module.alb.dns_name
}

output "alb_arn" {
  description = "ARN of the Application Load Balancer"
  value       = module.alb.alb_arn
}

output "alb_zone_id" {
  description = "Zone ID of the Application Load Balancer"
  value       = module.alb.zone_id
}

#==============================================================================
# Database Outputs
#==============================================================================

output "rds_endpoint" {
  description = "RDS PostgreSQL endpoint"
  value       = module.rds.endpoint
  sensitive   = true
}

output "rds_port" {
  description = "RDS PostgreSQL port"
  value       = module.rds.port
}

output "rds_database_name" {
  description = "Name of the RDS database"
  value       = var.db_name
}

#==============================================================================
# Cache Outputs
#==============================================================================

output "redis_endpoint" {
  description = "ElastiCache Redis endpoint"
  value       = module.elasticache.endpoint
}

output "redis_port" {
  description = "ElastiCache Redis port"
  value       = module.elasticache.port
}

#==============================================================================
# ECR Outputs
#==============================================================================

output "api_ecr_repository_url" {
  description = "URL of the API ECR repository"
  value       = module.ecr.repository_urls["api"]
}

output "webui_ecr_repository_url" {
  description = "URL of the Web UI ECR repository"
  value       = module.ecr.repository_urls["web-ui"]
}

output "scanner_ecr_repository_url" {
  description = "URL of the Scanner ECR repository"
  value       = module.ecr.repository_urls["scanner"]
}

#==============================================================================
# S3 Outputs
#==============================================================================

output "reports_bucket_name" {
  description = "Name of the reports S3 bucket"
  value       = module.s3.reports_bucket_name
}

output "logs_bucket_name" {
  description = "Name of the logs S3 bucket"
  value       = module.s3.logs_bucket_name
}

#==============================================================================
# ECS Outputs
#==============================================================================

output "ecs_cluster_name" {
  description = "Name of the ECS cluster"
  value       = module.ecs_cluster.cluster_name
}

output "ecs_cluster_arn" {
  description = "ARN of the ECS cluster"
  value       = module.ecs_cluster.cluster_arn
}

output "api_service_name" {
  description = "Name of the API ECS service"
  value       = module.ecs_api_service.service_name
}

output "webui_service_name" {
  description = "Name of the Web UI ECS service"
  value       = module.ecs_webui_service.service_name
}

#==============================================================================
# IAM Outputs
#==============================================================================

output "ecs_execution_role_arn" {
  description = "ARN of the ECS execution role"
  value       = module.iam.ecs_execution_role_arn
}

output "ecs_task_role_arn" {
  description = "ARN of the ECS task role"
  value       = module.iam.ecs_task_role_arn
}

#==============================================================================
# Security Group Outputs
#==============================================================================

output "alb_security_group_id" {
  description = "ID of the ALB security group"
  value       = module.security_groups.alb_sg_id
}

output "ecs_security_group_id" {
  description = "ID of the ECS security group"
  value       = module.security_groups.ecs_sg_id
}

output "rds_security_group_id" {
  description = "ID of the RDS security group"
  value       = module.security_groups.rds_sg_id
}

output "redis_security_group_id" {
  description = "ID of the Redis security group"
  value       = module.security_groups.redis_sg_id
}

#==============================================================================
# Deployment Information
#==============================================================================

output "deployment_info" {
  description = "Key information for deployment"
  value = {
    environment   = var.environment
    region        = var.aws_region
    alb_dns       = module.alb.dns_name
    cluster_name  = module.ecs_cluster.cluster_name
  }
}

#==============================================================================
# Connection Strings (for debugging - mark as sensitive)
#==============================================================================

output "connection_info" {
  description = "Connection information for services (sensitive)"
  value = {
    database_url = "postgresql://${var.db_master_username}:****@${module.rds.endpoint}/${var.db_name}"
    redis_url    = "redis://${module.elasticache.endpoint}:${module.elasticache.port}"
    api_url      = "https://${module.alb.dns_name}/api"
    web_url      = "https://${module.alb.dns_name}"
  }
  sensitive = true
}

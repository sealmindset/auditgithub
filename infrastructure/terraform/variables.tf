# AuditGitHub Terraform Variables

variable "project_name" {
  description = "Project name used for resource naming"
  type        = string
  default     = "auditgithub"
}

variable "environment" {
  description = "Environment name (dev, staging, prod)"
  type        = string
}

variable "aws_region" {
  description = "AWS region for resources"
  type        = string
  default     = "us-east-1"
}

variable "owner_email" {
  description = "Email of the infrastructure owner"
  type        = string
}

#==============================================================================
# Network Configuration
#==============================================================================

variable "vpc_cidr" {
  description = "CIDR block for VPC"
  type        = string
  default     = "10.0.0.0/16"
}

variable "availability_zones" {
  description = "List of availability zones"
  type        = list(string)
  default     = ["us-east-1a", "us-east-1b", "us-east-1c"]
}

#==============================================================================
# Domain and SSL
#==============================================================================

variable "domain_name" {
  description = "Domain name for the application"
  type        = string
}

variable "certificate_arn" {
  description = "ARN of ACM certificate for SSL"
  type        = string
}

#==============================================================================
# Database Configuration
#==============================================================================

variable "db_instance_class" {
  description = "RDS instance class"
  type        = string
  default     = "db.t3.medium"
}

variable "db_allocated_storage" {
  description = "RDS allocated storage in GB"
  type        = number
  default     = 100
}

variable "db_name" {
  description = "Database name"
  type        = string
  default     = "auditgithub"
}

variable "db_master_username" {
  description = "Database master username"
  type        = string
  default     = "auditgh_admin"
}

#==============================================================================
# Cache Configuration
#==============================================================================

variable "cache_node_type" {
  description = "ElastiCache node type"
  type        = string
  default     = "cache.t3.micro"
}

variable "cache_num_nodes" {
  description = "Number of cache nodes"
  type        = number
  default     = 1
}

#==============================================================================
# ECS API Service Configuration
#==============================================================================

variable "api_task_cpu" {
  description = "CPU units for API task (1024 = 1 vCPU)"
  type        = number
  default     = 1024
}

variable "api_task_memory" {
  description = "Memory for API task in MB"
  type        = number
  default     = 2048
}

variable "api_desired_count" {
  description = "Desired number of API tasks"
  type        = number
  default     = 2
}

variable "api_min_count" {
  description = "Minimum number of API tasks"
  type        = number
  default     = 1
}

variable "api_max_count" {
  description = "Maximum number of API tasks"
  type        = number
  default     = 4
}

#==============================================================================
# ECS Web UI Service Configuration
#==============================================================================

variable "webui_task_cpu" {
  description = "CPU units for Web UI task"
  type        = number
  default     = 512
}

variable "webui_task_memory" {
  description = "Memory for Web UI task in MB"
  type        = number
  default     = 1024
}

variable "webui_desired_count" {
  description = "Desired number of Web UI tasks"
  type        = number
  default     = 2
}

variable "webui_min_count" {
  description = "Minimum number of Web UI tasks"
  type        = number
  default     = 1
}

variable "webui_max_count" {
  description = "Maximum number of Web UI tasks"
  type        = number
  default     = 4
}

#==============================================================================
# Tags
#==============================================================================

variable "tags" {
  description = "Additional tags for resources"
  type        = map(string)
  default     = {}
}

# ECS Service Module Variables

variable "cluster_id" {
  description = "ID of the ECS cluster"
  type        = string
}

variable "cluster_name" {
  description = "Name of the ECS cluster"
  type        = string
}

variable "service_name" {
  description = "Name of the service (e.g., api, web-ui)"
  type        = string
}

variable "container_name" {
  description = "Name of the container"
  type        = string
}

variable "container_image" {
  description = "Docker image for the container"
  type        = string
}

variable "container_port" {
  description = "Port exposed by the container (null if no port)"
  type        = number
  default     = null
}

variable "task_cpu" {
  description = "CPU units for the task (256, 512, 1024, 2048, 4096)"
  type        = number
}

variable "task_memory" {
  description = "Memory for the task in MB (512, 1024, 2048, 4096, 8192, etc.)"
  type        = number
}

variable "execution_role_arn" {
  description = "ARN of the ECS execution role"
  type        = string
}

variable "task_role_arn" {
  description = "ARN of the ECS task role"
  type        = string
}

variable "subnet_ids" {
  description = "List of subnet IDs for the service"
  type        = list(string)
}

variable "security_group_ids" {
  description = "List of security group IDs for the service"
  type        = list(string)
}

variable "assign_public_ip" {
  description = "Assign public IP to tasks"
  type        = bool
  default     = false
}

variable "desired_count" {
  description = "Desired number of tasks"
  type        = number
  default     = 2
}

variable "min_count" {
  description = "Minimum number of tasks for autoscaling"
  type        = number
  default     = 2
}

variable "max_count" {
  description = "Maximum number of tasks for autoscaling"
  type        = number
  default     = 10
}

variable "target_group_arn" {
  description = "ARN of the target group (null if not using ALB)"
  type        = string
  default     = null
}

variable "health_check_grace_period" {
  description = "Health check grace period in seconds"
  type        = number
  default     = 60
}

variable "enable_execute_command" {
  description = "Enable ECS Exec for debugging"
  type        = bool
  default     = false
}

variable "environment_variables" {
  description = "List of environment variables"
  type = list(object({
    name  = string
    value = string
  }))
  default = []
}

variable "secrets" {
  description = "List of secrets from Secrets Manager or SSM Parameter Store"
  type = list(object({
    name      = string
    valueFrom = string
  }))
  default = []
}

variable "health_check" {
  description = "Container health check configuration"
  type = object({
    command     = list(string)
    interval    = number
    timeout     = number
    retries     = number
    startPeriod = number
  })
  default = null
}

variable "enable_autoscaling" {
  description = "Enable auto-scaling for the service"
  type        = bool
  default     = true
}

variable "cpu_target_value" {
  description = "Target CPU utilization percentage for autoscaling"
  type        = number
  default     = 70
}

variable "memory_target_value" {
  description = "Target memory utilization percentage for autoscaling"
  type        = number
  default     = 80
}

variable "scale_in_cooldown" {
  description = "Cooldown period in seconds before allowing scale in"
  type        = number
  default     = 300
}

variable "scale_out_cooldown" {
  description = "Cooldown period in seconds before allowing scale out"
  type        = number
  default     = 60
}

variable "enable_cloudwatch_alarms" {
  description = "Enable CloudWatch alarms for the service"
  type        = bool
  default     = true
}

variable "alarm_sns_topic_arn" {
  description = "SNS topic ARN for CloudWatch alarms"
  type        = string
  default     = null
}

variable "aws_region" {
  description = "AWS region"
  type        = string
}

variable "log_retention_days" {
  description = "CloudWatch Logs retention in days"
  type        = number
  default     = 30
}

variable "tags" {
  description = "Tags to apply to resources"
  type        = map(string)
  default     = {}
}

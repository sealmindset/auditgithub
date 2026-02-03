# ElastiCache Module Variables

variable "name_prefix" {
  description = "Prefix for resource names"
  type        = string
}

variable "subnet_ids" {
  description = "List of subnet IDs for the ElastiCache subnet group"
  type        = list(string)
}

variable "security_group_ids" {
  description = "List of security group IDs for the ElastiCache cluster"
  type        = list(string)
}

variable "node_type" {
  description = "ElastiCache node type"
  type        = string
  default     = "cache.t3.micro"
}

variable "num_cache_nodes" {
  description = "Number of cache nodes (1 for single node, 2+ for cluster with failover)"
  type        = number
  default     = 2
}

variable "engine_version" {
  description = "Redis engine version"
  type        = string
  default     = "7.0"
}

variable "parameter_group_family" {
  description = "Redis parameter group family"
  type        = string
  default     = "redis7"
}

variable "transit_encryption_enabled" {
  description = "Enable encryption in transit (requires AUTH token)"
  type        = bool
  default     = true
}

variable "auth_token" {
  description = "Auth token for Redis (if null and transit encryption enabled, random token is generated)"
  type        = string
  default     = null
  sensitive   = true
}

variable "snapshot_retention_limit" {
  description = "Number of days to retain automated snapshots"
  type        = number
  default     = 5
}

variable "snapshot_window" {
  description = "Daily time range for automated snapshots"
  type        = string
  default     = "03:00-05:00"
}

variable "maintenance_window" {
  description = "Weekly time range for maintenance"
  type        = string
  default     = "sun:05:00-sun:07:00"
}

variable "auto_minor_version_upgrade" {
  description = "Enable automatic minor version upgrades"
  type        = bool
  default     = true
}

variable "log_retention_days" {
  description = "CloudWatch Logs retention in days"
  type        = number
  default     = 7
}

variable "kms_key_arn" {
  description = "ARN of KMS key for encryption"
  type        = string
  default     = null
}

variable "notification_topic_arn" {
  description = "SNS topic ARN for ElastiCache notifications"
  type        = string
  default     = null
}

variable "alarm_sns_topic_arn" {
  description = "SNS topic ARN for CloudWatch alarms"
  type        = string
  default     = null
}

variable "tags" {
  description = "Tags to apply to resources"
  type        = map(string)
  default     = {}
}

# S3 Module Variables

variable "name_prefix" {
  description = "Prefix for resource names"
  type        = string
}

variable "aws_account_id" {
  description = "AWS account ID"
  type        = string
}

variable "elb_account_id" {
  description = "ELB service account ID for the region"
  type        = string
  # us-east-1: 127311923021
  # us-east-2: 033677994240
  # us-west-1: 027434742980
  # us-west-2: 797873946194
}

variable "enable_versioning" {
  description = "Enable versioning for reports bucket"
  type        = bool
  default     = true
}

variable "kms_key_arn" {
  description = "ARN of KMS key for bucket encryption"
  type        = string
  default     = null
}

variable "reports_transition_days" {
  description = "Days until reports transition to IA storage"
  type        = number
  default     = 90
}

variable "reports_glacier_days" {
  description = "Days until reports transition to Glacier"
  type        = number
  default     = 180
}

variable "reports_expiration_days" {
  description = "Days until reports expire"
  type        = number
  default     = 365
}

variable "logs_transition_days" {
  description = "Days until logs transition to IA storage"
  type        = number
  default     = 30
}

variable "logs_expiration_days" {
  description = "Days until logs expire"
  type        = number
  default     = 90
}

variable "create_backups_bucket" {
  description = "Create a backups bucket"
  type        = bool
  default     = true
}

variable "tags" {
  description = "Tags to apply to resources"
  type        = map(string)
  default     = {}
}

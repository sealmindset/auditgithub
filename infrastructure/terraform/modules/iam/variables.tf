# IAM Module Variables

variable "name_prefix" {
  description = "Prefix for resource names"
  type        = string
}

variable "aws_region" {
  description = "AWS region"
  type        = string
}

variable "aws_account_id" {
  description = "AWS account ID"
  type        = string
}

variable "secrets_prefix" {
  description = "Prefix for Secrets Manager secrets"
  type        = string
  default     = "auditgithub"
}

variable "reports_bucket_name" {
  description = "Name of the S3 bucket for reports"
  type        = string
}

variable "logs_bucket_name" {
  description = "Name of the S3 bucket for logs"
  type        = string
}

variable "create_github_actions_role" {
  description = "Create IAM role for GitHub Actions OIDC"
  type        = bool
  default     = false
}

variable "github_repo" {
  description = "GitHub repository in format owner/repo"
  type        = string
  default     = ""
}

variable "tags" {
  description = "Tags to apply to resources"
  type        = map(string)
  default     = {}
}

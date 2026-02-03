# ECR Module Variables

variable "name_prefix" {
  description = "Prefix for resource names"
  type        = string
}

variable "repository_names" {
  description = "List of ECR repository names to create"
  type        = list(string)
  default     = ["api", "web-ui", "scanner"]
}

variable "scan_on_push" {
  description = "Enable image scanning on push"
  type        = bool
  default     = true
}

variable "image_tag_mutability" {
  description = "Image tag mutability (MUTABLE or IMMUTABLE)"
  type        = string
  default     = "MUTABLE"
}

variable "encryption_type" {
  description = "Encryption type (AES256 or KMS)"
  type        = string
  default     = "AES256"
}

variable "kms_key_arn" {
  description = "ARN of KMS key for encryption (required if encryption_type is KMS)"
  type        = string
  default     = null
}

variable "max_image_count" {
  description = "Maximum number of images to retain"
  type        = number
  default     = 30
}

variable "enable_cross_account_access" {
  description = "Enable cross-account access to ECR repositories"
  type        = bool
  default     = false
}

variable "allowed_account_ids" {
  description = "List of AWS account IDs allowed to access ECR repositories"
  type        = list(string)
  default     = []
}

variable "tags" {
  description = "Tags to apply to resources"
  type        = map(string)
  default     = {}
}

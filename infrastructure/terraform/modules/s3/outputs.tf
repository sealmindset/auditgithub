# S3 Module Outputs

output "reports_bucket_name" {
  description = "Name of the reports S3 bucket"
  value       = aws_s3_bucket.reports.id
}

output "reports_bucket_arn" {
  description = "ARN of the reports S3 bucket"
  value       = aws_s3_bucket.reports.arn
}

output "logs_bucket_name" {
  description = "Name of the logs S3 bucket"
  value       = aws_s3_bucket.logs.id
}

output "logs_bucket_arn" {
  description = "ARN of the logs S3 bucket"
  value       = aws_s3_bucket.logs.arn
}

output "backups_bucket_name" {
  description = "Name of the backups S3 bucket"
  value       = var.create_backups_bucket ? aws_s3_bucket.backups[0].id : ""
}

output "backups_bucket_arn" {
  description = "ARN of the backups S3 bucket"
  value       = var.create_backups_bucket ? aws_s3_bucket.backups[0].arn : ""
}

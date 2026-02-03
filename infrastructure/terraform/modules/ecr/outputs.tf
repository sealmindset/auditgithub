# ECR Module Outputs

output "repository_urls" {
  description = "Map of repository names to URLs"
  value = {
    for name, repo in aws_ecr_repository.main : name => repo.repository_url
  }
}

output "repository_arns" {
  description = "Map of repository names to ARNs"
  value = {
    for name, repo in aws_ecr_repository.main : name => repo.arn
  }
}

output "repository_registry_ids" {
  description = "Map of repository names to registry IDs"
  value = {
    for name, repo in aws_ecr_repository.main : name => repo.registry_id
  }
}

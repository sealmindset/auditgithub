# IAM Module Outputs

output "ecs_execution_role_arn" {
  description = "ARN of the ECS execution role"
  value       = aws_iam_role.ecs_execution.arn
}

output "ecs_execution_role_name" {
  description = "Name of the ECS execution role"
  value       = aws_iam_role.ecs_execution.name
}

output "ecs_task_role_arn" {
  description = "ARN of the ECS task role"
  value       = aws_iam_role.ecs_task.arn
}

output "ecs_task_role_name" {
  description = "Name of the ECS task role"
  value       = aws_iam_role.ecs_task.name
}

output "github_actions_role_arn" {
  description = "ARN of the GitHub Actions role"
  value       = var.create_github_actions_role ? aws_iam_role.github_actions[0].arn : ""
}

output "github_actions_role_name" {
  description = "Name of the GitHub Actions role"
  value       = var.create_github_actions_role ? aws_iam_role.github_actions[0].name : ""
}

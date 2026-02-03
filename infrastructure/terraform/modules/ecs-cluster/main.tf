# ECS Cluster Module for AuditGitHub
# Creates ECS cluster with Fargate capacity providers

resource "aws_ecs_cluster" "main" {
  name = "${var.name_prefix}-cluster"

  setting {
    name  = "containerInsights"
    value = var.enable_container_insights ? "enabled" : "disabled"
  }

  tags = merge(
    var.tags,
    {
      Name = "${var.name_prefix}-cluster"
    }
  )
}

# Fargate Capacity Provider
resource "aws_ecs_cluster_capacity_providers" "main" {
  cluster_name = aws_ecs_cluster.main.name

  capacity_providers = ["FARGATE", "FARGATE_SPOT"]

  default_capacity_provider_strategy {
    capacity_provider = "FARGATE"
    weight            = var.fargate_weight
    base              = var.fargate_base
  }

  default_capacity_provider_strategy {
    capacity_provider = "FARGATE_SPOT"
    weight            = var.fargate_spot_weight
  }
}

# CloudWatch Log Group for ECS
resource "aws_cloudwatch_log_group" "ecs" {
  name              = "/ecs/${var.name_prefix}"
  retention_in_days = var.log_retention_days

  tags = var.tags
}

# CloudWatch Alarms for ECS Cluster
resource "aws_cloudwatch_metric_alarm" "cluster_cpu" {
  count               = var.enable_cloudwatch_alarms ? 1 : 0
  alarm_name          = "${var.name_prefix}-cluster-cpu-utilization"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "CPUUtilization"
  namespace           = "AWS/ECS"
  period              = "300"
  statistic           = "Average"
  threshold           = "80"
  alarm_description   = "ECS Cluster CPU utilization is too high"
  alarm_actions       = var.alarm_sns_topic_arn != null ? [var.alarm_sns_topic_arn] : []

  dimensions = {
    ClusterName = aws_ecs_cluster.main.name
  }

  tags = var.tags
}

resource "aws_cloudwatch_metric_alarm" "cluster_memory" {
  count               = var.enable_cloudwatch_alarms ? 1 : 0
  alarm_name          = "${var.name_prefix}-cluster-memory-utilization"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "MemoryUtilization"
  namespace           = "AWS/ECS"
  period              = "300"
  statistic           = "Average"
  threshold           = "80"
  alarm_description   = "ECS Cluster memory utilization is too high"
  alarm_actions       = var.alarm_sns_topic_arn != null ? [var.alarm_sns_topic_arn] : []

  dimensions = {
    ClusterName = aws_ecs_cluster.main.name
  }

  tags = var.tags
}

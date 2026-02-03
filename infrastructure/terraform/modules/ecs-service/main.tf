# ECS Service Module for AuditGitHub
# Reusable module for creating ECS Fargate services

# CloudWatch Log Group for the service
resource "aws_cloudwatch_log_group" "service" {
  name              = "/ecs/${var.cluster_name}/${var.service_name}"
  retention_in_days = var.log_retention_days

  tags = var.tags
}

# ECS Task Definition
resource "aws_ecs_task_definition" "main" {
  family                   = "${var.cluster_name}-${var.service_name}"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = var.task_cpu
  memory                   = var.task_memory
  execution_role_arn       = var.execution_role_arn
  task_role_arn            = var.task_role_arn

  container_definitions = jsonencode([
    {
      name      = var.container_name
      image     = var.container_image
      essential = true

      portMappings = var.container_port != null ? [
        {
          containerPort = var.container_port
          hostPort      = var.container_port
          protocol      = "tcp"
        }
      ] : []

      environment = var.environment_variables

      secrets = var.secrets

      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group"         = aws_cloudwatch_log_group.service.name
          "awslogs-region"        = var.aws_region
          "awslogs-stream-prefix" = "ecs"
        }
      }

      healthCheck = var.health_check != null ? var.health_check : null

      ulimits = [
        {
          name      = "nofile"
          softLimit = 65536
          hardLimit = 65536
        }
      ]
    }
  ])

  tags = merge(
    var.tags,
    {
      Name = "${var.cluster_name}-${var.service_name}"
    }
  )
}

# ECS Service
resource "aws_ecs_service" "main" {
  name            = "${var.cluster_name}-${var.service_name}-service"
  cluster         = var.cluster_id
  task_definition = aws_ecs_task_definition.main.arn
  desired_count   = var.desired_count
  launch_type     = "FARGATE"

  platform_version = "LATEST"

  network_configuration {
    subnets          = var.subnet_ids
    security_groups  = var.security_group_ids
    assign_public_ip = var.assign_public_ip
  }

  dynamic "load_balancer" {
    for_each = var.target_group_arn != null ? [1] : []
    content {
      target_group_arn = var.target_group_arn
      container_name   = var.container_name
      container_port   = var.container_port
    }
  }

  health_check_grace_period_seconds = var.target_group_arn != null ? var.health_check_grace_period : null

  deployment_configuration {
    maximum_percent         = 200
    minimum_healthy_percent = 100
    deployment_circuit_breaker {
      enable   = true
      rollback = true
    }
  }

  enable_execute_command = var.enable_execute_command

  propagate_tags = "SERVICE"

  tags = merge(
    var.tags,
    {
      Name = "${var.cluster_name}-${var.service_name}-service"
    }
  )

  depends_on = [
    aws_ecs_task_definition.main
  ]

  lifecycle {
    ignore_changes = [
      desired_count,
      task_definition
    ]
  }
}

# Auto Scaling Target
resource "aws_appautoscaling_target" "ecs" {
  count              = var.enable_autoscaling ? 1 : 0
  max_capacity       = var.max_count
  min_capacity       = var.min_count
  resource_id        = "service/${var.cluster_name}/${aws_ecs_service.main.name}"
  scalable_dimension = "ecs:service:DesiredCount"
  service_namespace  = "ecs"

  depends_on = [aws_ecs_service.main]
}

# Auto Scaling Policy - CPU
resource "aws_appautoscaling_policy" "ecs_cpu" {
  count              = var.enable_autoscaling ? 1 : 0
  name               = "${var.cluster_name}-${var.service_name}-cpu-autoscaling"
  policy_type        = "TargetTrackingScaling"
  resource_id        = aws_appautoscaling_target.ecs[0].resource_id
  scalable_dimension = aws_appautoscaling_target.ecs[0].scalable_dimension
  service_namespace  = aws_appautoscaling_target.ecs[0].service_namespace

  target_tracking_scaling_policy_configuration {
    predefined_metric_specification {
      predefined_metric_type = "ECSServiceAverageCPUUtilization"
    }
    target_value       = var.cpu_target_value
    scale_in_cooldown  = var.scale_in_cooldown
    scale_out_cooldown = var.scale_out_cooldown
  }
}

# Auto Scaling Policy - Memory
resource "aws_appautoscaling_policy" "ecs_memory" {
  count              = var.enable_autoscaling ? 1 : 0
  name               = "${var.cluster_name}-${var.service_name}-memory-autoscaling"
  policy_type        = "TargetTrackingScaling"
  resource_id        = aws_appautoscaling_target.ecs[0].resource_id
  scalable_dimension = aws_appautoscaling_target.ecs[0].scalable_dimension
  service_namespace  = aws_appautoscaling_target.ecs[0].service_namespace

  target_tracking_scaling_policy_configuration {
    predefined_metric_specification {
      predefined_metric_type = "ECSServiceAverageMemoryUtilization"
    }
    target_value       = var.memory_target_value
    scale_in_cooldown  = var.scale_in_cooldown
    scale_out_cooldown = var.scale_out_cooldown
  }
}

# CloudWatch Alarms
resource "aws_cloudwatch_metric_alarm" "service_cpu" {
  count               = var.enable_cloudwatch_alarms ? 1 : 0
  alarm_name          = "${var.cluster_name}-${var.service_name}-cpu-utilization"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "CPUUtilization"
  namespace           = "AWS/ECS"
  period              = "300"
  statistic           = "Average"
  threshold           = "90"
  alarm_description   = "Service CPU utilization is critically high"
  alarm_actions       = var.alarm_sns_topic_arn != null ? [var.alarm_sns_topic_arn] : []

  dimensions = {
    ClusterName = var.cluster_name
    ServiceName = aws_ecs_service.main.name
  }

  tags = var.tags
}

resource "aws_cloudwatch_metric_alarm" "service_memory" {
  count               = var.enable_cloudwatch_alarms ? 1 : 0
  alarm_name          = "${var.cluster_name}-${var.service_name}-memory-utilization"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "MemoryUtilization"
  namespace           = "AWS/ECS"
  period              = "300"
  statistic           = "Average"
  threshold           = "90"
  alarm_description   = "Service memory utilization is critically high"
  alarm_actions       = var.alarm_sns_topic_arn != null ? [var.alarm_sns_topic_arn] : []

  dimensions = {
    ClusterName = var.cluster_name
    ServiceName = aws_ecs_service.main.name
  }

  tags = var.tags
}

resource "aws_cloudwatch_metric_alarm" "service_tasks" {
  count               = var.enable_cloudwatch_alarms ? 1 : 0
  alarm_name          = "${var.cluster_name}-${var.service_name}-running-tasks"
  comparison_operator = "LessThanThreshold"
  evaluation_periods  = "1"
  metric_name         = "RunningTaskCount"
  namespace           = "ECS/ContainerInsights"
  period              = "60"
  statistic           = "Average"
  threshold           = var.min_count
  alarm_description   = "Service has too few running tasks"
  alarm_actions       = var.alarm_sns_topic_arn != null ? [var.alarm_sns_topic_arn] : []

  dimensions = {
    ClusterName = var.cluster_name
    ServiceName = aws_ecs_service.main.name
  }

  tags = var.tags
}

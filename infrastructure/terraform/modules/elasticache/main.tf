# ElastiCache Module for AuditGitHub
# Creates ElastiCache Redis cluster

# ElastiCache Subnet Group
resource "aws_elasticache_subnet_group" "main" {
  name       = "${var.name_prefix}-redis-subnet-group"
  subnet_ids = var.subnet_ids

  tags = merge(
    var.tags,
    {
      Name = "${var.name_prefix}-redis-subnet-group"
    }
  )
}

# ElastiCache Parameter Group
resource "aws_elasticache_parameter_group" "main" {
  name_prefix = "${var.name_prefix}-redis-"
  family      = var.parameter_group_family

  parameter {
    name  = "maxmemory-policy"
    value = "allkeys-lru"
  }

  parameter {
    name  = "timeout"
    value = "300"
  }

  tags = var.tags

  lifecycle {
    create_before_destroy = true
  }
}

# ElastiCache Replication Group (Redis Cluster)
resource "aws_elasticache_replication_group" "main" {
  replication_group_id       = "${var.name_prefix}-redis"
  replication_group_description = "Redis cluster for AuditGitHub"

  engine               = "redis"
  engine_version       = var.engine_version
  node_type            = var.node_type
  num_cache_clusters   = var.num_cache_nodes
  port                 = 6379

  parameter_group_name = aws_elasticache_parameter_group.main.name
  subnet_group_name    = aws_elasticache_subnet_group.main.name
  security_group_ids   = var.security_group_ids

  automatic_failover_enabled = var.num_cache_nodes > 1 ? true : false
  multi_az_enabled           = var.num_cache_nodes > 1 ? true : false

  at_rest_encryption_enabled = true
  transit_encryption_enabled = var.transit_encryption_enabled
  auth_token_enabled         = var.transit_encryption_enabled
  auth_token                 = var.transit_encryption_enabled ? var.auth_token : null
  kms_key_id                 = var.kms_key_arn

  snapshot_retention_limit   = var.snapshot_retention_limit
  snapshot_window            = var.snapshot_window
  maintenance_window         = var.maintenance_window

  auto_minor_version_upgrade = var.auto_minor_version_upgrade
  notification_topic_arn     = var.notification_topic_arn

  log_delivery_configuration {
    destination      = aws_cloudwatch_log_group.slow_log.name
    destination_type = "cloudwatch-logs"
    log_format       = "json"
    log_type         = "slow-log"
  }

  log_delivery_configuration {
    destination      = aws_cloudwatch_log_group.engine_log.name
    destination_type = "cloudwatch-logs"
    log_format       = "json"
    log_type         = "engine-log"
  }

  tags = merge(
    var.tags,
    {
      Name = "${var.name_prefix}-redis"
    }
  )

  lifecycle {
    ignore_changes = [
      auth_token
    ]
  }
}

# CloudWatch Log Groups
resource "aws_cloudwatch_log_group" "slow_log" {
  name              = "/aws/elasticache/${var.name_prefix}-redis/slow-log"
  retention_in_days = var.log_retention_days

  tags = var.tags
}

resource "aws_cloudwatch_log_group" "engine_log" {
  name              = "/aws/elasticache/${var.name_prefix}-redis/engine-log"
  retention_in_days = var.log_retention_days

  tags = var.tags
}

# Random auth token
resource "random_password" "auth_token" {
  count   = var.transit_encryption_enabled && var.auth_token == null ? 1 : 0
  length  = 32
  special = false
}

# Store auth token in Secrets Manager
resource "aws_secretsmanager_secret" "redis_auth_token" {
  count       = var.transit_encryption_enabled && var.auth_token == null ? 1 : 0
  name        = "${var.name_prefix}/redis/auth-token"
  description = "Auth token for Redis cluster"

  tags = var.tags
}

resource "aws_secretsmanager_secret_version" "redis_auth_token" {
  count         = var.transit_encryption_enabled && var.auth_token == null ? 1 : 0
  secret_id     = aws_secretsmanager_secret.redis_auth_token[0].id
  secret_string = random_password.auth_token[0].result
}

# CloudWatch Alarms
resource "aws_cloudwatch_metric_alarm" "redis_cpu" {
  alarm_name          = "${var.name_prefix}-redis-cpu-utilization"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "CPUUtilization"
  namespace           = "AWS/ElastiCache"
  period              = "300"
  statistic           = "Average"
  threshold           = "75"
  alarm_description   = "Redis CPU utilization is too high"
  alarm_actions       = var.alarm_sns_topic_arn != null ? [var.alarm_sns_topic_arn] : []

  dimensions = {
    CacheClusterId = "${var.name_prefix}-redis-001"
  }

  tags = var.tags
}

resource "aws_cloudwatch_metric_alarm" "redis_memory" {
  alarm_name          = "${var.name_prefix}-redis-memory"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "DatabaseMemoryUsagePercentage"
  namespace           = "AWS/ElastiCache"
  period              = "300"
  statistic           = "Average"
  threshold           = "80"
  alarm_description   = "Redis memory usage is too high"
  alarm_actions       = var.alarm_sns_topic_arn != null ? [var.alarm_sns_topic_arn] : []

  dimensions = {
    CacheClusterId = "${var.name_prefix}-redis-001"
  }

  tags = var.tags
}

resource "aws_cloudwatch_metric_alarm" "redis_evictions" {
  alarm_name          = "${var.name_prefix}-redis-evictions"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "Evictions"
  namespace           = "AWS/ElastiCache"
  period              = "300"
  statistic           = "Average"
  threshold           = "1000"
  alarm_description   = "Redis evictions are too high"
  alarm_actions       = var.alarm_sns_topic_arn != null ? [var.alarm_sns_topic_arn] : []

  dimensions = {
    CacheClusterId = "${var.name_prefix}-redis-001"
  }

  tags = var.tags
}

# ALB Module for AuditGitHub
# Creates Application Load Balancer with target groups

# Application Load Balancer
resource "aws_lb" "main" {
  name               = "${var.name_prefix}-alb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = var.security_group_ids
  subnets            = var.subnet_ids

  enable_deletion_protection = var.enable_deletion_protection
  enable_http2              = true
  enable_cross_zone_load_balancing = true

  access_logs {
    bucket  = var.access_logs_bucket
    prefix  = "alb"
    enabled = var.access_logs_bucket != null
  }

  tags = merge(
    var.tags,
    {
      Name = "${var.name_prefix}-alb"
    }
  )
}

# Target Group for API Service
resource "aws_lb_target_group" "api" {
  name_prefix = "api-"
  port        = 8000
  protocol    = "HTTP"
  vpc_id      = var.vpc_id
  target_type = "ip"

  health_check {
    enabled             = true
    healthy_threshold   = 2
    unhealthy_threshold = 3
    timeout             = 5
    interval            = 30
    path                = "/health"
    protocol            = "HTTP"
    matcher             = "200"
  }

  deregistration_delay = 30

  tags = merge(
    var.tags,
    {
      Name = "${var.name_prefix}-api-tg"
    }
  )

  lifecycle {
    create_before_destroy = true
  }
}

# Target Group for Web UI Service
resource "aws_lb_target_group" "webui" {
  name_prefix = "webui-"
  port        = 3000
  protocol    = "HTTP"
  vpc_id      = var.vpc_id
  target_type = "ip"

  health_check {
    enabled             = true
    healthy_threshold   = 2
    unhealthy_threshold = 3
    timeout             = 5
    interval            = 30
    path                = "/"
    protocol            = "HTTP"
    matcher             = "200"
  }

  deregistration_delay = 30

  tags = merge(
    var.tags,
    {
      Name = "${var.name_prefix}-webui-tg"
    }
  )

  lifecycle {
    create_before_destroy = true
  }
}

# HTTP Listener (redirect to HTTPS)
resource "aws_lb_listener" "http" {
  load_balancer_arn = aws_lb.main.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type = "redirect"

    redirect {
      port        = "443"
      protocol    = "HTTPS"
      status_code = "HTTP_301"
    }
  }

  tags = var.tags
}

# HTTPS Listener
resource "aws_lb_listener" "https" {
  count               = var.certificate_arn != null ? 1 : 0
  load_balancer_arn   = aws_lb.main.arn
  port                = 443
  protocol            = "HTTPS"
  ssl_policy          = "ELBSecurityPolicy-TLS-1-2-2017-01"
  certificate_arn     = var.certificate_arn

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.webui.arn
  }

  tags = var.tags
}

# HTTPS Listener Rule for API
resource "aws_lb_listener_rule" "api" {
  count        = var.certificate_arn != null ? 1 : 0
  listener_arn = aws_lb_listener.https[0].arn
  priority     = 100

  action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.api.arn
  }

  condition {
    path_pattern {
      values = ["/api/*", "/docs", "/openapi.json"]
    }
  }

  tags = var.tags
}

# HTTP Listener (if no certificate, use HTTP directly - for testing)
resource "aws_lb_listener" "http_forward" {
  count             = var.certificate_arn == null ? 1 : 0
  load_balancer_arn = aws_lb.main.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.webui.arn
  }

  tags = var.tags
}

# HTTP Listener Rule for API (if no certificate)
resource "aws_lb_listener_rule" "api_http" {
  count        = var.certificate_arn == null ? 1 : 0
  listener_arn = aws_lb_listener.http_forward[0].arn
  priority     = 100

  action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.api.arn
  }

  condition {
    path_pattern {
      values = ["/api/*", "/docs", "/openapi.json"]
    }
  }

  tags = var.tags
}

# CloudWatch Alarms
resource "aws_cloudwatch_metric_alarm" "target_response_time" {
  alarm_name          = "${var.name_prefix}-alb-response-time"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "TargetResponseTime"
  namespace           = "AWS/ApplicationELB"
  period              = "60"
  statistic           = "Average"
  threshold           = "1"
  alarm_description   = "ALB target response time is too high"
  alarm_actions       = var.alarm_sns_topic_arn != null ? [var.alarm_sns_topic_arn] : []

  dimensions = {
    LoadBalancer = aws_lb.main.arn_suffix
  }

  tags = var.tags
}

resource "aws_cloudwatch_metric_alarm" "unhealthy_hosts" {
  alarm_name          = "${var.name_prefix}-alb-unhealthy-hosts"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "UnHealthyHostCount"
  namespace           = "AWS/ApplicationELB"
  period              = "60"
  statistic           = "Average"
  threshold           = "0"
  alarm_description   = "ALB has unhealthy targets"
  alarm_actions       = var.alarm_sns_topic_arn != null ? [var.alarm_sns_topic_arn] : []

  dimensions = {
    LoadBalancer = aws_lb.main.arn_suffix
    TargetGroup  = aws_lb_target_group.api.arn_suffix
  }

  tags = var.tags
}

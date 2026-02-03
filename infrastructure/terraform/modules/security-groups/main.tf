# Security Groups Module for AuditGitHub
# Creates security groups for ALB, ECS, RDS, and ElastiCache

# Application Load Balancer Security Group
resource "aws_security_group" "alb" {
  name_prefix = "${var.name_prefix}-alb-"
  description = "Security group for Application Load Balancer"
  vpc_id      = var.vpc_id

  tags = merge(
    var.tags,
    {
      Name = "${var.name_prefix}-alb-sg"
    }
  )
}

# ALB Ingress Rules
resource "aws_vpc_security_group_ingress_rule" "alb_http" {
  security_group_id = aws_security_group.alb.id
  description       = "Allow HTTP from internet"
  cidr_ipv4         = "0.0.0.0/0"
  from_port         = 80
  to_port           = 80
  ip_protocol       = "tcp"
}

resource "aws_vpc_security_group_ingress_rule" "alb_https" {
  security_group_id = aws_security_group.alb.id
  description       = "Allow HTTPS from internet"
  cidr_ipv4         = "0.0.0.0/0"
  from_port         = 443
  to_port           = 443
  ip_protocol       = "tcp"
}

# ALB Egress Rules
resource "aws_vpc_security_group_egress_rule" "alb_all" {
  security_group_id = aws_security_group.alb.id
  description       = "Allow all outbound traffic"
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = "-1"
}

# ECS Tasks Security Group
resource "aws_security_group" "ecs" {
  name_prefix = "${var.name_prefix}-ecs-"
  description = "Security group for ECS tasks"
  vpc_id      = var.vpc_id

  tags = merge(
    var.tags,
    {
      Name = "${var.name_prefix}-ecs-sg"
    }
  )
}

# ECS Ingress Rules - API Port
resource "aws_vpc_security_group_ingress_rule" "ecs_api" {
  security_group_id            = aws_security_group.ecs.id
  description                  = "Allow API traffic from ALB"
  referenced_security_group_id = aws_security_group.alb.id
  from_port                    = 8000
  to_port                      = 8000
  ip_protocol                  = "tcp"
}

# ECS Ingress Rules - Web UI Port
resource "aws_vpc_security_group_ingress_rule" "ecs_webui" {
  security_group_id            = aws_security_group.ecs.id
  description                  = "Allow Web UI traffic from ALB"
  referenced_security_group_id = aws_security_group.alb.id
  from_port                    = 3000
  to_port                      = 3000
  ip_protocol                  = "tcp"
}

# ECS Egress Rules
resource "aws_vpc_security_group_egress_rule" "ecs_all" {
  security_group_id = aws_security_group.ecs.id
  description       = "Allow all outbound traffic"
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = "-1"
}

# RDS Security Group
resource "aws_security_group" "rds" {
  name_prefix = "${var.name_prefix}-rds-"
  description = "Security group for RDS PostgreSQL"
  vpc_id      = var.vpc_id

  tags = merge(
    var.tags,
    {
      Name = "${var.name_prefix}-rds-sg"
    }
  )
}

# RDS Ingress Rules - Allow from ECS
resource "aws_vpc_security_group_ingress_rule" "rds_from_ecs" {
  security_group_id            = aws_security_group.rds.id
  description                  = "Allow PostgreSQL from ECS tasks"
  referenced_security_group_id = aws_security_group.ecs.id
  from_port                    = 5432
  to_port                      = 5432
  ip_protocol                  = "tcp"
}

# RDS Egress Rules
resource "aws_vpc_security_group_egress_rule" "rds_all" {
  security_group_id = aws_security_group.rds.id
  description       = "Allow all outbound traffic"
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = "-1"
}

# ElastiCache Redis Security Group
resource "aws_security_group" "redis" {
  name_prefix = "${var.name_prefix}-redis-"
  description = "Security group for ElastiCache Redis"
  vpc_id      = var.vpc_id

  tags = merge(
    var.tags,
    {
      Name = "${var.name_prefix}-redis-sg"
    }
  )
}

# Redis Ingress Rules - Allow from ECS
resource "aws_vpc_security_group_ingress_rule" "redis_from_ecs" {
  security_group_id            = aws_security_group.redis.id
  description                  = "Allow Redis from ECS tasks"
  referenced_security_group_id = aws_security_group.ecs.id
  from_port                    = 6379
  to_port                      = 6379
  ip_protocol                  = "tcp"
}

# Redis Egress Rules
resource "aws_vpc_security_group_egress_rule" "redis_all" {
  security_group_id = aws_security_group.redis.id
  description       = "Allow all outbound traffic"
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = "-1"
}

# VPC Endpoints Security Group (for private AWS service access)
resource "aws_security_group" "vpc_endpoints" {
  name_prefix = "${var.name_prefix}-vpc-endpoints-"
  description = "Security group for VPC endpoints"
  vpc_id      = var.vpc_id

  tags = merge(
    var.tags,
    {
      Name = "${var.name_prefix}-vpc-endpoints-sg"
    }
  )
}

# VPC Endpoints Ingress - Allow from ECS
resource "aws_vpc_security_group_ingress_rule" "vpc_endpoints_from_ecs" {
  security_group_id            = aws_security_group.vpc_endpoints.id
  description                  = "Allow HTTPS from ECS tasks"
  referenced_security_group_id = aws_security_group.ecs.id
  from_port                    = 443
  to_port                      = 443
  ip_protocol                  = "tcp"
}

# VPC Endpoints Egress
resource "aws_vpc_security_group_egress_rule" "vpc_endpoints_all" {
  security_group_id = aws_security_group.vpc_endpoints.id
  description       = "Allow all outbound traffic"
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = "-1"
}

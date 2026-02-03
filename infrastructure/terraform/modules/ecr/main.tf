# ECR Module for AuditGitHub
# Creates ECR repositories for container images

locals {
  repositories = toset(var.repository_names)
}

# ECR Repositories
resource "aws_ecr_repository" "main" {
  for_each = local.repositories
  name     = "${var.name_prefix}-${each.value}"

  image_scanning_configuration {
    scan_on_push = var.scan_on_push
  }

  image_tag_mutability = var.image_tag_mutability

  encryption_configuration {
    encryption_type = var.encryption_type
    kms_key         = var.kms_key_arn
  }

  tags = merge(
    var.tags,
    {
      Name = "${var.name_prefix}-${each.value}"
    }
  )
}

# Lifecycle Policy to clean up old images
resource "aws_ecr_lifecycle_policy" "main" {
  for_each   = local.repositories
  repository = aws_ecr_repository.main[each.value].name

  policy = jsonencode({
    rules = [
      {
        rulePriority = 1
        description  = "Keep last ${var.max_image_count} images"
        selection = {
          tagStatus     = "any"
          countType     = "imageCountMoreThan"
          countNumber   = var.max_image_count
        }
        action = {
          type = "expire"
        }
      }
    ]
  })
}

# ECR Repository Policy (optional - for cross-account access)
resource "aws_ecr_repository_policy" "main" {
  for_each   = var.enable_cross_account_access ? local.repositories : []
  repository = aws_ecr_repository.main[each.value].name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowPushPull"
        Effect = "Allow"
        Principal = {
          AWS = var.allowed_account_ids
        }
        Action = [
          "ecr:GetDownloadUrlForLayer",
          "ecr:BatchGetImage",
          "ecr:BatchCheckLayerAvailability",
          "ecr:PutImage",
          "ecr:InitiateLayerUpload",
          "ecr:UploadLayerPart",
          "ecr:CompleteLayerUpload"
        ]
      }
    ]
  })
}

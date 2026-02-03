# S3 Module for AuditGitHub
# Creates S3 buckets for reports, logs, and backups

# Reports Bucket
resource "aws_s3_bucket" "reports" {
  bucket = "${var.name_prefix}-reports-${var.aws_account_id}"

  tags = merge(
    var.tags,
    {
      Name = "${var.name_prefix}-reports"
      Type = "Reports"
    }
  )
}

# Reports Bucket Versioning
resource "aws_s3_bucket_versioning" "reports" {
  bucket = aws_s3_bucket.reports.id

  versioning_configuration {
    status = var.enable_versioning ? "Enabled" : "Suspended"
  }
}

# Reports Bucket Encryption
resource "aws_s3_bucket_server_side_encryption_configuration" "reports" {
  bucket = aws_s3_bucket.reports.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = var.kms_key_arn != null ? "aws:kms" : "AES256"
      kms_master_key_id = var.kms_key_arn
    }
    bucket_key_enabled = var.kms_key_arn != null ? true : false
  }
}

# Reports Bucket Public Access Block
resource "aws_s3_bucket_public_access_block" "reports" {
  bucket = aws_s3_bucket.reports.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Reports Bucket Lifecycle Policy
resource "aws_s3_bucket_lifecycle_configuration" "reports" {
  bucket = aws_s3_bucket.reports.id

  rule {
    id     = "transition-old-reports"
    status = "Enabled"

    transition {
      days          = var.reports_transition_days
      storage_class = "STANDARD_IA"
    }

    transition {
      days          = var.reports_glacier_days
      storage_class = "GLACIER"
    }

    expiration {
      days = var.reports_expiration_days
    }
  }
}

# Logs Bucket
resource "aws_s3_bucket" "logs" {
  bucket = "${var.name_prefix}-logs-${var.aws_account_id}"

  tags = merge(
    var.tags,
    {
      Name = "${var.name_prefix}-logs"
      Type = "Logs"
    }
  )
}

# Logs Bucket Versioning
resource "aws_s3_bucket_versioning" "logs" {
  bucket = aws_s3_bucket.logs.id

  versioning_configuration {
    status = "Suspended"
  }
}

# Logs Bucket Encryption
resource "aws_s3_bucket_server_side_encryption_configuration" "logs" {
  bucket = aws_s3_bucket.logs.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = var.kms_key_arn != null ? "aws:kms" : "AES256"
      kms_master_key_id = var.kms_key_arn
    }
    bucket_key_enabled = var.kms_key_arn != null ? true : false
  }
}

# Logs Bucket Public Access Block
resource "aws_s3_bucket_public_access_block" "logs" {
  bucket = aws_s3_bucket.logs.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Logs Bucket Lifecycle Policy
resource "aws_s3_bucket_lifecycle_configuration" "logs" {
  bucket = aws_s3_bucket.logs.id

  rule {
    id     = "transition-old-logs"
    status = "Enabled"

    transition {
      days          = var.logs_transition_days
      storage_class = "STANDARD_IA"
    }

    expiration {
      days = var.logs_expiration_days
    }
  }
}

# ALB Access Logs Policy
resource "aws_s3_bucket_policy" "logs" {
  bucket = aws_s3_bucket.logs.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AWSLogDeliveryWrite"
        Effect = "Allow"
        Principal = {
          Service = "logging.s3.amazonaws.com"
        }
        Action = "s3:PutObject"
        Resource = "${aws_s3_bucket.logs.arn}/*"
      },
      {
        Sid    = "AWSLogDeliveryAclCheck"
        Effect = "Allow"
        Principal = {
          Service = "logging.s3.amazonaws.com"
        }
        Action = "s3:GetBucketAcl"
        Resource = aws_s3_bucket.logs.arn
      },
      {
        Sid    = "AWSELBAccessLogWrite"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${var.elb_account_id}:root"
        }
        Action = "s3:PutObject"
        Resource = "${aws_s3_bucket.logs.arn}/alb/*"
      }
    ]
  })
}

# Backups Bucket (optional)
resource "aws_s3_bucket" "backups" {
  count  = var.create_backups_bucket ? 1 : 0
  bucket = "${var.name_prefix}-backups-${var.aws_account_id}"

  tags = merge(
    var.tags,
    {
      Name = "${var.name_prefix}-backups"
      Type = "Backups"
    }
  )
}

# Backups Bucket Versioning
resource "aws_s3_bucket_versioning" "backups" {
  count  = var.create_backups_bucket ? 1 : 0
  bucket = aws_s3_bucket.backups[0].id

  versioning_configuration {
    status = "Enabled"
  }
}

# Backups Bucket Encryption
resource "aws_s3_bucket_server_side_encryption_configuration" "backups" {
  count  = var.create_backups_bucket ? 1 : 0
  bucket = aws_s3_bucket.backups[0].id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = var.kms_key_arn != null ? "aws:kms" : "AES256"
      kms_master_key_id = var.kms_key_arn
    }
    bucket_key_enabled = var.kms_key_arn != null ? true : false
  }
}

# Backups Bucket Public Access Block
resource "aws_s3_bucket_public_access_block" "backups" {
  count  = var.create_backups_bucket ? 1 : 0
  bucket = aws_s3_bucket.backups[0].id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# -----------------------------------------------------------------
# HARDENED TERRAFORM
# -----------------------------------------------------------------

# ================================================================
# S3 BUCKET
# ================================================================

resource "aws_s3_bucket" "poc_bucket" {
  bucket = "devsecops-poc-artifacts-example"
}

# Versioning
resource "aws_s3_bucket_versioning" "poc_bucket_versioning" {
  bucket = aws_s3_bucket.poc_bucket.id

  versioning_configuration {
    status = "Enabled"
  }
}

# KMS encryption
resource "aws_kms_key" "s3" {
  description         = "KMS key for S3 bucket encryption"
  enable_key_rotation = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "poc_bucket_encryption" {
  bucket = aws_s3_bucket.poc_bucket.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.s3.arn
    }

    bucket_key_enabled = true
  }
}

# Public access completely blocked
resource "aws_s3_bucket_public_access_block" "poc_bucket_block" {
  bucket = aws_s3_bucket.poc_bucket.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Lifecycle
resource "aws_s3_bucket_lifecycle_configuration" "poc_bucket_lifecycle" {
  bucket = aws_s3_bucket.poc_bucket.id

  rule {
    id     = "delete-old-objects"
    status = "Enabled"

    expiration {
      days = 90
    }

    noncurrent_version_expiration {
      noncurrent_days = 30
    }
  }
}


# ================================================================
# SECURITY GROUP
# ================================================================

variable "trusted_cidr" {
  description = "CIDR block allowed to reach admin/SSH ports"
  type        = string
}

resource "aws_security_group" "poc_sg" {
  name        = "devsecops-poc-sg"
  description = "Restricted security group"

  ingress {
    description = "SSH from trusted network only"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.trusted_cidr]
  }

  ingress {
    description = "Application traffic"
    from_port   = 3000
    to_port     = 3000
    protocol    = "tcp"
    cidr_blocks = [var.trusted_cidr]
  }

  # HTTPS only
  egress {
    description = "HTTPS outbound"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# -----------------------------------------------------------------
# HARDENED TERRAFORM (optional reference for Checkov/Trivy IaC scans)
#
# Fixes applied:
#  - Private bucket, public access fully blocked
#  - Versioning and access logging enabled
#  - Default encryption enabled
#  - Security group restricted to known CIDRs, no world-open SSH
# -----------------------------------------------------------------
resource "aws_s3_bucket" "poc_bucket" {
  bucket = "devsecops-poc-artifacts-example"
}

resource "aws_s3_bucket_versioning" "poc_bucket_versioning" {
  bucket = aws_s3_bucket.poc_bucket.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "poc_bucket_encryption" {
  bucket = aws_s3_bucket.poc_bucket.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_logging" "poc_bucket_logging" {
  bucket        = aws_s3_bucket.poc_bucket.id
  target_bucket = aws_s3_bucket.poc_bucket.id
  target_prefix = "access-logs/"
}

resource "aws_s3_bucket_public_access_block" "poc_bucket_block" {
  bucket                  = aws_s3_bucket.poc_bucket.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

variable "trusted_cidr" {
  description = "CIDR block allowed to reach admin/SSH ports - set this to your own IP, not 0.0.0.0/0"
  type        = string
}

resource "aws_security_group" "poc_sg" {
  name        = "devsecops-poc-sg"
  description = "Restricted security group - app port and SSH limited to trusted_cidr only"

  ingress {
    description = "SSH from trusted network only"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.trusted_cidr]
  }

  ingress {
    description = "App port from trusted network only"
    from_port   = 3000
    to_port     = 3000
    protocol    = "tcp"
    cidr_blocks = [var.trusted_cidr]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# --- S3 Audit Bucket -------------------------------------------------------

resource "aws_s3_bucket" "audit" {
  count  = var.enable_s3_audit ? 1 : 0
  bucket = "${var.project_name}-audit-${data.aws_caller_identity.current.account_id}"

  object_lock_enabled = true

  tags = { Name = "${var.project_name}-audit" }
}

resource "aws_s3_bucket_versioning" "audit" {
  count  = var.enable_s3_audit ? 1 : 0
  bucket = aws_s3_bucket.audit[0].id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "audit" {
  count  = var.enable_s3_audit ? 1 : 0
  bucket = aws_s3_bucket.audit[0].id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "audit" {
  count  = var.enable_s3_audit ? 1 : 0
  bucket = aws_s3_bucket.audit[0].id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_object_lock_configuration" "audit" {
  count  = var.enable_s3_audit ? 1 : 0
  bucket = aws_s3_bucket.audit[0].id

  depends_on = [aws_s3_bucket_versioning.audit]

  rule {
    default_retention {
      mode = "GOVERNANCE"
      days = 365
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "audit" {
  count  = var.enable_s3_audit ? 1 : 0
  bucket = aws_s3_bucket.audit[0].id

  rule {
    id     = "transition-to-ia"
    status = "Enabled"

    filter {}

    transition {
      days          = 90
      storage_class = "STANDARD_IA"
    }

    transition {
      days          = 365
      storage_class = "GLACIER"
    }
  }
}

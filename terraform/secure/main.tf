provider "aws" {
  region = "us-east-1"
}

resource "aws_s3_bucket" "company_data" {
  bucket = "om-cloud-security-lab-company-data-secure-2026"
}

# Block public access through bucket policies and ACLs
resource "aws_s3_bucket_public_access_block" "company_data" {
  bucket = aws_s3_bucket.company_data.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Enable versioning to protect against accidental deletion or overwrites
resource "aws_s3_bucket_versioning" "company_data" {
  bucket = aws_s3_bucket.company_data.id

  versioning_configuration {
    status = "Enabled"
  }
}

# Enable default server-side encryption
resource "aws_s3_bucket_server_side_encryption_configuration" "company_data" {
  bucket = aws_s3_bucket.company_data.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# Deny requests that do not use HTTPS
resource "aws_s3_bucket_policy" "secure_transport" {
  bucket = aws_s3_bucket.company_data.id

  policy = jsonencode({
    Version = "2012-10-17"

    Statement = [{
      Sid       = "DenyInsecureTransport"
      Effect    = "Deny"
      Principal = "*"
      Action    = "s3:*"
      Resource = [
        aws_s3_bucket.company_data.arn,
        "${aws_s3_bucket.company_data.arn}/*"
      ]

      Condition = {
        Bool = {
          "aws:SecureTransport" = "false"
        }
      }
    }]
  })

  depends_on = [
    aws_s3_bucket_public_access_block.company_data
  ]
}
provider "aws" {
  region = "us-east-1"
}

resource "aws_s3_bucket" "company_data" {
  bucket = "vulnerable-om-cloud-security-lab-company-data-2026"
}

resource "aws_s3_bucket_policy" "public_access" {
  bucket = aws_s3_bucket.company_data.id
  policy = jsonencode({
    Version = "2012-10-17"

    Statement = [
      {
        Principal = "*"
        Effect    = "Allow"
        Action    = "s3:GetObject"
        Resource  = "${aws_s3_bucket.company_data.arn}/*"
      }
    ]
  })

}
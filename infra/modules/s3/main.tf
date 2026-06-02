resource "aws_s3_bucket" "cloudtrail_logs" {
  bucket        = "cloudtrail-logs"
  force_destroy = true
}

resource "aws_s3_bucket_policy" "cloudtrail_logs_policy" {
  bucket = aws_s3_bucket.cloudtrail_logs.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AWSCloudTrailAclCheck"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action   = "s3:GetBucketAcl"
        Resource = aws_s3_bucket.cloudtrail_logs.arn
      },
      {
        Sid    = "AWSCloudTrailWrite"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action   = "s3:PutObject"
        Resource = "${aws_s3_bucket.cloudtrail_logs.arn}/CloudTrail/*"
        Condition = {
          StringEquals = {
            "s3:x-amz-acl" = "bucket-owner-full-control"
          }
        }
      }
    ]
  })
}

resource "aws_s3_bucket" "exposed_bucket" {
  bucket        = "exposed-test-bucket"
  force_destroy = true
}

resource "aws_s3_bucket_ownership_controls" "exposed_bucket_ownership" {
  bucket = aws_s3_bucket.exposed_bucket.id
  rule {
    object_ownership = "BucketOwnerPreferred"
  }
}

resource "aws_s3_bucket_public_access_block" "exposed_bucket_public_access_block" {
  bucket = aws_s3_bucket.exposed_bucket.id

  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

resource "aws_s3_bucket_acl" "exposed_bucket_acl" {
  depends_on = [
    aws_s3_bucket_ownership_controls.exposed_bucket_ownership,
    aws_s3_bucket_public_access_block.exposed_bucket_public_access_block,
  ]

  bucket = aws_s3_bucket.exposed_bucket.id
  acl    = "public-read"
}

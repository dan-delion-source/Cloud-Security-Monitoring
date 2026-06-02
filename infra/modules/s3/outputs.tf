output "cloudtrail_bucket_name" {
  value = aws_s3_bucket.cloudtrail_logs.id
}

output "cloudtrail_bucket_arn" {
  value = aws_s3_bucket.cloudtrail_logs.arn
}

output "exposed_bucket_name" {
  value = aws_s3_bucket.exposed_bucket.id
}

output "exposed_bucket_arn" {
  value = aws_s3_bucket.exposed_bucket.arn
}

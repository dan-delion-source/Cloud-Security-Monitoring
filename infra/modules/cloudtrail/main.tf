# CloudTrail is a Pro-only feature in LocalStack.
# The backend scripts (simulate-events.sh) simulate CloudTrail logs by writing
# JSON records directly into the S3 cloudtrail-logs bucket, so this module
# is not required for the security pipeline to function.
#
# If you have LocalStack Pro, uncomment the resource below:
#
# resource "aws_cloudtrail" "security_trail" {
#   name                          = "security-trail"
#   s3_bucket_name                = var.bucket_name
#   include_global_service_events = true
#   is_multi_region_trail         = true
#   enable_logging                = true
# }

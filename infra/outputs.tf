output "vpc_id" {
  value = module.vpc.vpc_id
}

output "public_subnet_id" {
  value = module.vpc.public_subnet_id
}

output "private_subnet_id" {
  value = module.vpc.private_subnet_id
}

output "dynamodb_table_name" {
  value = module.dynamodb.table_name
}

output "cloudtrail_bucket_name" {
  value = module.s3.cloudtrail_bucket_name
}

output "exposed_bucket_name" {
  value = module.s3.exposed_bucket_name
}

output "normal_user_arn" {
  value = module.iam.normal_user_arn
}

output "suspicious_user_arn" {
  value = module.iam.suspicious_user_arn
}

output "sns_topic_arn" {
  value = module.sns.topic_arn
}

output "sqs_queue_arn" {
  value = module.sqs.queue_arn
}

output "sqs_queue_url" {
  value = module.sqs.queue_url
}

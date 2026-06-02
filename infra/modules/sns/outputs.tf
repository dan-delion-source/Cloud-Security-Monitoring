output "topic_arn" {
  value       = aws_sns_topic.security_alerts.arn
  description = "The ARN of the SNS topic"
}

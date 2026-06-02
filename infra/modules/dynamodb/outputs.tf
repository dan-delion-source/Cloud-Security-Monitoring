output "table_name" {
  value = aws_dynamodb_table.security_alerts.name
}

output "table_arn" {
  value = aws_dynamodb_table.security_alerts.arn
}

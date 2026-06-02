resource "aws_dynamodb_table" "security_alerts" {
  name         = "SecurityAlerts"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "alertId"
  range_key    = "timestamp"

  attribute {
    name = "alertId"
    type = "S"
  }

  attribute {
    name = "timestamp"
    type = "S"
  }

  tags = {
    Name = "SecurityAlerts"
  }
}

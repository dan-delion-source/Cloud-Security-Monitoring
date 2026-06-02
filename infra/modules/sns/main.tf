resource "aws_sns_topic" "security_alerts" {
  name = "security-alerts"

  tags = {
    Name = "security-alerts"
  }
}

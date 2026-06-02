output "web_server_id" {
  value       = aws_instance.web_server.id
  description = "Instance ID of the web server"
}

output "attacker_instance_id" {
  value       = aws_instance.attacker_instance.id
  description = "Instance ID of the attacker instance"
}

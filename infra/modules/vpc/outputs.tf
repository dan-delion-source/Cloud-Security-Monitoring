output "vpc_id" {
  value       = aws_vpc.security_vpc.id
  description = "VPC ID"
}

output "public_subnet_id" {
  value       = aws_subnet.public_subnet.id
  description = "Public subnet ID"
}

output "private_subnet_id" {
  value       = aws_subnet.private_subnet.id
  description = "Private subnet ID"
}

output "web_sg_id" {
  value       = aws_security_group.web_sg.id
  description = "Security group ID for web server"
}

variable "public_subnet_id" {
  type        = string
  description = "The ID of the public subnet to deploy web-server"
}

variable "private_subnet_id" {
  type        = string
  description = "The ID of the private subnet to deploy attacker-instance"
}

variable "security_group_id" {
  type        = string
  description = "The security group ID for web-server"
}

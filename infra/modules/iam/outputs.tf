output "normal_user_name" {
  value = aws_iam_user.normal_user.name
}

output "normal_user_arn" {
  value = aws_iam_user.normal_user.arn
}

output "suspicious_user_name" {
  value = aws_iam_user.suspicious_user.name
}

output "suspicious_user_arn" {
  value = aws_iam_user.suspicious_user.arn
}

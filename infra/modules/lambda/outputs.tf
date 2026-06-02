output "s3_scanner_name" {
  value = aws_lambda_function.s3_scanner.function_name
}

output "iam_detector_name" {
  value = aws_lambda_function.iam_detector.function_name
}

output "unauth_detector_name" {
  value = aws_lambda_function.unauth_detector.function_name
}

output "suspicious_login_name" {
  value = aws_lambda_function.suspicious_login.function_name
}

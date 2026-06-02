data "external" "localstack_ip" {
  program = ["bash", "-c", "ip=$(docker inspect localstack-main --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' 2>/dev/null || docker inspect localstack --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' 2>/dev/null); if [ -z \"$ip\" ]; then ip=\"localhost\"; fi; echo \"{\\\"ip\\\": \\\"$ip\\\"}\""]
}

# Archive file data blocks pointing to backend/lambdas/
data "archive_file" "s3_scanner_zip" {
  type        = "zip"
  source_file = "${path.module}/../../../backend/lambdas/s3-scanner.js"
  output_path = "${path.module}/s3-scanner.zip"
}

data "archive_file" "iam_detector_zip" {
  type        = "zip"
  source_file = "${path.module}/../../../backend/lambdas/iam-detector.js"
  output_path = "${path.module}/iam-detector.zip"
}

data "archive_file" "unauth_detector_zip" {
  type        = "zip"
  source_file = "${path.module}/../../../backend/lambdas/unauth-detector.js"
  output_path = "${path.module}/unauth-detector.zip"
}

data "archive_file" "suspicious_login_zip" {
  type        = "zip"
  source_file = "${path.module}/../../../backend/lambdas/suspicious-login.js"
  output_path = "${path.module}/suspicious-login.zip"
}

# IAM Role for Lambda
resource "aws_iam_role" "lambda_exec" {
  name = "lambda-execution-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "lambda_policy" {
  role       = aws_iam_role.lambda_exec.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

# Lambdas deployment
resource "aws_lambda_function" "s3_scanner" {
  filename         = data.archive_file.s3_scanner_zip.output_path
  source_code_hash = data.archive_file.s3_scanner_zip.output_base64sha256
  function_name    = "s3-scanner"
  role             = aws_iam_role.lambda_exec.arn
  handler          = "s3-scanner.handler"
  runtime          = "nodejs18.x"
  timeout          = 15

  environment {
    variables = {
      AWS_ENDPOINT_URL = "http://${data.external.localstack_ip.result.ip}:4566"
    }
  }
}

resource "aws_lambda_function" "iam_detector" {
  filename         = data.archive_file.iam_detector_zip.output_path
  source_code_hash = data.archive_file.iam_detector_zip.output_base64sha256
  function_name    = "iam-detector"
  role             = aws_iam_role.lambda_exec.arn
  handler          = "iam-detector.handler"
  runtime          = "nodejs18.x"
  timeout          = 15

  environment {
    variables = {
      AWS_ENDPOINT_URL = "http://${data.external.localstack_ip.result.ip}:4566"
    }
  }
}

resource "aws_lambda_function" "unauth_detector" {
  filename         = data.archive_file.unauth_detector_zip.output_path
  source_code_hash = data.archive_file.unauth_detector_zip.output_base64sha256
  function_name    = "unauth-detector"
  role             = aws_iam_role.lambda_exec.arn
  handler          = "unauth-detector.handler"
  runtime          = "nodejs18.x"
  timeout          = 15

  environment {
    variables = {
      AWS_ENDPOINT_URL = "http://${data.external.localstack_ip.result.ip}:4566"
    }
  }
}

resource "aws_lambda_function" "suspicious_login" {
  filename         = data.archive_file.suspicious_login_zip.output_path
  source_code_hash = data.archive_file.suspicious_login_zip.output_base64sha256
  function_name    = "suspicious-login"
  role             = aws_iam_role.lambda_exec.arn
  handler          = "suspicious-login.handler"
  runtime          = "nodejs18.x"
  timeout          = 15

  environment {
    variables = {
      AWS_ENDPOINT_URL = "http://${data.external.localstack_ip.result.ip}:4566"
    }
  }
}

# Event Source Mapping (SQS to Lambda trigger)
resource "aws_lambda_event_source_mapping" "sqs_unauth_trigger" {
  event_source_arn = var.sqs_queue_arn
  function_name    = aws_lambda_function.unauth_detector.function_name
  batch_size       = 10
}

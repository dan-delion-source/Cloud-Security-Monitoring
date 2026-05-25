#!/bin/bash

# Exit on error
set -e

echo "=================================================="
echo "  CloudSentinel - LocalStack Provisioning Script  "
echo "=================================================="

ENDPOINT="http://localhost:4566"
REGION="us-east-1"
export AWS_ACCESS_KEY_ID="test"
export AWS_SECRET_ACCESS_KEY="test"
export AWS_DEFAULT_REGION="$REGION"

# Helper function for AWS CLI calls
aws_local() {
    aws --endpoint-url="$ENDPOINT" "$@"
}

echo "[*] Waiting for LocalStack to be healthy on $ENDPOINT..."
for i in {1..30}; do
    if curl -s "$ENDPOINT/_localstack/health" > /dev/null; then
        echo "[✓] LocalStack is healthy and reachable."
        break
    fi
    if [ "$i" -eq 30 ]; then
        echo "[✗] LocalStack was not reachable after 30 seconds. Exiting."
        exit 1
    fi
    echo "[*] Retrying in 1s ($i/30)..."
    sleep 1
done

# 1. DynamoDB: Create SecurityAlerts table
echo "[*] Creating DynamoDB table 'SecurityAlerts'..."
if aws_local dynamodb list-tables | grep -q "SecurityAlerts"; then
    echo "[-] DynamoDB table 'SecurityAlerts' already exists. Skipping."
else
    aws_local dynamodb create-table \
        --table-name SecurityAlerts \
        --attribute-definitions \
            AttributeName=alertId,AttributeType=S \
            AttributeName=timestamp,AttributeType=S \
        --key-schema \
            AttributeName=alertId,KeyType=HASH \
            AttributeName=timestamp,KeyType=RANGE \
        --billing-mode PAY_PER_REQUEST
    echo "[✓] Table 'SecurityAlerts' created successfully."
fi

# 2. S3: Create cloudtrail-logs bucket
echo "[*] Creating S3 bucket 'cloudtrail-logs'..."
if aws_local s3api list-buckets | grep -q "cloudtrail-logs"; then
    echo "[-] S3 bucket 'cloudtrail-logs' already exists. Skipping."
else
    aws_local s3 mb s3://cloudtrail-logs
    echo "[✓] S3 bucket 'cloudtrail-logs' created successfully."
fi

# 3. SNS: Create security-alerts topic
echo "[*] Creating SNS topic 'security-alerts'..."
SNS_ARN=$(aws_local sns create-topic --name security-alerts --query "TopicArn" --output text)
echo "[✓] SNS topic created: $SNS_ARN"

# 4. SQS: Create alert-queue
echo "[*] Creating SQS queue 'alert-queue'..."
SQS_URL=$(aws_local sqs create-queue --queue-name alert-queue --query "QueueUrl" --output text)
SQS_ARN=$(aws_local sqs get-queue-attributes --queue-url "$SQS_URL" --attribute-names QueueArn --query "Attributes.QueueArn" --output text)
echo "[✓] SQS queue created: $SQS_URL (ARN: $SQS_ARN)"

# 5. SNS-SQS Subscription
echo "[*] Subscribing SQS queue to SNS topic..."
aws_local sns subscribe --topic-arn "$SNS_ARN" --protocol sqs --notification-endpoint "$SQS_ARN"
echo "[✓] Subscribed successfully."

# 6. Deploy Lambda functions
echo "[*] Packaging and deploying Lambda functions..."
LAMBDA_ROLE="arn:aws:iam::000000000000:role/lambda-execution-role"

# Make a temp directory for packaging zips
TEMP_ZIP_DIR=$(mktemp -d)

# Deploy individual lambdas
LAMBDAS=("s3-scanner" "iam-detector" "unauth-detector" "suspicious-login")

for lambda in "${LAMBDAS[@]}"; do
    echo "[*] Deploying Lambda: $lambda..."
    
    # Zip the Lambda function code
    zip -j "$TEMP_ZIP_DIR/$lambda.zip" "lambdas/$lambda.js" > /dev/null
    
    # Delete if exists
    if aws_local lambda list-functions | grep -q "$lambda"; then
        echo "[-] Lambda $lambda already exists. Updating code..."
        aws_local lambda update-function-code \
            --function-name "$lambda" \
            --zip-file "fileb://$TEMP_ZIP_DIR/$lambda.zip" > /dev/null
        echo "[✓] Lambda $lambda code updated."
    else
        aws_local lambda create-function \
            --function-name "$lambda" \
            --runtime nodejs18.x \
            --role "$LAMBDA_ROLE" \
            --handler "$lambda.handler" \
            --zip-file "fileb://$TEMP_ZIP_DIR/$lambda.zip" \
            --timeout 15 \
            --environment "Variables={AWS_ENDPOINT_URL=$ENDPOINT}" > /dev/null
        echo "[✓] Lambda $lambda created successfully."
    fi
done

# Clean up packaging zip
rm -rf "$TEMP_ZIP_DIR"

# 7. Map SQS trigger to unauth-detector lambda
echo "[*] Setting up SQS event source mapping for unauth-detector..."
if aws_local lambda list-event-source-mappings --function-name unauth-detector --query "EventSourceMappings" --output text | grep -q "$SQS_ARN"; then
    echo "[-] SQS source mapping already exists. Skipping."
else
    aws_local lambda create-event-source-mapping \
        --function-name unauth-detector \
        --event-source-arn "$SQS_ARN" \
        --batch-size 10
    echo "[✓] SQS event trigger mapped to unauth-detector lambda successfully."
fi

echo "=================================================="
echo "  [✓] All LocalStack resources deployed!        "
echo "=================================================="

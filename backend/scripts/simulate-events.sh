#!/bin/bash

# Exit on error
set -e

echo "=================================================="
echo "  CloudSentinel - Security Event Simulator Script"
echo "=================================================="

ENDPOINT="http://localhost:4566"
REGION="us-east-1"
export AWS_ACCESS_KEY_ID="test"
export AWS_SECRET_ACCESS_KEY="test"
export AWS_DEFAULT_REGION="$REGION"

aws_local() {
    aws --endpoint-url="$ENDPOINT" "$@"
}

echo "[*] Initializing simulation target resources..."

# 1. Setup compliance breach S3 bucket: public-assets-static-website
echo "[*] Creating vulnerable S3 bucket (public access)..."
if aws_local s3api list-buckets | grep -q "public-assets-static-website"; then
    echo "[-] Bucket already exists. Skipping."
else
    aws_local s3 mb s3://public-assets-static-website
    
    # Enable static website hosting
    aws_local s3api put-bucket-website \
        --bucket public-assets-static-website \
        --website-configuration '{"IndexDocument":{"Suffix":"index.html"}}'
        
    # Put open-access policy
    aws_local s3api put-bucket-policy \
        --bucket public-assets-static-website \
        --policy '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::public-assets-static-website/*"}]}'
    
    echo "[✓] Vulnerable public S3 bucket created."
fi

# 2. Setup secure/compliant S3 bucket: secure-customer-pii-kms
echo "[*] Creating compliant S3 bucket (secure KMS encryption & versioning)..."
if aws_local s3api list-buckets | grep -q "secure-customer-pii-kms"; then
    echo "[-] Bucket already exists. Skipping."
else
    aws_local s3 mb s3://secure-customer-pii-kms
    
    # Configure SSE-KMS
    aws_local s3api put-bucket-encryption \
      --bucket secure-customer-pii-kms \
      --server-side-encryption-configuration '{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"aws:kms"}}]}'
      
    # Enable versioning
    aws_local s3api put-bucket-versioning \
      --bucket secure-customer-pii-kms \
      --versioning-configuration Status=Enabled
      
    echo "[✓] Secure S3 bucket created."
fi

# 3. Setup dangerous IAM user: junior-dev with direct AdministratorAccess policy
echo "[*] Creating vulnerable IAM User (direct Admin policy)..."
if aws_local iam list-users --query "Users[].UserName" --output text | grep -q "junior-dev"; then
    echo "[-] IAM User junior-dev already exists. Skipping."
else
    aws_local iam create-user --user-name junior-dev
    
    # Direct attach of AdministratorAccess
    aws_local iam attach-user-policy \
        --user-name junior-dev \
        --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
    echo "[✓] IAM user junior-dev created with direct AdministratorAccess policy."
fi

# 4. Setup compliant IAM user: john-doe with active Virtual MFA
echo "[*] Creating compliant IAM User john-doe (MFA active)..."
if aws_local iam list-users --query "Users[].UserName" --output text | grep -q "john-doe"; then
    echo "[-] IAM User john-doe already exists. Skipping."
else
    aws_local iam create-user --user-name john-doe
    # Simulate virtual MFA configuration
    aws_local iam create-virtual-mfa-device --virtual-mfa-device-name "john-doe-mfa" > /dev/null
    aws_local iam enable-mfa-device \
        --user-name john-doe \
        --serial-number "arn:aws:iam::000000000000:mfa/john-doe-mfa" \
        --authentication-code-1 "123456" \
        --authentication-code-2 "654321"
    echo "[✓] IAM user john-doe created with virtual MFA configured."
fi

# 5. S3 CloudTrail logs: Create failed & suspicious login/access logs
echo "[*] Generating CloudTrail log file in S3 'cloudtrail-logs'..."

CLOUDTRAIL_LOGS='{
  "Records": [
    {
      "eventVersion": "1.08",
      "userIdentity": {
        "type": "IAMUser",
        "principalId": "AIDAJKNDFSKNDF",
        "arn": "arn:aws:iam::000000000000:user/junior-dev",
        "accountId": "000000000000",
        "userName": "junior-dev"
      },
      "eventTime": "'$(date -u -d "4 mins ago" +"%Y-%m-%dT%H:%M:%SZ")'",
      "eventSource": "signin.amazonaws.com",
      "eventName": "ConsoleLogin",
      "awsRegion": "us-east-1",
      "sourceIPAddress": "198.51.100.42",
      "userAgent": "Mozilla/5.0",
      "additionalEventData": {
        "MFAUsed": "No"
      },
      "responseElements": {
        "ConsoleLogin": "Success"
      }
    },
    {
      "eventVersion": "1.08",
      "userIdentity": {
        "type": "IAMUser",
        "principalId": "AIDAPDFJDFNDF",
        "arn": "arn:aws:iam::000000000000:user/untrusted-actor",
        "accountId": "000000000000",
        "userName": "untrusted-actor"
      },
      "eventTime": "'$(date -u -d "12 mins ago" +"%Y-%m-%dT%H:%M:%SZ")'",
      "eventSource": "s3.amazonaws.com",
      "eventName": "GetObject",
      "awsRegion": "us-east-1",
      "sourceIPAddress": "203.0.113.85",
      "userAgent": "aws-cli",
      "errorCode": "AccessDenied",
      "errorMessage": "Access Denied by bucket policy rules",
      "requestParameters": {
        "bucketName": "secure-customer-pii-kms",
        "key": "customer_passwords.csv"
      }
    },
    {
      "eventVersion": "1.08",
      "userIdentity": {
        "type": "IAMUser",
        "principalId": "AIDAJKNDFSKNDF",
        "arn": "arn:aws:iam::000000000000:user/junior-dev",
        "accountId": "000000000000",
        "userName": "junior-dev"
      },
      "eventTime": "'$(date -u -d "23:05" +"%Y-%m-%dT%H:%M:%SZ")'",
      "eventSource": "signin.amazonaws.com",
      "eventName": "ConsoleLogin",
      "awsRegion": "us-east-1",
      "sourceIPAddress": "45.227.254.12",
      "userAgent": "Mozilla/5.0",
      "additionalEventData": {
        "MFAUsed": "No"
      },
      "responseElements": {
        "ConsoleLogin": "Success"
      }
    }
  ]
}'

# Save CloudTrail mock records into a temp file
TEMP_LOG_FILE=$(mktemp)
echo "$CLOUDTRAIL_LOGS" > "$TEMP_LOG_FILE"

# Upload to S3 bucket cloudtrail-logs
aws_local s3 cp "$TEMP_LOG_FILE" s3://cloudtrail-logs/CloudTrail/us-east-1/2026/05/25/mock_trail_01.json > /dev/null
rm -f "$TEMP_LOG_FILE"
echo "[✓] Simulated CloudTrail logs uploaded."

# 6. Publish real-time Boundary Breach alert via SNS/SQS path
echo "[*] Publishing direct boundary breach SNS warning..."
SNS_ARN=$(aws_local sns list-topics --query "Topics[0].TopicArn" --output text)

BREACH_MSG='{
  "alertId": "sns-breach-'$(date +%s)'",
  "timestamp": "'$(date -u +"%Y-%m-%dT%H:%M:%SZ")'",
  "type": "UNAUTHORIZED_ACCESS",
  "severity": "CRITICAL",
  "resource": "185.220.101.5",
  "detail": "Application origin direct bypass: incoming request from untrusted public IP 185.220.101.5 did not contain valid CloudFront origin verification headers."
}'

aws_local sns publish --topic-arn "$SNS_ARN" --message "$BREACH_MSG" > /dev/null
echo "[✓] Boundary breach warning published."

# Give SQS and Lambda mapping a split second to process the message
echo "[*] Allowing SQS trigger propagation..."
sleep 2

# 7. Run compliance scans
echo "[*] Invoking scanner Lambdas to execute initial posture check..."
aws_local lambda invoke --function-name s3-scanner /dev/null > /dev/null
aws_local lambda invoke --function-name iam-detector /dev/null > /dev/null
aws_local lambda invoke --function-name suspicious-login /dev/null > /dev/null

echo "=================================================="
echo "  [✓] Security events simulated & scanned!       "
echo "=================================================="

const { S3Client, CreateBucketCommand, PutBucketWebsiteCommand, PutBucketPolicyCommand, PutBucketEncryptionCommand, PutBucketVersioningCommand, PutObjectCommand } = require('@aws-sdk/client-s3');
const { IAMClient, CreateUserCommand, AttachUserPolicyCommand, CreateVirtualMFADeviceCommand, EnableMFADeviceCommand } = require('@aws-sdk/client-iam');
const { SNSClient, ListTopicsCommand, PublishCommand } = require('@aws-sdk/client-sns');
const { LambdaClient, InvokeCommand } = require('@aws-sdk/client-lambda');

const ENDPOINT = 'http://localhost:4566';
const REGION = 'us-east-1';

const clientConfig = {
  endpoint: ENDPOINT,
  region: REGION,
  credentials: {
    accessKeyId: 'test',
    secretAccessKey: 'test'
  },
  forcePathStyle: true
};

const s3Client = new S3Client(clientConfig);
const iamClient = new IAMClient(clientConfig);
const snsClient = new SNSClient(clientConfig);
const lambdaClient = new LambdaClient(clientConfig);

async function main() {
  console.log('==================================================');
  console.log('  CloudSentinel - JS Security Event Simulator    ');
  console.log('==================================================');

  // 1. S3: public-assets-static-website
  console.log('[*] Creating vulnerable public S3 bucket "public-assets-static-website"...');
  try {
    await s3Client.send(new CreateBucketCommand({ Bucket: 'public-assets-static-website' }));
    
    await s3Client.send(new PutBucketWebsiteCommand({
      Bucket: 'public-assets-static-website',
      WebsiteConfiguration: {
        IndexDocument: { Suffix: 'index.html' }
      }
    }));

    const policy = {
      Version: '2012-10-17',
      Statement: [{
        Effect: 'Allow',
        Principal: '*',
        Action: 's3:GetObject',
        Resource: 'arn:aws:s3:::public-assets-static-website/*'
      }]
    };
    await s3Client.send(new PutBucketPolicyCommand({
      Bucket: 'public-assets-static-website',
      Policy: JSON.stringify(policy)
    }));
    console.log('[✓] Public bucket created and configured.');
  } catch (err) {
    console.log('[-] Bucket already configured or error:', err.message);
  }

  // 2. S3: secure-customer-pii-kms
  console.log('[*] Creating secure S3 bucket "secure-customer-pii-kms"...');
  try {
    await s3Client.send(new CreateBucketCommand({ Bucket: 'secure-customer-pii-kms' }));
    
    await s3Client.send(new PutBucketEncryptionCommand({
      Bucket: 'secure-customer-pii-kms',
      ServerSideEncryptionConfiguration: {
        Rules: [{
          ApplyServerSideEncryptionByDefault: {
            SSEAlgorithm: 'aws:kms'
          }
        }]
      }
    }));

    await s3Client.send(new PutBucketVersioningCommand({
      Bucket: 'secure-customer-pii-kms',
      VersioningConfiguration: {
        Status: 'Enabled'
      }
    }));
    console.log('[✓] Secure bucket created and configured.');
  } catch (err) {
    console.log('[-] Bucket already configured or error:', err.message);
  }

  // 3. IAM: Create junior-dev with direct admin rights
  console.log('[*] Creating IAM User "junior-dev" with direct AdministratorAccess policy...');
  try {
    await iamClient.send(new CreateUserCommand({ UserName: 'junior-dev' }));
    await iamClient.send(new AttachUserPolicyCommand({
      UserName: 'junior-dev',
      PolicyArn: 'arn:aws:iam::aws:policy/AdministratorAccess'
    }));
    console.log('[✓] IAM user junior-dev created with direct admin policy.');
  } catch (err) {
    console.log('[-] IAM user junior-dev already exists or error:', err.message);
  }

  // 4. IAM: Create compliant john-doe with MFA
  console.log('[*] Creating compliant IAM User "john-doe" (with simulated MFA)...');
  try {
    await iamClient.send(new CreateUserCommand({ UserName: 'john-doe' }));
    
    const mfaRes = await iamClient.send(new CreateVirtualMFADeviceCommand({
      VirtualMFADeviceName: 'john-doe-mfa'
    }));
    const serial = mfaRes.VirtualMFADevice?.SerialNumber;
    
    if (serial) {
      await iamClient.send(new EnableMFADeviceCommand({
        UserName: 'john-doe',
        SerialNumber: serial,
        AuthenticationCode1: '123456',
        AuthenticationCode2: '654321'
      }));
    }
    console.log('[✓] IAM user john-doe created with simulated MFA.');
  } catch (err) {
    console.log('[-] IAM user john-doe already exists or error:', err.message);
  }

  // 5. CloudTrail Logs: Write to S3 cloudtrail-logs
  console.log('[*] Generating and uploading CloudTrail log file to "cloudtrail-logs" S3 bucket...');
  const logs = {
    Records: [
      {
        eventVersion: '1.08',
        userIdentity: {
          type: 'IAMUser',
          principalId: 'AIDAJKNDFSKNDF',
          arn: 'arn:aws:iam::000000000000:user/junior-dev',
          accountId: '000000000000',
          userName: 'junior-dev'
        },
        eventTime: new Date(Date.now() - 4 * 60000).toISOString(),
        eventSource: 'signin.amazonaws.com',
        eventName: 'ConsoleLogin',
        awsRegion: 'us-east-1',
        sourceIPAddress: '198.51.100.42',
        userAgent: 'Mozilla/5.0',
        additionalEventData: {
          MFAUsed: 'No'
        },
        responseElements: {
          ConsoleLogin: 'Success'
        }
      },
      {
        eventVersion: '1.08',
        userIdentity: {
          type: 'IAMUser',
          principalId: 'AIDAPDFJDFNDF',
          arn: 'arn:aws:iam::000000000000:user/untrusted-actor',
          accountId: '000000000000',
          userName: 'untrusted-actor'
        },
        eventTime: new Date(Date.now() - 12 * 60000).toISOString(),
        eventSource: 's3.amazonaws.com',
        eventName: 'GetObject',
        awsRegion: 'us-east-1',
        sourceIPAddress: '203.0.113.85',
        userAgent: 'aws-cli',
        errorCode: 'AccessDenied',
        errorMessage: 'Access Denied by bucket policy rules',
        requestParameters: {
          bucketName: 'secure-customer-pii-kms',
          key: 'customer_passwords.csv'
        }
      },
      {
        eventVersion: '1.08',
        userIdentity: {
          type: 'IAMUser',
          principalId: 'AIDAJKNDFSKNDF',
          arn: 'arn:aws:iam::000000000000:user/junior-dev',
          accountId: '000000000000',
          userName: 'junior-dev'
        },
        eventTime: new Date(new Date().setUTCHours(23, 5, 0, 0)).toISOString(),
        eventSource: 'signin.amazonaws.com',
        eventName: 'ConsoleLogin',
        awsRegion: 'us-east-1',
        sourceIPAddress: '45.227.254.12',
        userAgent: 'Mozilla/5.0',
        additionalEventData: {
          MFAUsed: 'No'
        },
        responseElements: {
          ConsoleLogin: 'Success'
        }
      }
    ]
  };

  try {
    await s3Client.send(new PutObjectCommand({
      Bucket: 'cloudtrail-logs',
      Key: 'CloudTrail/us-east-1/2026/05/25/mock_trail_01.json',
      Body: JSON.stringify(logs, null, 2),
      ContentType: 'application/json'
    }));
    console.log('[✓] Simulated CloudTrail logs uploaded successfully.');
  } catch (err) {
    console.error('[✗] Failed to upload CloudTrail logs:', err.message);
  }

  // 6. Publish real-time boundary breach alert via SNS
  console.log('[*] Publishing boundary breach SNS message...');
  try {
    const listRes = await snsClient.send(new ListTopicsCommand({}));
    const topicArn = listRes.Topics?.[0]?.TopicArn;

    if (topicArn) {
      const breachMsg = {
        alertId: `sns-breach-${Date.now()}`,
        timestamp: new Date().toISOString(),
        type: 'UNAUTHORIZED_ACCESS',
        severity: 'CRITICAL',
        resource: '185.220.101.5',
        detail: 'Application origin direct bypass: incoming request from untrusted public IP 185.220.101.5 did not contain valid CloudFront origin verification headers.'
      };
      
      await snsClient.send(new PublishCommand({
        TopicArn: topicArn,
        Message: JSON.stringify(breachMsg)
      }));
      console.log('[✓] Real-time SNS breach message published.');
    } else {
      console.log('[-] No SNS topics found to publish to.');
    }
  } catch (err) {
    console.error('[✗] Failed to publish SNS message:', err.message);
  }

  // 7. Wait 12 seconds for LocalStack Lambda containers to move from Pending to Active state
  console.log('[*] Waiting 12 seconds for Lambda containers to become active...');
  await new Promise(resolve => setTimeout(resolve, 12000));
  console.log('[*] Invoking scanner and detector Lambdas to run initial scans...');
  const scanners = ['s3-scanner', 'iam-detector', 'suspicious-login'];
  for (const name of scanners) {
    try {
      await lambdaClient.send(new InvokeCommand({
        FunctionName: name
      }));
      console.log(`[✓] Lambda function "${name}" invoked successfully.`);
    } catch (err) {
      console.error(`[✗] Failed to invoke Lambda "${name}":`, err.message);
    }
  }

  console.log('==================================================');
  console.log('  [✓] Simulation completed successfully!         ');
  console.log('==================================================');
}

main().catch(err => {
  console.error('Fatal error during simulation:', err);
  process.exit(1);
});

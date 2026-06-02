const { S3Client, CreateBucketCommand, PutBucketWebsiteCommand, PutBucketPolicyCommand, PutBucketEncryptionCommand, PutBucketVersioningCommand, PutObjectCommand, PutBucketAclCommand } = require('@aws-sdk/client-s3');
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
  console.log('  CloudSentinel - Premium Security Event Simulator');
  console.log('==================================================');

  // --- PART 1: S3 BUCKETS SETUP ---
  console.log('[*] Provisioning S3 buckets...');

  // 1. public-assets-static-website (Public website)
  try {
    await s3Client.send(new CreateBucketCommand({ Bucket: 'public-assets-static-website' }));
    await s3Client.send(new PutBucketWebsiteCommand({
      Bucket: 'public-assets-static-website',
      WebsiteConfiguration: { IndexDocument: { Suffix: 'index.html' } }
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
    console.log('[✓] Bucket "public-assets-static-website" created (Vulnerable: Public Policy).');
  } catch (err) {
    console.log('[-] Bucket "public-assets-static-website" already exists or error:', err.message);
  }

  // 2. prod-finance-customer-data (CRITICAL VULNERABILITY: Public Read/Write Allowed)
  try {
    await s3Client.send(new CreateBucketCommand({ Bucket: 'prod-finance-customer-data' }));
    const policy = {
      Version: '2012-10-17',
      Statement: [{
        Effect: 'Allow',
        Principal: '*',
        Action: ['s3:GetObject', 's3:PutObject'],
        Resource: 'arn:aws:s3:::prod-finance-customer-data/*'
      }]
    };
    await s3Client.send(new PutBucketPolicyCommand({
      Bucket: 'prod-finance-customer-data',
      Policy: JSON.stringify(policy)
    }));
    console.log('[✓] Bucket "prod-finance-customer-data" created (CRITICAL: Public Policy R/W).');
  } catch (err) {
    console.log('[-] Bucket "prod-finance-customer-data" already exists or error:', err.message);
  }

  // 3. stage-web-frontend-cache (HIGH VULNERABILITY: Public ACL enabled)
  try {
    await s3Client.send(new CreateBucketCommand({ Bucket: 'stage-web-frontend-cache' }));
    await s3Client.send(new PutBucketAclCommand({
      Bucket: 'stage-web-frontend-cache',
      ACL: 'public-read'
    }));
    console.log('[✓] Bucket "stage-web-frontend-cache" created (Vulnerable: Public Read ACL).');
  } catch (err) {
    console.log('[-] Bucket "stage-web-frontend-cache" already exists or error:', err.message);
  }

  // 4. secure-customer-pii-kms (Compliant)
  try {
    await s3Client.send(new CreateBucketCommand({ Bucket: 'secure-customer-pii-kms' }));
    await s3Client.send(new PutBucketEncryptionCommand({
      Bucket: 'secure-customer-pii-kms',
      ServerSideEncryptionConfiguration: {
        Rules: [{ ApplyServerSideEncryptionByDefault: { SSEAlgorithm: 'aws:kms' } }]
      }
    }));
    await s3Client.send(new PutBucketVersioningCommand({
      Bucket: 'secure-customer-pii-kms',
      VersioningConfiguration: { Status: 'Enabled' }
    }));
    console.log('[✓] Bucket "secure-customer-pii-kms" created (Compliant: KMS & Versioning).');
  } catch (err) {
    console.log('[-] Bucket "secure-customer-pii-kms" already exists or error:', err.message);
  }


  // --- PART 2: IAM IDENTITY PROVISIONING ---
  console.log('\n[*] Provisioning IAM Users...');

  // 1. junior-dev (Direct Admin Policy, No MFA)
  try {
    await iamClient.send(new CreateUserCommand({ UserName: 'junior-dev' }));
    await iamClient.send(new AttachUserPolicyCommand({
      UserName: 'junior-dev',
      PolicyArn: 'arn:aws:iam::aws:policy/AdministratorAccess'
    }));
    console.log('[✓] IAM user "junior-dev" created (Vulnerable: Direct Admin, No MFA).');
  } catch (err) {
    console.log('[-] IAM user "junior-dev" already exists or error:', err.message);
  }

  // 2. contractor-auditor (CRITICAL: Direct Admin Policy, No MFA)
  try {
    await iamClient.send(new CreateUserCommand({ UserName: 'contractor-auditor' }));
    await iamClient.send(new AttachUserPolicyCommand({
      UserName: 'contractor-auditor',
      PolicyArn: 'arn:aws:iam::aws:policy/AdministratorAccess'
    }));
    console.log('[✓] IAM user "contractor-auditor" created (Vulnerable: Direct Admin, No MFA).');
  } catch (err) {
    console.log('[-] IAM user "contractor-auditor" already exists or error:', err.message);
  }

  // 3. temp-deployer (HIGH: direct AdministratorAccess attached, no MFA)
  try {
    await iamClient.send(new CreateUserCommand({ UserName: 'temp-deployer' }));
    await iamClient.send(new AttachUserPolicyCommand({
      UserName: 'temp-deployer',
      PolicyArn: 'arn:aws:iam::aws:policy/AdministratorAccess'
    }));
    console.log('[✓] IAM user "temp-deployer" created (Vulnerable: Direct Admin, No MFA).');
  } catch (err) {
    console.log('[-] IAM user "temp-deployer" already exists or error:', err.message);
  }

  // 4. john-doe (Compliant User)
  try {
    await iamClient.send(new CreateUserCommand({ UserName: 'john-doe' }));
    const mfaRes = await iamClient.send(new CreateVirtualMFADeviceCommand({ VirtualMFADeviceName: 'john-doe-mfa' }));
    const serial = mfaRes.VirtualMFADevice?.SerialNumber;
    if (serial) {
      await iamClient.send(new EnableMFADeviceCommand({
        UserName: 'john-doe',
        SerialNumber: serial,
        AuthenticationCode1: '123456',
        AuthenticationCode2: '654321'
      }));
    }
    console.log('[✓] IAM user "john-doe" created (Compliant: MFA Active).');
  } catch (err) {
    console.log('[-] IAM user "john-doe" already exists or error:', err.message);
  }


  // --- PART 3: CLOUDTRAIL COMPREHENSIVE LOGS GENERATION ---
  console.log('\n[*] Generating comprehensive CloudTrail log suite in S3...');
  const logs = {
    Records: [
      // 1. CRITICAL: ConsoleLogin by AWS Root Account from unexpected IP (Tor node)
      {
        eventVersion: '1.08',
        userIdentity: {
          type: 'Root',
          principalId: '000000000000',
          arn: 'arn:aws:iam::000000000000:root',
          accountId: '000000000000'
        },
        eventTime: new Date(Date.now() - 5 * 60000).toISOString(),
        eventSource: 'signin.amazonaws.com',
        eventName: 'ConsoleLogin',
        awsRegion: 'us-east-1',
        sourceIPAddress: '185.220.101.5',
        userAgent: 'Mozilla/5.0 (Tor Exit Node)',
        additionalEventData: { MFAUsed: 'No' },
        responseElements: { ConsoleLogin: 'Success' }
      },
      // 2. HIGH: junior-dev calling iam:PassRole (Privilege Escalation indicator)
      {
        eventVersion: '1.08',
        userIdentity: {
          type: 'IAMUser',
          principalId: 'AIDAJKNDFSKNDF',
          arn: 'arn:aws:iam::000000000000:user/junior-dev',
          accountId: '000000000000',
          userName: 'junior-dev'
        },
        eventTime: new Date(Date.now() - 10 * 60000).toISOString(),
        eventSource: 'iam.amazonaws.com',
        eventName: 'PassRole',
        awsRegion: 'us-east-1',
        sourceIPAddress: '198.51.100.42',
        userAgent: 'aws-cli',
        requestParameters: {
          roleArn: 'arn:aws:iam::000000000000:role/AdministratorAccessRole'
        }
      },
      // 3. HIGH: AccessDenied error for untrusted-actor attempting s3:GetObject on secure bucket
      {
        eventVersion: '1.08',
        userIdentity: {
          type: 'IAMUser',
          principalId: 'AIDAPDFJDFNDF',
          arn: 'arn:aws:iam::000000000000:user/untrusted-actor',
          accountId: '000000000000',
          userName: 'untrusted-actor'
        },
        eventTime: new Date(Date.now() - 15 * 60000).toISOString(),
        eventSource: 's3.amazonaws.com',
        eventName: 'GetObject',
        awsRegion: 'us-east-1',
        sourceIPAddress: '203.0.113.85',
        userAgent: 'aws-cli',
        errorCode: 'AccessDenied',
        errorMessage: 'Access Denied by bucket policy boundaries',
        requestParameters: {
          bucketName: 'secure-customer-pii-kms',
          key: 'corporate_salaries.xlsx'
        }
      },
      // 4. MEDIUM: junior-dev modifying policies directly (security risk)
      {
        eventVersion: '1.08',
        userIdentity: {
          type: 'IAMUser',
          principalId: 'AIDAJKNDFSKNDF',
          arn: 'arn:aws:iam::000000000000:user/junior-dev',
          accountId: '000000000000',
          userName: 'junior-dev'
        },
        eventTime: new Date(Date.now() - 25 * 60000).toISOString(),
        eventSource: 'iam.amazonaws.com',
        eventName: 'AttachUserPolicy',
        awsRegion: 'us-east-1',
        sourceIPAddress: '198.51.100.42',
        userAgent: 'aws-cli',
        requestParameters: {
          userName: 'junior-dev',
          policyArn: 'arn:aws:iam::aws:policy/AdministratorAccess'
        }
      },
      // 5. HIGH: DeleteFlowLogs (Network evasion attempt by untrusted-actor!)
      {
        eventVersion: '1.08',
        userIdentity: {
          type: 'IAMUser',
          principalId: 'AIDAPDFJDFNDF',
          arn: 'arn:aws:iam::000000000000:user/untrusted-actor',
          accountId: '000000000000',
          userName: 'untrusted-actor'
        },
        eventTime: new Date(Date.now() - 30 * 60000).toISOString(),
        eventSource: 'ec2.amazonaws.com',
        eventName: 'DeleteFlowLogs',
        awsRegion: 'us-east-1',
        sourceIPAddress: '203.0.113.85',
        userAgent: 'aws-cli',
        errorCode: 'UnauthorizedOperation',
        errorMessage: 'User is not authorized to delete network flow logs',
        requestParameters: {
          flowLogIds: ['fl-0123456789abcdef0']
        }
      },
      // 6. MEDIUM: Off-hours login without MFA by contractor-auditor
      {
        eventVersion: '1.08',
        userIdentity: {
          type: 'IAMUser',
          principalId: 'AIDAJKNDFSCONTR',
          arn: 'arn:aws:iam::000000000000:user/contractor-auditor',
          accountId: '000000000000',
          userName: 'contractor-auditor'
        },
        eventTime: new Date(new Date().setUTCHours(2, 15, 0, 0)).toISOString(),
        eventSource: 'signin.amazonaws.com',
        eventName: 'ConsoleLogin',
        awsRegion: 'us-east-1',
        sourceIPAddress: '45.227.254.12',
        userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
        additionalEventData: { MFAUsed: 'No' },
        responseElements: { ConsoleLogin: 'Success' }
      },
      // 7. LOW: Standard list buckets call from john-doe
      {
        eventVersion: '1.08',
        userIdentity: {
          type: 'IAMUser',
          principalId: 'AIDAJKNDFSJOHN',
          arn: 'arn:aws:iam::000000000000:user/john-doe',
          accountId: '000000000000',
          userName: 'john-doe'
        },
        eventTime: new Date(Date.now() - 40 * 60000).toISOString(),
        eventSource: 's3.amazonaws.com',
        eventName: 'ListBuckets',
        awsRegion: 'us-east-1',
        sourceIPAddress: '127.0.0.1',
        userAgent: 'aws-sdk-js'
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
    console.log('[✓] Massive CloudTrail log suite uploaded successfully.');
  } catch (err) {
    console.error('[✗] Failed to upload CloudTrail logs:', err.message);
  }


  // --- PART 4: MULTIPLE REAL-TIME BOUNDARY BREACH SNS MESSAGES ---
  console.log('\n[*] Publishing boundary breach alerts to SNS queue...');
  try {
    const listRes = await snsClient.send(new ListTopicsCommand({}));
    const topicArn = listRes.Topics?.[0]?.TopicArn;

    if (topicArn) {
      // Alert 1: Direct ALB Origin Bypass
      const breachMsg1 = {
        alertId: `sns-breach-alb-${Date.now()}`,
        timestamp: new Date(Date.now() - 2000).toISOString(),
        type: 'UNAUTHORIZED_ACCESS',
        severity: 'CRITICAL',
        resource: '185.220.101.5',
        detail: 'ALB direct bypass: HTTP request from TOR address 185.220.101.5 directly reached the back-end Application Load Balancer without passing through the CloudFront WAF origin shield.'
      };
      await snsClient.send(new PublishCommand({ TopicArn: topicArn, Message: JSON.stringify(breachMsg1) }));

      // Alert 2: SQL Injection Attack Blocked
      const breachMsg2 = {
        alertId: `sns-breach-sqli-${Date.now()}`,
        timestamp: new Date(Date.now() - 5000).toISOString(),
        type: 'UNAUTHORIZED_ACCESS',
        severity: 'HIGH',
        resource: '198.51.100.99',
        detail: 'SQL Injection detected: CloudFront Web Application Firewall (WAF) blocked a SQLi payload request containing `SELECT * FROM users;` in request headers from IP 198.51.100.99.'
      };
      await snsClient.send(new PublishCommand({ TopicArn: topicArn, Message: JSON.stringify(breachMsg2) }));

      // Alert 3: Bruteforce SSH attack
      const breachMsg3 = {
        alertId: `sns-breach-ssh-${Date.now()}`,
        timestamp: new Date(Date.now() - 10000).toISOString(),
        type: 'UNAUTHORIZED_ACCESS',
        severity: 'HIGH',
        resource: '203.0.113.111',
        detail: 'SSH brute force detected: Bastion host logged 45 failed SSH login attempts for user root in 30 seconds from public IP 203.0.113.111.'
      };
      await snsClient.send(new PublishCommand({ TopicArn: topicArn, Message: JSON.stringify(breachMsg3) }));

      console.log('[✓] Multiple live boundary breach SNS alerts published to SQS queues.');
    } else {
      console.log('[-] No SNS topics found to publish to.');
    }
  } catch (err) {
    console.error('[✗] Failed to publish SNS messages:', err.message);
  }


  // --- PART 5: EXECUTE LAMBDA SCAN SWEEPS ---
  console.log('\n[*] Waiting 5 seconds for SNS/SQS alert propagation...');
  await new Promise(resolve => setTimeout(resolve, 5000));

  console.log('[*] Invoking scanner Lambdas to record these events into DynamoDB...');
  const scanners = ['s3-scanner', 'iam-detector', 'suspicious-login', 'unauth-detector'];
  for (const name of scanners) {
    try {
      await lambdaClient.send(new InvokeCommand({ FunctionName: name }));
      console.log(`[✓] Lambda function "${name}" successfully scanned LocalStack.`);
    } catch (err) {
      console.error(`[✗] Failed to invoke Lambda "${name}":`, err.message);
    }
  }

  console.log('\n==================================================');
  console.log('  [✓] All complex events successfully simulated!');
  console.log('==================================================');
}

main().catch(err => {
  console.error('Fatal error during simulation:', err);
  process.exit(1);
});

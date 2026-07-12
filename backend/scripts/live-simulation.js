const { S3Client, CreateBucketCommand, PutBucketWebsiteCommand, PutBucketPolicyCommand, PutBucketAclCommand } = require('@aws-sdk/client-s3');
const { IAMClient, CreateUserCommand, AttachUserPolicyCommand, CreateVirtualMFADeviceCommand, EnableMFADeviceCommand } = require('@aws-sdk/client-iam');
const { SNSClient, ListTopicsCommand, PublishCommand } = require('@aws-sdk/client-sns');
const { LambdaClient, InvokeCommand } = require('@aws-sdk/client-lambda');
const { DynamoDBClient, ScanCommand, DeleteItemCommand } = require('@aws-sdk/client-dynamodb');
const { sendCriticalAlert } = require('../middleware/emailNotifier');

const ENDPOINT = 'http://localhost:4566';
const REGION = 'us-east-1';

const clientConfig = {
  endpoint: ENDPOINT,
  region: REGION,
  credentials: { accessKeyId: 'test', secretAccessKey: 'test' },
  forcePathStyle: true
};

const s3Client = new S3Client(clientConfig);
const iamClient = new IAMClient(clientConfig);
const snsClient = new SNSClient(clientConfig);
const lambdaClient = new LambdaClient(clientConfig);
const ddbClient = new DynamoDBClient(clientConfig);

// Helper to clear existing alerts in DynamoDB
async function clearSecurityAlerts() {
  console.log('\n🧹 [1/3] Sweeping DynamoDB database clean...');
  try {
    const scanRes = await ddbClient.send(new ScanCommand({ TableName: 'SecurityAlerts' }));
    const items = scanRes.Items || [];
    console.log(`[*] Found ${items.length} old alerts. Deleting...`);
    
    for (const item of items) {
      await ddbClient.send(new DeleteItemCommand({
        TableName: 'SecurityAlerts',
        Key: {
          alertId: item.alertId,
          timestamp: item.timestamp
        }
      }));
    }
    console.log('[✓] Database is now 100% clean!');
  } catch (err) {
    console.error('[-] Failed to clear alerts:', err.message);
  }
}

// Helper to remove existing IAM users so we can recreate them clean
async function clearExistingIamUsers() {
  console.log('🧹 [2/3] Cleaning up old IAM users...');
  const users = ['junior-dev', 'contractor-auditor', 'temp-deployer', 'john-doe'];
  for (const user of users) {
    try {
      // In LocalStack we can force delete or recreate.
      // We will try to delete attached policies first
      const { DetachUserPolicyCommand, DeleteVirtualMFADeviceCommand, DeleteUserCommand } = require('@aws-sdk/client-iam');
      
      try {
        await iamClient.send(new DetachUserPolicyCommand({
          UserName: user,
          PolicyArn: 'arn:aws:iam::aws:policy/AdministratorAccess'
        }));
      } catch (e) {}

      try {
        await iamClient.send(new DeleteVirtualMFADeviceCommand({
          SerialNumber: `arn:aws:iam::000000000000:mfa/${user}-mfa`
        }));
      } catch (e) {}

      await iamClient.send(new DeleteUserCommand({ UserName: user }));
    } catch (e) {}
  }
  console.log('[✓] Pre-existing simulated users wiped.');
}

// Helper to remove existing S3 buckets
async function clearBuckets() {
  console.log('🧹 [3/3] Deleting previous simulated S3 buckets...');
  const buckets = ['prod-finance-customer-data', 'stage-web-frontend-cache', 'public-assets-static-website', 'secure-customer-pii-kms'];
  for (const b of buckets) {
    try {
      const { DeleteBucketPolicyCommand, DeleteBucketCommand } = require('@aws-sdk/client-s3');
      try { await s3Client.send(new DeleteBucketPolicyCommand({ Bucket: b })); } catch (e) {}
      await s3Client.send(new DeleteBucketCommand({ Bucket: b }));
    } catch (e) {}
  }
  console.log('[✓] Bucket cleanup complete.');
}

// Run scanner Lambdas
async function invokeScanners() {
  console.log('   🔍 Running background scanner Lambdas...');
  const scanners = ['s3-scanner', 'iam-detector', 'suspicious-login', 'unauth-detector'];
  for (const name of scanners) {
    try {
      await lambdaClient.send(new InvokeCommand({ FunctionName: name }));
    } catch (err) {
      console.error(`   [✗] Scanner "${name}" failed:`, err.message);
    }
  }
}

// Sleep utility
const delay = ms => new Promise(resolve => setTimeout(resolve, ms));

async function main() {
  console.log('==================================================');
  console.log('  CloudSentinel - Live Delayed Telemetry Simulator');
  console.log('==================================================');

  // Clear everything to start with an exciting 0-alert baseline
  await clearSecurityAlerts();
  await clearExistingIamUsers();
  await clearBuckets();

  // Baseline setup
  console.log('\n🟢 Starting Live Streaming Scenario in 3 seconds...');
  await delay(3000);

  // --- STAGE 1 ---
  console.log('\n📢 [STAGE 1] Creating secure baseline S3 buckets...');
  try {
    await s3Client.send(new CreateBucketCommand({ Bucket: 'secure-customer-pii-kms' }));
    await s3Client.send(new CreateBucketCommand({ Bucket: 'cloudtrail-logs' }));
    console.log('[✓] Provisioned compliant bucket: secure-customer-pii-kms');
    console.log('[✓] Provisioned audit trail bucket: cloudtrail-logs');
  } catch (e) {}

  await invokeScanners();
  console.log('⚡ Check your dashboard: State is clean (0 anomalies).');
  console.log('🕒 Waiting 6 seconds before triggering next threat event...');
  await delay(6000);

  // --- STAGE 2 ---
  console.log('\n🚨 [STAGE 2] Vulnerability Event: junior-dev backdoor created!');
  try {
    await iamClient.send(new CreateUserCommand({ UserName: 'junior-dev' }));
    await iamClient.send(new AttachUserPolicyCommand({
      UserName: 'junior-dev',
      PolicyArn: 'arn:aws:iam::aws:policy/AdministratorAccess'
    }));
    console.log('[✓] Created IAM user "junior-dev" with direct AdministratorAccess attached.');
  } catch (e) {}

  await invokeScanners();
  console.log('⚡ Dashboard action: Go to "IAM Misuse". You should see "junior-dev" flagged as Non-Compliant!');
  console.log('🕒 Waiting 6 seconds before triggering next threat event...');
  await delay(6000);

  // --- STAGE 3 ---
  console.log('\n🚨 [STAGE 3] Vulnerability Event: Critical S3 bucket public policy breach!');
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
    console.log('[✓] Created bucket "prod-finance-customer-data" with public Read/Write policy.');
  } catch (e) {}

  await invokeScanners();
  console.log('⚡ Dashboard action: Go to "Overview" or "S3 Scanner". Look at the critical open policy alarm!');
  console.log('🕒 Waiting 6 seconds before triggering next threat event...');
  await delay(6000);

  // --- STAGE 4 ---
  console.log('\n🚨 [STAGE 4] Attack Event: TOR Node direct access boundary bypass alert!');
  try {
    const listRes = await snsClient.send(new ListTopicsCommand({}));
    const topicArn = listRes.Topics?.[0]?.TopicArn;
    if (topicArn) {
      const breachMsg = {
        alertId: `sns-breach-alb-${Date.now()}`,
        timestamp: new Date().toISOString(),
        type: 'UNAUTHORIZED_ACCESS',
        severity: 'CRITICAL',
        resource: '185.220.101.5',
        detail: 'ALB direct bypass: HTTP request from TOR address 185.220.101.5 directly reached the back-end Application Load Balancer without passing through the CloudFront WAF origin shield.'
      };
      await snsClient.send(new PublishCommand({ TopicArn: topicArn, Message: JSON.stringify(breachMsg) }));
      console.log('[✓] SNS breach notification sent. SQS event mapping triggered unauth-detector.');
    }
  } catch (e) {}

  await invokeScanners();
  console.log('⚡ Dashboard action: View your notification alerts in "Overview" and the terminal log stream!');
  console.log('🕒 Waiting 6 seconds before triggering next threat event...');
  await delay(6000);

  // --- STAGE 5 ---
  console.log('\n🚨 [STAGE 5] Intrusion Event: Hacker attempts to steal corporate files (Access Denied logged)!');
  try {
    const logs = {
      Records: [
        {
          eventVersion: '1.08',
          userIdentity: {
            type: 'IAMUser',
            principalId: 'AIDAPDFJDFNDF',
            arn: 'arn:aws:iam::000000000000:user/untrusted-actor',
            accountId: '000000000000',
            userName: 'untrusted-actor'
          },
          eventTime: new Date().toISOString(),
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
        }
      ]
    };
    const { PutObjectCommand } = require('@aws-sdk/client-s3');
    await s3Client.send(new PutObjectCommand({
      Bucket: 'cloudtrail-logs',
      Key: 'CloudTrail/us-east-1/2026/05/25/live_trail_01.json',
      Body: JSON.stringify(logs, null, 2),
      ContentType: 'application/json'
    }));
    console.log('[✓] Wrote AccessDenied audit trail logs to S3 cloudtrail-logs bucket.');
  } catch (e) {}

  await invokeScanners();
  console.log('⚡ Dashboard action: Go to "AWS Logs" tab. Switch to CloudTrail. The failed GetObject logs are now streamed!');
  console.log('🕒 Waiting 6 seconds before triggering next threat event...');
  await delay(6000);

  // --- STAGE 6 ---
  console.log('\n🚨 [STAGE 6] Attack Event: SQL Injection attempt blocked by WAF!');
  try {
    const listRes = await snsClient.send(new ListTopicsCommand({}));
    const topicArn = listRes.Topics?.[0]?.TopicArn;
    if (topicArn) {
      const breachMsg = {
        alertId: `sns-breach-sqli-${Date.now()}`,
        timestamp: new Date().toISOString(),
        type: 'UNAUTHORIZED_ACCESS',
        severity: 'HIGH',
        resource: '198.51.100.99',
        detail: 'SQL Injection detected: CloudFront Web Application Firewall (WAF) blocked a SQLi payload request containing `SELECT * FROM users;` in request headers from IP 198.51.100.99.'
      };
      await snsClient.send(new PublishCommand({ TopicArn: topicArn, Message: JSON.stringify(breachMsg) }));
      console.log('[✓] SQL Injection WAF alarm dispatched.');
    }
  } catch (e) {}

  await invokeScanners();
  console.log('⚡ Dashboard action: Look at the WAF alert popup on your dashboard!');
  console.log('🕒 Waiting 6 seconds before triggering next threat event...');
  await delay(6000);

  // --- STAGE 7 ---
  console.log('\n🚨 [STAGE 7] Vulnerability Event: auditor bypass backdoor installed!');
  try {
    await iamClient.send(new CreateUserCommand({ UserName: 'contractor-auditor' }));
    await iamClient.send(new AttachUserPolicyCommand({
      UserName: 'contractor-auditor',
      PolicyArn: 'arn:aws:iam::aws:policy/AdministratorAccess'
    }));
    console.log('[✓] Created backdoor IAM user "contractor-auditor" with direct admin rights.');
  } catch (e) {}

  await invokeScanners();
  console.log('⚡ Dashboard action: Look at the IAM posture card for "contractor-auditor"!');
  console.log('🕒 Waiting 6 seconds before triggering next threat event...');
  await delay(6000);

  // --- STAGE 8 ---
  console.log('\n🚨 [STAGE 8] Vulnerability Event: Public S3 bucket ACL exposed!');
  try {
    await s3Client.send(new CreateBucketCommand({ Bucket: 'stage-web-frontend-cache' }));
    await s3Client.send(new PutBucketAclCommand({
      Bucket: 'stage-web-frontend-cache',
      ACL: 'public-read'
    }));
    console.log('[✓] Configured public Read ACL on "stage-web-frontend-cache".');
  } catch (e) {}

  await invokeScanners();
  console.log('⚡ Dashboard action: A new public Read ACL violation is registered!');
  console.log('🕒 Waiting 6 seconds before triggering next threat event...');
  await delay(6000);

  // --- STAGE 9 ---
  console.log('\n🚨 [STAGE 9] Direct Email Notification Test!');
  try {
    const testAlert = {
      alertId:   `live-test-${Date.now()}`,
      timestamp: new Date().toISOString(),
      type:      'DIRECT_EMAIL_TEST',
      severity:  'CRITICAL',
      resource:  'live-simulation-script',
      detail:    'This is a direct test of the email notification system from the live simulation script.',
      status:    'OPEN'
    };
    await sendCriticalAlert(testAlert);
    console.log('[✓] Dispatched test alert email via Resend.');
  } catch (e) {
    console.error('[✗] Failed to send test alert email:', e);
  }

  console.log('\n==================================================');
  console.log('  🏁 [✓] Live Delayed Stream Simulation Completed!');
  console.log('==================================================');
}

main().catch(err => {
  console.error('Fatal error during simulation:', err);
  process.exit(1);
});

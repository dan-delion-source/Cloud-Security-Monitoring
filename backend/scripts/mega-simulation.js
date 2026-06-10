const { S3Client, CreateBucketCommand, PutBucketPolicyCommand, PutBucketAclCommand, PutBucketWebsiteCommand, PutBucketEncryptionCommand, PutBucketVersioningCommand, PutObjectCommand, DeleteBucketPolicyCommand, DeleteBucketCommand } = require('@aws-sdk/client-s3');
const { IAMClient, CreateUserCommand, AttachUserPolicyCommand, CreateVirtualMFADeviceCommand, EnableMFADeviceCommand, DetachUserPolicyCommand, DeleteVirtualMFADeviceCommand, DeleteUserCommand } = require('@aws-sdk/client-iam');
const { SNSClient, ListTopicsCommand, PublishCommand } = require('@aws-sdk/client-sns');
const { LambdaClient, InvokeCommand } = require('@aws-sdk/client-lambda');
const { DynamoDBClient, ScanCommand, DeleteItemCommand } = require('@aws-sdk/client-dynamodb');

const ENDPOINT = 'http://localhost:4566';
const cfg = { endpoint: ENDPOINT, region: 'us-east-1', credentials: { accessKeyId: 'test', secretAccessKey: 'test' }, forcePathStyle: true };
const s3 = new S3Client(cfg), iam = new IAMClient(cfg), sns = new SNSClient(cfg), lambda = new LambdaClient(cfg), ddb = new DynamoDBClient(cfg);
const delay = ms => new Promise(r => setTimeout(r, ms));
const safe = async (fn) => { try { await fn(); } catch(e) {} };

// ── Threat actor IP pool (realistic hostile IPs) ─────────────────────────────
const THREAT_IPS = [
  '185.220.101.5',   // Known Tor exit
  '198.51.100.42',   // Suspicious VPN
  '203.0.113.85',    // Scanner bot
  '45.227.254.12',   // South American proxy
  '103.152.220.44',  // APAC bulletproof host
  '91.219.236.174',  // Eastern European relay
  '23.129.64.201',   // US Tor relay
  '104.244.76.13',   // Hosting provider abuse
  '176.10.99.200',   // Swiss privacy VPN
  '162.247.74.206',  // Tor project exit
  '209.141.58.178',  // Known brute-forcer
  '77.247.181.163',  // NL anonymizer
];

const THREAT_AGENTS = [
  'Mozilla/5.0 (Tor Exit Node)',
  'python-requests/2.31.0',
  'aws-cli/2.15.0 Python/3.11.8',
  'Boto3/1.34.0 Python/3.12.1',
  'curl/8.4.0',
  'Nuclei v3.1.0',
  'sqlmap/1.8',
  'Go-http-client/2.0',
];

// ── Cleanup ──────────────────────────────────────────────────────────────────
async function cleanup() {
  console.log('\n🧹 Phase 0: Cleaning previous simulation state...');
  // Clear DynamoDB
  try {
    const res = await ddb.send(new ScanCommand({ TableName: 'SecurityAlerts' }));
    for (const item of (res.Items || [])) {
      await ddb.send(new DeleteItemCommand({ TableName: 'SecurityAlerts', Key: { alertId: item.alertId, timestamp: item.timestamp } }));
    }
  } catch(e) {}

  // Clear IAM users
  const users = ['junior-dev','contractor-auditor','temp-deployer','john-doe','sec-auditor','extern-consultant','ci-bot-user','data-engineer','staging-admin','root-backup'];
  for (const u of users) {
    await safe(() => iam.send(new DetachUserPolicyCommand({ UserName: u, PolicyArn: 'arn:aws:iam::aws:policy/AdministratorAccess' })));
    await safe(() => iam.send(new DetachUserPolicyCommand({ UserName: u, PolicyArn: 'arn:aws:iam::aws:policy/AmazonEC2ReadOnlyAccess' })));
    await safe(() => iam.send(new DetachUserPolicyCommand({ UserName: u, PolicyArn: 'arn:aws:iam::aws:policy/SecurityAudit' })));
    await safe(() => iam.send(new DeleteVirtualMFADeviceCommand({ SerialNumber: `arn:aws:iam::000000000000:mfa/${u}-mfa` })));
    await safe(() => iam.send(new DeleteUserCommand({ UserName: u })));
  }

  // Clear S3 buckets
  const buckets = ['prod-finance-customer-data','stage-web-frontend-cache','public-assets-static-website','secure-customer-pii-kms','dev-internal-artifacts','backup-db-snapshots','ml-training-datasets','logs-archive-2024','api-media-uploads','compliance-audit-reports'];
  for (const b of buckets) {
    await safe(() => s3.send(new DeleteBucketPolicyCommand({ Bucket: b })));
    await safe(() => s3.send(new DeleteBucketCommand({ Bucket: b })));
  }
  console.log('[✓] Cleanup complete.\n');
}

// ── Invoke all scanner Lambdas ───────────────────────────────────────────────
async function scan() {
  for (const fn of ['s3-scanner','iam-detector','suspicious-login','unauth-detector']) {
    await safe(() => lambda.send(new InvokeCommand({ FunctionName: fn })));
  }
}

// ── S3 Bucket Scenarios (12 buckets) ─────────────────────────────────────────
async function simulateS3Buckets() {
  console.log('📂 Phase 1: Simulating 12 S3 bucket configurations...');
  const vulnBuckets = [
    { name: 'prod-finance-customer-data', vuln: 'Public R/W Policy', policy: { Version:'2012-10-17', Statement:[{ Effect:'Allow', Principal:'*', Action:['s3:GetObject','s3:PutObject'], Resource:'arn:aws:s3:::prod-finance-customer-data/*' }] }},
    { name: 'public-assets-static-website', vuln: 'Public Website + Open Policy', website: true, policy: { Version:'2012-10-17', Statement:[{ Effect:'Allow', Principal:'*', Action:'s3:GetObject', Resource:'arn:aws:s3:::public-assets-static-website/*' }] }},
    { name: 'stage-web-frontend-cache', vuln: 'Public Read ACL', acl: 'public-read' },
    { name: 'dev-internal-artifacts', vuln: 'Public Read-Write ACL', acl: 'public-read-write' },
    { name: 'backup-db-snapshots', vuln: 'Wildcard Policy Delete', policy: { Version:'2012-10-17', Statement:[{ Effect:'Allow', Principal:'*', Action:['s3:GetObject','s3:DeleteObject'], Resource:'arn:aws:s3:::backup-db-snapshots/*' }] }},
    { name: 'ml-training-datasets', vuln: 'Public List + Get', policy: { Version:'2012-10-17', Statement:[{ Effect:'Allow', Principal:'*', Action:['s3:ListBucket','s3:GetObject'], Resource:['arn:aws:s3:::ml-training-datasets','arn:aws:s3:::ml-training-datasets/*'] }] }},
    { name: 'api-media-uploads', vuln: 'Public Put Allowed', policy: { Version:'2012-10-17', Statement:[{ Effect:'Allow', Principal:'*', Action:'s3:PutObject', Resource:'arn:aws:s3:::api-media-uploads/*' }] }},
  ];

  const secureBuckets = [
    { name: 'secure-customer-pii-kms', kms: true, versioning: true },
    { name: 'logs-archive-2024', kms: true, versioning: true },
    { name: 'compliance-audit-reports', kms: true, versioning: true },
  ];

  for (const b of vulnBuckets) {
    await safe(async () => {
      await s3.send(new CreateBucketCommand({ Bucket: b.name }));
      if (b.website) await s3.send(new PutBucketWebsiteCommand({ Bucket: b.name, WebsiteConfiguration: { IndexDocument: { Suffix: 'index.html' } } }));
      if (b.policy) await s3.send(new PutBucketPolicyCommand({ Bucket: b.name, Policy: JSON.stringify(b.policy) }));
      if (b.acl) await s3.send(new PutBucketAclCommand({ Bucket: b.name, ACL: b.acl }));
      console.log(`  🔴 ${b.name} — ${b.vuln}`);
    });
  }

  for (const b of secureBuckets) {
    await safe(async () => {
      await s3.send(new CreateBucketCommand({ Bucket: b.name }));
      if (b.kms) await s3.send(new PutBucketEncryptionCommand({ Bucket: b.name, ServerSideEncryptionConfiguration: { Rules: [{ ApplyServerSideEncryptionByDefault: { SSEAlgorithm: 'aws:kms' } }] } }));
      if (b.versioning) await s3.send(new PutBucketVersioningCommand({ Bucket: b.name, VersioningConfiguration: { Status: 'Enabled' } }));
      console.log(`  🟢 ${b.name} — Compliant (KMS + Versioning)`);
    });
  }
  console.log(`[✓] 12 S3 buckets provisioned.\n`);
}

// ── IAM User Scenarios (10 users) ────────────────────────────────────────────
async function simulateIamUsers() {
  console.log('👤 Phase 2: Simulating 10 IAM user configurations...');
  const users = [
    { name: 'junior-dev',          policy: 'AdministratorAccess', mfa: false, label: 'CRITICAL: Admin + No MFA' },
    { name: 'contractor-auditor',  policy: 'AdministratorAccess', mfa: false, label: 'CRITICAL: Admin + No MFA' },
    { name: 'temp-deployer',       policy: 'AdministratorAccess', mfa: false, label: 'CRITICAL: Admin + No MFA' },
    { name: 'staging-admin',       policy: 'AdministratorAccess', mfa: false, label: 'CRITICAL: Admin + No MFA' },
    { name: 'extern-consultant',   policy: 'AdministratorAccess', mfa: false, label: 'HIGH: External Admin' },
    { name: 'ci-bot-user',         policy: 'AmazonEC2ReadOnlyAccess', mfa: false, label: 'MEDIUM: No MFA' },
    { name: 'data-engineer',       policy: 'AmazonEC2ReadOnlyAccess', mfa: false, label: 'MEDIUM: No MFA' },
    { name: 'root-backup',         policy: 'AdministratorAccess', mfa: false, label: 'CRITICAL: Backup root' },
    { name: 'john-doe',            policy: 'AmazonEC2ReadOnlyAccess', mfa: true, label: 'Compliant' },
    { name: 'sec-auditor',         policy: 'SecurityAudit',       mfa: true, label: 'Compliant' },
  ];

  for (const u of users) {
    await safe(async () => {
      await iam.send(new CreateUserCommand({ UserName: u.name }));
      await iam.send(new AttachUserPolicyCommand({ UserName: u.name, PolicyArn: `arn:aws:iam::aws:policy/${u.policy}` }));
      if (u.mfa) {
        const mfaRes = await iam.send(new CreateVirtualMFADeviceCommand({ VirtualMFADeviceName: `${u.name}-mfa` }));
        const serial = mfaRes.VirtualMFADevice?.SerialNumber;
        if (serial) await iam.send(new EnableMFADeviceCommand({ UserName: u.name, SerialNumber: serial, AuthenticationCode1: '123456', AuthenticationCode2: '654321' }));
      }
      const icon = u.mfa ? '🟢' : '🔴';
      console.log(`  ${icon} ${u.name} — ${u.label}`);
    });
  }
  console.log(`[✓] 10 IAM users provisioned.\n`);
}

// ── CloudTrail Log Records (15 events) ───────────────────────────────────────
async function simulateCloudTrailLogs() {
  console.log('📋 Phase 3: Generating 15 CloudTrail log events...');

  const mkUser = (type, arn, name) => ({ type, principalId: 'AIDA' + Math.random().toString(36).slice(2,10).toUpperCase(), arn, accountId: '000000000000', ...(name ? { userName: name } : {}) });

  const records = [
    // CRITICAL events
    { userIdentity: mkUser('Root','arn:aws:iam::000000000000:root'), eventName: 'ConsoleLogin', eventSource: 'signin.amazonaws.com', sourceIPAddress: THREAT_IPS[0], userAgent: THREAT_AGENTS[0], additionalEventData: { MFAUsed: 'No' }, responseElements: { ConsoleLogin: 'Success' }, _label: 'Root login from Tor (no MFA)' },
    { userIdentity: mkUser('Root','arn:aws:iam::000000000000:root'), eventName: 'CreateAccessKey', eventSource: 'iam.amazonaws.com', sourceIPAddress: THREAT_IPS[0], userAgent: THREAT_AGENTS[0], _label: 'Root creating access keys' },
    { userIdentity: mkUser('IAMUser','arn:aws:iam::000000000000:user/junior-dev','junior-dev'), eventName: 'PassRole', eventSource: 'iam.amazonaws.com', sourceIPAddress: THREAT_IPS[1], userAgent: THREAT_AGENTS[2], requestParameters: { roleArn: 'arn:aws:iam::000000000000:role/AdministratorAccessRole' }, _label: 'PassRole privilege escalation' },
    { userIdentity: mkUser('IAMUser','arn:aws:iam::000000000000:user/junior-dev','junior-dev'), eventName: 'CreateFunction20150331', eventSource: 'lambda.amazonaws.com', sourceIPAddress: THREAT_IPS[1], userAgent: THREAT_AGENTS[2], requestParameters: { functionName: 'backdoor-exfil' }, _label: 'Backdoor Lambda creation' },
    // HIGH events
    { userIdentity: mkUser('IAMUser','arn:aws:iam::000000000000:user/untrusted-actor','untrusted-actor'), eventName: 'GetObject', eventSource: 's3.amazonaws.com', sourceIPAddress: THREAT_IPS[2], userAgent: THREAT_AGENTS[1], errorCode: 'AccessDenied', errorMessage: 'Access Denied', requestParameters: { bucketName: 'secure-customer-pii-kms', key: 'corporate_salaries.xlsx' }, _label: 'Data theft attempt (denied)' },
    { userIdentity: mkUser('IAMUser','arn:aws:iam::000000000000:user/untrusted-actor','untrusted-actor'), eventName: 'DeleteFlowLogs', eventSource: 'ec2.amazonaws.com', sourceIPAddress: THREAT_IPS[2], userAgent: THREAT_AGENTS[5], errorCode: 'UnauthorizedOperation', _label: 'Flow log deletion (evasion)' },
    { userIdentity: mkUser('IAMUser','arn:aws:iam::000000000000:user/extern-consultant','extern-consultant'), eventName: 'StopLogging', eventSource: 'cloudtrail.amazonaws.com', sourceIPAddress: THREAT_IPS[5], userAgent: THREAT_AGENTS[3], _label: 'CloudTrail logging disabled' },
    { userIdentity: mkUser('IAMUser','arn:aws:iam::000000000000:user/contractor-auditor','contractor-auditor'), eventName: 'ConsoleLogin', eventSource: 'signin.amazonaws.com', sourceIPAddress: THREAT_IPS[3], userAgent: THREAT_AGENTS[0], additionalEventData: { MFAUsed: 'No' }, responseElements: { ConsoleLogin: 'Success' }, _label: 'Off-hours login, no MFA' },
    { userIdentity: mkUser('IAMUser','arn:aws:iam::000000000000:user/staging-admin','staging-admin'), eventName: 'AttachUserPolicy', eventSource: 'iam.amazonaws.com', sourceIPAddress: THREAT_IPS[4], userAgent: THREAT_AGENTS[2], requestParameters: { userName: 'staging-admin', policyArn: 'arn:aws:iam::aws:policy/AdministratorAccess' }, _label: 'Self-privilege escalation' },
    { userIdentity: mkUser('IAMUser','arn:aws:iam::000000000000:user/temp-deployer','temp-deployer'), eventName: 'PutBucketPolicy', eventSource: 's3.amazonaws.com', sourceIPAddress: THREAT_IPS[6], userAgent: THREAT_AGENTS[2], requestParameters: { bucketName: 'prod-finance-customer-data' }, _label: 'Bucket policy override' },
    // MEDIUM events
    { userIdentity: mkUser('IAMUser','arn:aws:iam::000000000000:user/ci-bot-user','ci-bot-user'), eventName: 'RunInstances', eventSource: 'ec2.amazonaws.com', sourceIPAddress: THREAT_IPS[7], userAgent: THREAT_AGENTS[7], _label: 'Unauthorized EC2 launch' },
    { userIdentity: mkUser('IAMUser','arn:aws:iam::000000000000:user/data-engineer','data-engineer'), eventName: 'GetSecretValue', eventSource: 'secretsmanager.amazonaws.com', sourceIPAddress: THREAT_IPS[8], userAgent: THREAT_AGENTS[3], _label: 'Secrets access attempt' },
    { userIdentity: mkUser('AssumedRole','arn:aws:sts::000000000000:assumed-role/ExternalAttacker/session'), eventName: 'AssumeRole', eventSource: 'sts.amazonaws.com', sourceIPAddress: THREAT_IPS[9], userAgent: THREAT_AGENTS[1], requestParameters: { roleArn: 'arn:aws:iam::000000000000:role/OrganizationAccountAccessRole' }, _label: 'Cross-account assume role' },
    // LOW events (normal activity)
    { userIdentity: mkUser('IAMUser','arn:aws:iam::000000000000:user/john-doe','john-doe'), eventName: 'ListBuckets', eventSource: 's3.amazonaws.com', sourceIPAddress: '127.0.0.1', userAgent: 'aws-sdk-js', _label: 'Normal ListBuckets' },
    { userIdentity: mkUser('IAMUser','arn:aws:iam::000000000000:user/sec-auditor','sec-auditor'), eventName: 'DescribeInstances', eventSource: 'ec2.amazonaws.com', sourceIPAddress: '10.0.1.50', userAgent: 'aws-sdk-js', _label: 'Normal audit read' },
  ];

  const formatted = { Records: records.map((r, i) => {
    const { _label, ...event } = r;
    console.log(`  ${i < 4 ? '🔴' : i < 10 ? '🟡' : i < 13 ? '🔵' : '🟢'} [${i+1}/15] ${_label}`);
    return { eventVersion: '1.08', awsRegion: 'us-east-1', eventTime: new Date(Date.now() - (15 - i) * 3 * 60000).toISOString(), ...event };
  })};

  const datePrefix = new Date().toISOString().slice(0,10).replace(/-/g, '/');
  await safe(() => s3.send(new PutObjectCommand({
    Bucket: 'cloudtrail-logs',
    Key: `CloudTrail/us-east-1/${datePrefix}/mega_simulation_${Date.now()}.json`,
    Body: JSON.stringify(formatted, null, 2),
    ContentType: 'application/json'
  })));
  console.log(`[✓] 15 CloudTrail events written to S3.\n`);
}

// ── Unauthorized Access SNS Alerts (12 events) ──────────────────────────────
async function simulateUnauthorizedAccess() {
  console.log('🚨 Phase 4: Publishing 12 unauthorized access alerts via SNS...');
  const listRes = await sns.send(new ListTopicsCommand({}));
  const topicArn = listRes.Topics?.[0]?.TopicArn;
  if (!topicArn) { console.log('[-] No SNS topic found. Skipping.'); return; }

  const alerts = [
    { severity: 'CRITICAL', resource: THREAT_IPS[0],  detail: 'ALB direct bypass: HTTP request from TOR exit node directly hit backend ALB, bypassing CloudFront WAF origin shield.' },
    { severity: 'CRITICAL', resource: THREAT_IPS[9],  detail: 'Direct API Gateway invocation from known Tor relay. WAF geo-restriction bypassed via IPv6 tunnel.' },
    { severity: 'CRITICAL', resource: THREAT_IPS[5],  detail: 'RDP brute-force: 200+ failed login attempts on Windows bastion host ec2-bastion-01 in 60 seconds.' },
    { severity: 'HIGH',     resource: THREAT_IPS[1],  detail: 'SQL Injection: WAF blocked SQLi payload `UNION SELECT * FROM aws_credentials` from suspicious VPN endpoint.' },
    { severity: 'HIGH',     resource: THREAT_IPS[2],  detail: 'Path traversal attack: HTTP request containing `/../../../etc/passwd` blocked at CloudFront edge.' },
    { severity: 'HIGH',     resource: THREAT_IPS[7],  detail: 'SSH brute-force: 78 failed SSH login attempts for user `ec2-user` from hosting provider abuse IP in 45 seconds.' },
    { severity: 'HIGH',     resource: THREAT_IPS[10], detail: 'XSS payload detected in POST body targeting /api/v2/user/profile endpoint. Request blocked by WAF rule.' },
    { severity: 'HIGH',     resource: THREAT_IPS[4],  detail: 'SSRF attempt: Internal metadata endpoint 169.254.169.254 accessed via forged Host header from APAC bulletproof host.' },
    { severity: 'MEDIUM',   resource: THREAT_IPS[8],  detail: 'Credential stuffing: 150 unique username/password combinations tried against Cognito user pool in 2 minutes.' },
    { severity: 'MEDIUM',   resource: THREAT_IPS[6],  detail: 'Suspicious API call pattern: 400 ListBuckets requests in 30 seconds suggesting automated enumeration.' },
    { severity: 'MEDIUM',   resource: THREAT_IPS[11], detail: 'DNS rebinding attempt detected targeting internal VPC resolver from external anonymizer IP.' },
    { severity: 'LOW',      resource: THREAT_IPS[3],  detail: 'Port scan detected: sequential TCP SYN probes on ports 22, 80, 443, 3306, 5432, 6379, 8080 from South American proxy.' },
  ];

  for (let i = 0; i < alerts.length; i++) {
    const a = alerts[i];
    const msg = { alertId: `sim-unauth-${Date.now()}-${i}`, timestamp: new Date(Date.now() - (12-i)*2*60000).toISOString(), type: 'UNAUTHORIZED_ACCESS', ...a };
    await sns.send(new PublishCommand({ TopicArn: topicArn, Message: JSON.stringify(msg) }));
    const icon = a.severity === 'CRITICAL' ? '🔴' : a.severity === 'HIGH' ? '🟡' : '🔵';
    console.log(`  ${icon} [${i+1}/12] ${a.severity} — ${a.detail.slice(0, 80)}...`);
  }
  console.log(`[✓] 12 unauthorized access alerts published.\n`);
}

// ── Main Orchestrator ────────────────────────────────────────────────────────
async function main() {
  console.log('╔══════════════════════════════════════════════════════╗');
  console.log('║  CloudSentinel — Mega Security Simulation Engine    ║');
  console.log('║  12 S3 · 10 IAM · 15 CloudTrail · 12 Unauth Access ║');
  console.log('╚══════════════════════════════════════════════════════╝\n');

  await cleanup();
  await simulateS3Buckets();
  await delay(1000);
  await simulateIamUsers();
  await delay(1000);
  await simulateCloudTrailLogs();
  await delay(1000);
  await simulateUnauthorizedAccess();

  console.log('⏳ Waiting 3s for SNS/SQS propagation...');
  await delay(3000);

  console.log('\n🔍 Phase 5: Invoking all scanner Lambdas...');
  await scan();
  console.log('[✓] All scanners invoked.\n');

  console.log('╔══════════════════════════════════════════════════════╗');
  console.log('║  ✅ Mega Simulation Complete!                       ║');
  console.log('║                                                      ║');
  console.log('║  Open http://localhost:5173 to see:                  ║');
  console.log('║  • 15 CloudTrail logs in the Logs tab                ║');
  console.log('║  • 12 boundary breach alerts in Overview             ║');
  console.log('║  • 12 S3 bucket findings (7 vulnerable, 3 secure)   ║');
  console.log('║  • 10 IAM users (8 non-compliant, 2 compliant)      ║');
  console.log('╚══════════════════════════════════════════════════════╝');
}

main().catch(err => { console.error('Fatal:', err); process.exit(1); });

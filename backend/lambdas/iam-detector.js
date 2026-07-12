const { IAMClient, ListUsersCommand, ListAttachedUserPoliciesCommand, ListMFADevicesCommand } = require('@aws-sdk/client-iam');
const { DynamoDBClient } = require('@aws-sdk/client-dynamodb');
const { DynamoDBDocumentClient, PutCommand } = require('@aws-sdk/lib-dynamodb');
const crypto = require('crypto');
const { sendCriticalAlert } = require('../middleware/emailNotifier');

const region = process.env.AWS_REGION || 'us-east-1';
const endpoint = process.env.AWS_ENDPOINT_URL || 'http://localhost:4566';

const iamClient = new IAMClient({ endpoint, region });
const ddbClient = new DynamoDBClient({ endpoint, region });
const ddbDocClient = DynamoDBDocumentClient.from(ddbClient);

exports.handler = async (event) => {
  console.log('Starting IAM compliance scan...', event);
  
  try {
    const listRes = await iamClient.send(new ListUsersCommand({}));
    const users = listRes.Users || [];
    console.log(`Found ${users.length} IAM users. Checking privileges and compliance...`);
    
    let findingsCount = 0;
    
    for (const user of users) {
      const userName = user.UserName;
      if (!userName) continue;
      
      console.log(`Scanning IAM user: ${userName}`);
      
      // 1. Check for highly privileged policies attached directly to user
      try {
        const policiesRes = await iamClient.send(new ListAttachedUserPoliciesCommand({ UserName: userName }));
        const policies = policiesRes.AttachedPolicies || [];
        for (const policy of policies) {
          const policyArn = policy.PolicyArn || '';
          if (policyArn.includes('AdministratorAccess')) {
            findingsCount++;
            const alert = {
              alertId: crypto.randomUUID(),
              timestamp: new Date().toISOString(),
              type: 'IAM_MISUSE',
              severity: 'CRITICAL',
              resource: userName,
              detail: `Critical vulnerability: Policy "AdministratorAccess" is attached directly to IAM User ${userName}. This violates the principle of least privilege (policies should be attached via IAM groups or roles).`,
              status: 'OPEN'
            };
            
            await ddbDocClient.send(new PutCommand({
              TableName: 'SecurityAlerts',
              Item: alert
            }));
            await sendCriticalAlert(alert);
            console.log(`[ALERT] Direct AdministratorAccess policy detected on user ${userName}`);
          }
        }
      } catch (err) {
        console.warn(`Could not fetch attached policies for user ${userName}:`, err.message);
      }
      
      // 2. Check for missing MFA (Console logins should have MFA enabled)
      // Since IAM users can be console users, if they have no MFA devices, log a MEDIUM security alert
      try {
        const mfaRes = await iamClient.send(new ListMFADevicesCommand({ UserName: userName }));
        const mfaDevices = mfaRes.MFADevices || [];
        if (mfaDevices.length === 0) {
          findingsCount++;
          const alert = {
            alertId: crypto.randomUUID(),
            timestamp: new Date().toISOString(),
            type: 'IAM_MISUSE',
            severity: 'MEDIUM',
            resource: userName,
            detail: `MFA Compliance alert: IAM User ${userName} has password or console access enabled but lacks active Multi-Factor Authentication (MFA).`,
            status: 'OPEN'
          };
          
          await ddbDocClient.send(new PutCommand({
            TableName: 'SecurityAlerts',
            Item: alert
          }));
          await sendCriticalAlert(alert);
          console.log(`[ALERT] Missing MFA compliance detected on user ${userName}`);
        }
      } catch (err) {
        console.warn(`Could not check MFA devices for user ${userName}:`, err.message);
      }
    }
    
    return {
      statusCode: 200,
      body: JSON.stringify({
        message: `IAM compliance scan completed. Found ${findingsCount} findings.`,
        scannedCount: users.length,
        findingsCount
      })
    };
  } catch (error) {
    console.error('IAM compliance scan failed:', error);
    return {
      statusCode: 500,
      body: JSON.stringify({ error: error.message })
    };
  }
};

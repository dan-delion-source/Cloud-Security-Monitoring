const { S3Client, ListObjectsV2Command, GetObjectCommand } = require('@aws-sdk/client-s3');
const { DynamoDBClient } = require('@aws-sdk/client-dynamodb');
const { DynamoDBDocumentClient, PutCommand } = require('@aws-sdk/lib-dynamodb');
const crypto = require('crypto');
const { sendCriticalAlert } = require('../middleware/emailNotifier');

const region = process.env.AWS_REGION || 'us-east-1';
const endpoint = process.env.AWS_ENDPOINT_URL || 'http://localhost:4566';

const s3Client = new S3Client({ endpoint, region, forcePathStyle: true });
const ddbClient = new DynamoDBClient({ endpoint, region });
const ddbDocClient = DynamoDBDocumentClient.from(ddbClient);

// Helper to read S3 stream as string
async function streamToString(stream) {
  const chunks = [];
  return new Promise((resolve, reject) => {
    stream.on('data', (chunk) => chunks.push(Buffer.from(chunk)));
    stream.on('error', (err) => reject(err));
    stream.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
  });
}

exports.handler = async (event) => {
  console.log('Starting Suspicious Login detector...', JSON.stringify(event));
  
  let findingsCount = 0;
  
  try {
    console.log('Scanning S3 cloudtrail-logs for ConsoleLogin logs...');
    
    try {
      const objectsRes = await s3Client.send(new ListObjectsV2Command({ Bucket: 'cloudtrail-logs' }));
      const objects = objectsRes.Contents || [];
      console.log(`Found ${objects.length} log objects in S3.`);
      
      for (const obj of objects) {
        const key = obj.Key;
        if (!key) continue;
        
        const getObjRes = await s3Client.send(new GetObjectCommand({ Bucket: 'cloudtrail-logs', Key: key }));
        const contentStr = await streamToString(getObjRes.Body);
        
        const logData = JSON.parse(contentStr);
        const records = logData.Records || [];
        
        for (const rec of records) {
          if (rec.eventName === 'ConsoleLogin') {
            let isSuspicious = false;
            let reason = '';
            
            // 1. Check for missing MFA
            const mfaUsed = rec.additionalEventData?.MFAUsed;
            if (mfaUsed === 'No') {
              isSuspicious = true;
              reason = 'Successful console sign-in performed WITHOUT Multi-Factor Authentication (MFA)';
            }
            
            // 2. Check for Off-hours login (between 11 PM and 5 AM)
            if (!isSuspicious && rec.eventTime) {
              const loginDate = new Date(rec.eventTime);
              const loginHour = loginDate.getUTCHours();
              if (loginHour >= 23 || loginHour < 5) {
                isSuspicious = true;
                reason = `Successful console sign-in performed at off-hours (${loginHour}:00 UTC)`;
              }
            }
            
            if (isSuspicious) {
              findingsCount++;
              const principal = rec.userIdentity?.userName || rec.userIdentity?.arn || 'unknown-principal';
              const alert = {
                alertId: crypto.randomUUID(),
                timestamp: rec.eventTime || new Date().toISOString(),
                type: 'SUSPICIOUS_LOGIN',
                severity: mfaUsed === 'No' ? 'CRITICAL' : 'HIGH',
                resource: rec.sourceIPAddress || 'unknown-ip',
                detail: `Suspicious Console Login: Principal ${principal} logged into console from IP ${rec.sourceIPAddress}. Security trigger: ${reason}`,
                status: 'OPEN'
              };
              
              await ddbDocClient.send(new PutCommand({
                TableName: 'SecurityAlerts',
                Item: alert
              }));
              await sendCriticalAlert(alert);
              console.log(`[ALERT] Logged Suspicious Login event finding: ${alert.detail}`);
            }
          }
        }
      }
    } catch (err) {
      if (err.name !== 'NoSuchBucket' && err.name !== 'NoSuchKey') {
        console.warn('S3 login log scan warning:', err.message);
      }
    }
    
    return {
      statusCode: 200,
      body: JSON.stringify({
        message: `Suspicious Login detection complete. Found ${findingsCount} events.`,
        findingsCount
      })
    };
  } catch (error) {
    console.error('Suspicious Login detector failed:', error);
    return {
      statusCode: 500,
      body: JSON.stringify({ error: error.message })
    };
  }
};

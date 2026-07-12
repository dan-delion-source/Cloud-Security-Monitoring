const { S3Client, ListObjectsV2Command, GetObjectCommand } = require('@aws-sdk/client-s3');
const { DynamoDBClient } = require('@aws-sdk/client-dynamodb');
const { DynamoDBDocumentClient, PutCommand } = require('@aws-sdk/lib-dynamodb');
const crypto = require('crypto');
const { sendCriticalAlert } = require('./middleware/emailNotifier');

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
  console.log('Starting Unauthorized Access detector...', JSON.stringify(event));
  
  let findingsCount = 0;
  
  try {
    // A. Check if triggered by SQS queue events (which setup-localstack triggers via SNS/SQS)
    if (event && event.Records && event.Records.length > 0) {
      console.log(`Processing ${event.Records.length} SQS events...`);
      for (const record of event.Records) {
        try {
          const body = JSON.parse(record.body || '{}');
          // SNS messages wrap the payload in Message
          const alertData = body.Message ? JSON.parse(body.Message) : body;
          
          if (alertData.type === 'UNAUTHORIZED_ACCESS' || alertData.type === 'SUSPICIOUS_LOGIN') {
            findingsCount++;
            const alert = {
              alertId: alertData.alertId || crypto.randomUUID(),
              timestamp: alertData.timestamp || new Date().toISOString(),
              type: alertData.type,
              severity: alertData.severity || 'HIGH',
              resource: alertData.resource || 'unknown-origin',
              detail: alertData.detail || 'SQS boundary breach alert triggered',
              status: 'OPEN'
            };
            
            await ddbDocClient.send(new PutCommand({
              TableName: 'SecurityAlerts',
              Item: alert
            }));
            await sendCriticalAlert(alert);
            console.log(`[ALERT] Logged SQS event finding: ${alert.detail}`);
          }
        } catch (err) {
          console.warn('Error parsing SQS record body:', err.message);
        }
      }
    }
    
    // B. Scan S3 CloudTrail logs for AccessDenied or unauthorized operations
    console.log('Scanning S3 cloudtrail-logs bucket for API failures...');
    try {
      const objectsRes = await s3Client.send(new ListObjectsV2Command({ Bucket: 'cloudtrail-logs' }));
      const objects = objectsRes.Contents || [];
      console.log(`Found ${objects.length} log objects in S3.`);
      
      for (const obj of objects) {
        const key = obj.Key;
        if (!key) continue;
        
        console.log(`Analyzing log object: ${key}`);
        const getObjRes = await s3Client.send(new GetObjectCommand({ Bucket: 'cloudtrail-logs', Key: key }));
        const contentStr = await streamToString(getObjRes.Body);
        
        const logData = JSON.parse(contentStr);
        const records = logData.Records || [];
        
        for (const rec of records) {
          // Detect "AccessDenied", "UnauthorizedOperation" or unauthorized API invoke attempts
          const errorCode = rec.errorCode || '';
          const errorMessage = rec.errorMessage || '';
          
          if (errorCode.includes('AccessDenied') || errorCode.includes('UnauthorizedOperation')) {
            findingsCount++;
            const principal = rec.userIdentity?.userName || rec.userIdentity?.arn || 'Anonymous';
            const alert = {
              alertId: crypto.randomUUID(),
              timestamp: rec.eventTime || new Date().toISOString(),
              type: 'UNAUTHORIZED_ACCESS',
              severity: 'HIGH',
              resource: rec.sourceIPAddress || 'unknown-ip',
              detail: `Unauthorized Access attempt: ${principal} received AccessDenied while calling ${rec.eventSource}:${rec.eventName} from source IP ${rec.sourceIPAddress}. Error details: ${errorMessage}`,
              status: 'OPEN'
            };
            
            await ddbDocClient.send(new PutCommand({
              TableName: 'SecurityAlerts',
              Item: alert
            }));
            await sendCriticalAlert(alert);
            console.log(`[ALERT] Logged AccessDenied event finding for ${rec.eventName}`);
          }
        }
      }
    } catch (err) {
      if (err.name !== 'NoSuchBucket' && err.name !== 'NoSuchKey') {
        console.warn('S3 log scan warning:', err.message);
      }
    }
    
    return {
      statusCode: 200,
      body: JSON.stringify({
        message: `Unauthorized Access detection complete. Found ${findingsCount} events.`,
        findingsCount
      })
    };
  } catch (error) {
    console.error('Unauthorized Access detector failed:', error);
    return {
      statusCode: 500,
      body: JSON.stringify({ error: error.message })
    };
  }
};

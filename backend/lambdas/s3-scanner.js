const { S3Client, ListBucketsCommand, GetBucketAclCommand, GetBucketPolicyCommand } = require('@aws-sdk/client-s3');
const { DynamoDBClient } = require('@aws-sdk/client-dynamodb');
const { DynamoDBDocumentClient, PutCommand } = require('@aws-sdk/lib-dynamodb');
const crypto = require('crypto');
const { sendCriticalAlert } = require('./middleware/emailNotifier');

const region = process.env.AWS_REGION || 'us-east-1';
const endpoint = process.env.AWS_ENDPOINT_URL || 'http://localhost:4566';

const s3Client = new S3Client({ endpoint, region, forcePathStyle: true });
const ddbClient = new DynamoDBClient({ endpoint, region });
const ddbDocClient = DynamoDBDocumentClient.from(ddbClient);

exports.handler = async (event) => {
  console.log('Starting S3 compliance scan...', event);
  
  try {
    const listRes = await s3Client.send(new ListBucketsCommand({}));
    const buckets = listRes.Buckets || [];
    console.log(`Found ${buckets.length} S3 buckets. Checking exposure...`);
    
    let findingsCount = 0;
    
    for (const bucket of buckets) {
      const bucketName = bucket.Name;
      if (!bucketName) continue;
      
      console.log(`Scanning bucket: ${bucketName}`);
      let isPublic = false;
      let reason = '';
      
      // 1. Check ACL
      try {
        const aclRes = await s3Client.send(new GetBucketAclCommand({ Bucket: bucketName }));
        const grants = aclRes.Grants || [];
        for (const grant of grants) {
          const uri = grant.Grantee?.URI || '';
          if (uri.includes('global/AllUsers') || uri.includes('global/AuthenticatedUsers')) {
            isPublic = true;
            reason = 'Bucket has active Public/Authenticated Read/Write ACL grants';
            break;
          }
        }
      } catch (err) {
        console.warn(`Could not fetch ACL for bucket ${bucketName}:`, err.message);
      }
      
      // 2. Check Policy (if ACL didn't trigger)
      if (!isPublic) {
        try {
          const policyRes = await s3Client.send(new GetBucketPolicyCommand({ Bucket: bucketName }));
          if (policyRes.Policy) {
            const policyJson = JSON.parse(policyRes.Policy);
            const statements = Array.isArray(policyJson.Statement) ? policyJson.Statement : [policyJson.Statement];
            for (const stmt of statements) {
              if (stmt.Effect === 'Allow' && stmt.Principal === '*') {
                isPublic = true;
                reason = 'Bucket policy allows public Access with Principal: "*"';
                break;
              }
            }
          }
        } catch (err) {
          // NoSuchBucketPolicy is expected if there is no bucket policy
          if (err.name !== 'NoSuchBucketPolicy') {
            console.warn(`Error scanning policy for bucket ${bucketName}:`, err.message);
          }
        }
      }
      
      // If public exposure is found, write PUBLIC_S3_BUCKET alert to DynamoDB
      if (isPublic) {
        findingsCount++;
        const alert = {
          alertId: crypto.randomUUID(),
          timestamp: new Date().toISOString(),
          type: 'PUBLIC_S3_BUCKET',
          severity: 'HIGH',
          resource: bucketName,
          detail: `S3 bucket ${bucketName} is publicly exposed. Reason: ${reason}`,
          status: 'OPEN'
        };
        
        await ddbDocClient.send(new PutCommand({
          TableName: 'SecurityAlerts',
          Item: alert
        }));
        await sendCriticalAlert(alert);
        console.log(`[ALERT] Logged public bucket finding for ${bucketName}`);
      }
    }
    
    return {
      statusCode: 200,
      body: JSON.stringify({
        message: `S3 Compliance scan completed. Found ${findingsCount} public buckets.`,
        scannedCount: buckets.length,
        findingsCount
      })
    };
  } catch (error) {
    console.error('S3 compliance scan failed:', error);
    return {
      statusCode: 500,
      body: JSON.stringify({ error: error.message })
    };
  }
};

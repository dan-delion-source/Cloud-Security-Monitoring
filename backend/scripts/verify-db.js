const { DynamoDBClient, ScanCommand } = require('@aws-sdk/client-dynamodb');
const { S3Client, ListBucketsCommand } = require('@aws-sdk/client-s3');

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

const ddbClient = new DynamoDBClient(clientConfig);
const s3Client = new S3Client(clientConfig);

async function main() {
  console.log('==================================================');
  console.log('  Integration Verification - Reading LocalStack   ');
  console.log('==================================================\n');

  // 1. Scan DynamoDB SecurityAlerts
  console.log('[*] Scanning DynamoDB "SecurityAlerts" table...');
  try {
    const ddbRes = await ddbClient.send(new ScanCommand({ TableName: 'SecurityAlerts' }));
    const items = ddbRes.Items || [];
    console.log(`[✓] Successfully retrieved ${items.length} alerts from DynamoDB:\n`);
    
    items.forEach((item, index) => {
      console.log(`--- Alert #${index + 1} ---`);
      console.log(`ID:       ${item.alertId?.S}`);
      console.log(`Type:     ${item.type?.S}`);
      console.log(`Severity: ${item.severity?.S}`);
      console.log(`Resource: ${item.resource?.S}`);
      console.log(`Details:  ${item.detail?.S}`);
      console.log(`Time:     ${item.timestamp?.S}`);
      console.log(`Status:   ${item.status?.S}`);
      console.log('------------------------\n');
    });
  } catch (err) {
    console.error('[✗] Failed to read from SecurityAlerts table:', err.message);
  }

  // 2. List S3 Buckets
  console.log('[*] Listing S3 buckets in LocalStack...');
  try {
    const s3Res = await s3Client.send(new ListBucketsCommand({}));
    const buckets = s3Res.Buckets || [];
    console.log(`[✓] Successfully found ${buckets.length} S3 buckets:`);
    buckets.forEach(b => console.log(` - Name: ${b.Name} (Created: ${b.CreationDate})`));
  } catch (err) {
    console.error('[✗] Failed to list S3 buckets:', err.message);
  }
}

main().catch(console.error);

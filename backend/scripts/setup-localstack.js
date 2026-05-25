const { DynamoDBClient, CreateTableCommand, ListTablesCommand } = require('@aws-sdk/client-dynamodb');
const { S3Client, CreateBucketCommand, ListBucketsCommand } = require('@aws-sdk/client-s3');
const { SNSClient, CreateTopicCommand, SubscribeCommand } = require('@aws-sdk/client-sns');
const { SQSClient, CreateQueueCommand, GetQueueAttributesCommand } = require('@aws-sdk/client-sqs');
const { LambdaClient, CreateFunctionCommand, UpdateFunctionCodeCommand, ListFunctionsCommand, CreateEventSourceMappingCommand, ListEventSourceMappingsCommand } = require('@aws-sdk/client-lambda');
const AdmZip = require('adm-zip');
const fs = require('fs');
const path = require('path');
const http = require('http');
const { execSync } = require('child_process');

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
const snsClient = new SNSClient(clientConfig);
const sqsClient = new SQSClient(clientConfig);
const lambdaClient = new LambdaClient(clientConfig);

// Resolve the Docker bridge IP of the LocalStack container so that Lambda
// containers (which run in separate Docker containers) can reach LocalStack
// services. Using 'localhost' inside a Lambda container refers to the Lambda
// container itself, NOT the LocalStack host.
function resolveLocalStackInternalEndpoint() {
  try {
    const ip = execSync(
      "docker inspect localstack --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}'"
    ).toString().trim();
    if (ip) {
      console.log(`[*] Resolved LocalStack internal IP: ${ip}`);
      return `http://${ip}:4566`;
    }
  } catch (err) {
    console.warn('[!] Could not resolve LocalStack container IP, falling back to ENDPOINT.');
  }
  return ENDPOINT;
}

const LAMBDA_ENDPOINT = resolveLocalStackInternalEndpoint();

// Helper to wait for LocalStack health
function waitLocalStackReady() {
  return new Promise((resolve, reject) => {
    let attempts = 0;
    const check = () => {
      attempts++;
      http.get(`${ENDPOINT}/_localstack/health`, (res) => {
        if (res.statusCode === 200) {
          console.log('[✓] LocalStack is healthy and reachable.');
          resolve();
        } else {
          retry();
        }
      }).on('error', () => {
        retry();
      });
    };

    const retry = () => {
      if (attempts >= 30) {
        reject(new Error('LocalStack did not become healthy within 30 seconds.'));
      } else {
        console.log(`[*] Waiting for LocalStack (attempt ${attempts}/30)...`);
        setTimeout(check, 1000);
      }
    };

    check();
  });
}

async function main() {
  console.log('==================================================');
  console.log('  CloudSentinel - JS LocalStack Provisioning      ');
  console.log('==================================================');

  await waitLocalStackReady();

  // 1. DynamoDB Table
  console.log('[*] Provisioning DynamoDB Table "SecurityAlerts"...');
  try {
    const listRes = await ddbClient.send(new ListTablesCommand({}));
    if (listRes.TableNames?.includes('SecurityAlerts')) {
      console.log('[-] DynamoDB Table "SecurityAlerts" already exists.');
    } else {
      await ddbClient.send(new CreateTableCommand({
        TableName: 'SecurityAlerts',
        AttributeDefinitions: [
          { AttributeName: 'alertId', AttributeType: 'S' },
          { AttributeName: 'timestamp', AttributeType: 'S' }
        ],
        KeySchema: [
          { AttributeName: 'alertId', KeyType: 'HASH' },
          { AttributeName: 'timestamp', KeyType: 'RANGE' }
        ],
        BillingMode: 'PAY_PER_REQUEST'
      }));
      console.log('[✓] DynamoDB Table "SecurityAlerts" created.');
    }
  } catch (err) {
    console.error('[✗] DynamoDB Table creation failed:', err.message);
  }

  // 2. S3 Bucket
  console.log('[*] Provisioning S3 Bucket "cloudtrail-logs"...');
  try {
    const listRes = await s3Client.send(new ListBucketsCommand({}));
    if (listRes.Buckets?.some(b => b.Name === 'cloudtrail-logs')) {
      console.log('[-] S3 Bucket "cloudtrail-logs" already exists.');
    } else {
      await s3Client.send(new CreateBucketCommand({ Bucket: 'cloudtrail-logs' }));
      console.log('[✓] S3 Bucket "cloudtrail-logs" created.');
    }
  } catch (err) {
    console.error('[✗] S3 Bucket creation failed:', err.message);
  }

  // 3. SNS Topic
  console.log('[*] Provisioning SNS Topic "security-alerts"...');
  let topicArn;
  try {
    const res = await snsClient.send(new CreateTopicCommand({ Name: 'security-alerts' }));
    topicArn = res.TopicArn;
    console.log('[✓] SNS Topic created:', topicArn);
  } catch (err) {
    console.error('[✗] SNS Topic creation failed:', err.message);
  }

  // 4. SQS Queue
  console.log('[*] Provisioning SQS Queue "alert-queue"...');
  let queueUrl, queueArn;
  try {
    const createRes = await sqsClient.send(new CreateQueueCommand({ QueueName: 'alert-queue' }));
    queueUrl = createRes.QueueUrl;
    
    const attrRes = await sqsClient.send(new GetQueueAttributesCommand({
      QueueUrl: queueUrl,
      AttributeNames: ['QueueArn']
    }));
    queueArn = attrRes.Attributes?.QueueArn;
    console.log('[✓] SQS Queue created:', queueUrl, `(ARN: ${queueArn})`);
  } catch (err) {
    console.error('[✗] SQS Queue creation failed:', err.message);
  }

  // 5. Subscription
  if (topicArn && queueArn) {
    console.log('[*] Subscribing SQS to SNS Topic...');
    try {
      await snsClient.send(new SubscribeCommand({
        TopicArn: topicArn,
        Protocol: 'sqs',
        Endpoint: queueArn
      }));
      console.log('[✓] SNS-SQS subscription created.');
    } catch (err) {
      console.error('[✗] SNS-SQS subscription failed:', err.message);
    }
  }

  // 6. Packaging & Deploying Lambdas
  console.log('[*] Packaging and deploying Lambda functions...');
  const lambdas = ['s3-scanner', 'iam-detector', 'unauth-detector', 'suspicious-login'];
  const role = 'arn:aws:iam::000000000000:role/lambda-execution-role';

  for (const lambdaName of lambdas) {
    console.log(`[*] Deploying Lambda "${lambdaName}"...`);
    try {
      // Package code in-memory with adm-zip
      const zip = new AdmZip();
      const codePath = path.join(__dirname, '../lambdas', `${lambdaName}.js`);
      zip.addLocalFile(codePath);
      const zipBuffer = zip.toBuffer();

      // Check if function exists
      const listRes = await lambdaClient.send(new ListFunctionsCommand({}));
      const exists = listRes.Functions?.some(f => f.FunctionName === lambdaName);

      if (exists) {
        console.log(`[-] Lambda "${lambdaName}" exists. Updating code...`);
        await lambdaClient.send(new UpdateFunctionCodeCommand({
          FunctionName: lambdaName,
          ZipFile: zipBuffer
        }));
        console.log(`[✓] Lambda "${lambdaName}" code updated.`);
      } else {
        await lambdaClient.send(new CreateFunctionCommand({
          FunctionName: lambdaName,
          Runtime: 'nodejs18.x',
          Role: role,
          Handler: `${lambdaName}.handler`,
          Code: {
            ZipFile: zipBuffer
          },
          Timeout: 15,
          Environment: {
            Variables: {
              AWS_ENDPOINT_URL: LAMBDA_ENDPOINT
            }
          }
        }));
        console.log(`[✓] Lambda "${lambdaName}" created.`);
      }
    } catch (err) {
      console.error(`[✗] Lambda "${lambdaName}" deployment failed:`, err.message);
    }
  }

  // 7. Event Source Mapping (SQS to Lambda trigger)
  if (queueArn) {
    console.log('[*] Setting up SQS event source mapping for unauth-detector...');
    try {
      const listMappings = await lambdaClient.send(new ListEventSourceMappingsCommand({
        FunctionName: 'unauth-detector'
      }));
      const mapped = listMappings.EventSourceMappings?.some(m => m.EventSourceArn === queueArn);

      if (mapped) {
        console.log('[-] Event source mapping already exists.');
      } else {
        await lambdaClient.send(new CreateEventSourceMappingCommand({
          FunctionName: 'unauth-detector',
          EventSourceArn: queueArn,
          BatchSize: 10
        }));
        console.log('[✓] Event source mapping created successfully.');
      }
    } catch (err) {
      console.error('[✗] Event source mapping creation failed:', err.message);
    }
  }

  console.log('==================================================');
  console.log('  [✓] All LocalStack resources deployed!        ');
  console.log('==================================================');
}

main().catch(err => {
  console.error('Fatal error during provisioning:', err);
  process.exit(1);
});

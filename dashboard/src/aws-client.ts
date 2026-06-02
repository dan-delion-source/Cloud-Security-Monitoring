import { CloudTrailClient } from '@aws-sdk/client-cloudtrail';
import { CloudWatchLogsClient } from '@aws-sdk/client-cloudwatch-logs';
import { GuardDutyClient } from '@aws-sdk/client-guardduty';
import { ConfigServiceClient } from '@aws-sdk/client-config-service';
import { S3Client } from '@aws-sdk/client-s3';
import { S3ControlClient } from '@aws-sdk/client-s3-control';
import { IAMClient } from '@aws-sdk/client-iam';
import { DynamoDBClient } from '@aws-sdk/client-dynamodb';
import { DynamoDBDocumentClient } from '@aws-sdk/lib-dynamodb';
import { LambdaClient } from '@aws-sdk/client-lambda';

// Environment variables configuration
const accessKeyId = import.meta.env.VITE_AWS_ACCESS_KEY_ID || 'test';
const secretAccessKey = import.meta.env.VITE_AWS_SECRET_ACCESS_KEY || 'test';
const sessionToken = import.meta.env.VITE_AWS_SESSION_TOKEN || undefined;
const region = import.meta.env.VITE_AWS_REGION || 'us-east-1';

const awsCredentials = {
  accessKeyId,
  secretAccessKey,
  sessionToken
};

// AWS SDK Clients Initialization pointing to our Vite proxy (bypassing CORS checks)
const localstackEndpoint = typeof window !== 'undefined'
  ? `${window.location.origin}/aws-local`
  : 'http://localhost:4566';

const clientConfig = {
  region,
  endpoint: localstackEndpoint,
  credentials: awsCredentials,
  forcePathStyle: true // Safe for local S3
};

export const cloudTrailClient = new CloudTrailClient(clientConfig);
export const cloudWatchLogsClient = new CloudWatchLogsClient(clientConfig);
export const guardDutyClient = new GuardDutyClient(clientConfig);
export const configServiceClient = new ConfigServiceClient(clientConfig);
export const s3Client = new S3Client(clientConfig);
export const s3ControlClient = new S3ControlClient(clientConfig);
export const iamClient = new IAMClient(clientConfig);
export const dynamoDbClient = new DynamoDBClient(clientConfig);
export const ddbDocClient = DynamoDBDocumentClient.from(dynamoDbClient);
export const lambdaClient = new LambdaClient(clientConfig);

/**
 * Executes a function calling the AWS SDK.
 * Handles retry with exponential backoff (max 3 attempts),
 * and error normalization using the tuple pattern.
 */
export async function executeAwsCall<T>(
  fn: () => Promise<T>,
  retries = 3,
  initialDelay = 500
): Promise<[T | null, Error | null]> {
  let lastError: Error | null = null;
  
  for (let attempt = 0; attempt < retries; attempt++) {
    try {
      const result = await fn();
      return [result, null];
    } catch (error: any) {
      lastError = error instanceof Error ? error : new Error(String(error));
      
      // If we have attempts remaining, wait with exponential backoff
      if (attempt < retries - 1) {
        const delay = initialDelay * Math.pow(2, attempt);
        await new Promise(resolve => setTimeout(resolve, delay));
      }
    }
  }
  
  return [null, lastError || new Error('AWS action failed')];
}

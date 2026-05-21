import { CloudTrailClient } from '@aws-sdk/client-cloudtrail';
import { CloudWatchLogsClient } from '@aws-sdk/client-cloudwatch-logs';
import { GuardDutyClient } from '@aws-sdk/client-guardduty';
import { ConfigServiceClient } from '@aws-sdk/client-config-service';
import { S3Client } from '@aws-sdk/client-s3';
import { S3ControlClient } from '@aws-sdk/client-s3-control';
import { IAMClient } from '@aws-sdk/client-iam';

// Environment variables configuration
const accessKeyId = import.meta.env.VITE_AWS_ACCESS_KEY_ID || '';
const secretAccessKey = import.meta.env.VITE_AWS_SECRET_ACCESS_KEY || '';
const sessionToken = import.meta.env.VITE_AWS_SESSION_TOKEN || undefined;
const region = import.meta.env.VITE_AWS_REGION || 'us-east-1';

const awsCredentials = accessKeyId && secretAccessKey ? {
  accessKeyId,
  secretAccessKey,
  sessionToken
} : undefined;

export const isMockMode = import.meta.env.VITE_USE_MOCK_DATA === 'true' || !awsCredentials;

// AWS SDK Clients Initialization
const clientConfig = {
  region,
  ...(awsCredentials ? { credentials: awsCredentials } : {})
};

export const cloudTrailClient = !isMockMode ? new CloudTrailClient(clientConfig) : null;
export const cloudWatchLogsClient = !isMockMode ? new CloudWatchLogsClient(clientConfig) : null;
export const guardDutyClient = !isMockMode ? new GuardDutyClient(clientConfig) : null;
export const configServiceClient = !isMockMode ? new ConfigServiceClient(clientConfig) : null;
export const s3Client = !isMockMode ? new S3Client(clientConfig) : null;
export const s3ControlClient = !isMockMode ? new S3ControlClient(clientConfig) : null;
export const iamClient = !isMockMode ? new IAMClient(clientConfig) : null;

/**
 * Executes a function calling the AWS SDK.
 * Handles credential injection, retry with exponential backoff (max 3 attempts),
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

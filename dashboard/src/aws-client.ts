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

import { useSecurityStore } from './store/securityStore';

// Dynamic client configuration resolver
function getClientConfig() {
  let storeAccessKeyId = '';
  let storeSecretAccessKey = '';
  let storeRegion = 'us-east-1';

  try {
    const state = useSecurityStore.getState();
    if (state && state.awsConfig) {
      storeAccessKeyId = state.awsConfig.accessKeyId;
      storeSecretAccessKey = state.awsConfig.secretAccessKey;
      storeRegion = state.awsConfig.region;
    }
  } catch (e) {
    // Fallback if store is not initialized during early module load
  }

  const accessKeyId = storeAccessKeyId || import.meta.env.VITE_AWS_ACCESS_KEY_ID || 'test';
  const secretAccessKey = storeSecretAccessKey || import.meta.env.VITE_AWS_SECRET_ACCESS_KEY || 'test';
  const sessionToken: string | undefined = import.meta.env.VITE_AWS_SESSION_TOKEN || undefined;
  const region = storeRegion || import.meta.env.VITE_AWS_REGION || 'us-east-1';

  const isLocalStack = accessKeyId === 'test' || accessKeyId === '';

  if (isLocalStack && import.meta.env.DEV) {
    console.debug('[aws-client] Using LocalStack fallback credentials (test/test)');
  }

  const localstackEndpoint = typeof window !== 'undefined'
    ? `${window.location.origin}/aws-local`
    : 'http://localhost:4566';

  const endpoint = isLocalStack ? localstackEndpoint : undefined;

  const credentials: { accessKeyId: string; secretAccessKey: string; sessionToken?: string } = {
    accessKeyId,
    secretAccessKey,
    ...(sessionToken ? { sessionToken } : {}),
  };

  return {
    region,
    endpoint,
    credentials,
    forcePathStyle: isLocalStack
  };
}

// Re-creatable backing client instances
let currentCloudTrailClient = new CloudTrailClient(getClientConfig());
let currentCloudWatchLogsClient = new CloudWatchLogsClient(getClientConfig());
let currentGuardDutyClient = new GuardDutyClient(getClientConfig());
let currentConfigServiceClient = new ConfigServiceClient(getClientConfig());
let currentS3Client = new S3Client(getClientConfig());
let currentS3ControlClient = new S3ControlClient(getClientConfig());
let currentIamClient = new IAMClient(getClientConfig());
let currentDynamoDbClient = new DynamoDBClient(getClientConfig());
let currentDdbDocClient = DynamoDBDocumentClient.from(currentDynamoDbClient);
let currentLambdaClient = new LambdaClient(getClientConfig());

// Re-instantiate backing clients when store config changes
function updateClients() {
  const config = getClientConfig();
  currentCloudTrailClient = new CloudTrailClient(config);
  currentCloudWatchLogsClient = new CloudWatchLogsClient(config);
  currentGuardDutyClient = new GuardDutyClient(config);
  currentConfigServiceClient = new ConfigServiceClient(config);
  currentS3Client = new S3Client(config);
  currentS3ControlClient = new S3ControlClient(config);
  currentIamClient = new IAMClient(config);
  currentDynamoDbClient = new DynamoDBClient(config);
  currentDdbDocClient = DynamoDBDocumentClient.from(currentDynamoDbClient);
  currentLambdaClient = new LambdaClient(config);
}

// Subscribe to store updates – re-create clients when credentials OR mode change
try {
  useSecurityStore.subscribe((state, prevState) => {
    if (
      state.awsConfig !== prevState.awsConfig ||
      state.isMockMode !== prevState.isMockMode
    ) {
      console.log('[aws-client] Config or mode changed – reinitializing SDK clients', {
        isMockMode: state.isMockMode,
        region: state.awsConfig.region,
      });
      updateClients();
    }
  });
} catch (e) {
  // Ignored if store is not available during early load
}

// Exported Proxies that delegate to the active backing instances
export const cloudTrailClient = new Proxy({}, {
  get(_target, prop) {
    const value = Reflect.get(currentCloudTrailClient, prop);
    return typeof value === 'function' ? value.bind(currentCloudTrailClient) : value;
  }
}) as CloudTrailClient;

export const cloudWatchLogsClient = new Proxy({}, {
  get(_target, prop) {
    const value = Reflect.get(currentCloudWatchLogsClient, prop);
    return typeof value === 'function' ? value.bind(currentCloudWatchLogsClient) : value;
  }
}) as CloudWatchLogsClient;

export const guardDutyClient = new Proxy({}, {
  get(_target, prop) {
    const value = Reflect.get(currentGuardDutyClient, prop);
    return typeof value === 'function' ? value.bind(currentGuardDutyClient) : value;
  }
}) as GuardDutyClient;

export const configServiceClient = new Proxy({}, {
  get(_target, prop) {
    const value = Reflect.get(currentConfigServiceClient, prop);
    return typeof value === 'function' ? value.bind(currentConfigServiceClient) : value;
  }
}) as ConfigServiceClient;

export const s3Client = new Proxy({}, {
  get(_target, prop) {
    const value = Reflect.get(currentS3Client, prop);
    return typeof value === 'function' ? value.bind(currentS3Client) : value;
  }
}) as S3Client;

export const s3ControlClient = new Proxy({}, {
  get(_target, prop) {
    const value = Reflect.get(currentS3ControlClient, prop);
    return typeof value === 'function' ? value.bind(currentS3ControlClient) : value;
  }
}) as S3ControlClient;

export const iamClient = new Proxy({}, {
  get(_target, prop) {
    const value = Reflect.get(currentIamClient, prop);
    return typeof value === 'function' ? value.bind(currentIamClient) : value;
  }
}) as IAMClient;

export const dynamoDbClient = new Proxy({}, {
  get(_target, prop) {
    const value = Reflect.get(currentDynamoDbClient, prop);
    return typeof value === 'function' ? value.bind(currentDynamoDbClient) : value;
  }
}) as DynamoDBClient;

export const ddbDocClient = new Proxy({}, {
  get(_target, prop) {
    const value = Reflect.get(currentDdbDocClient, prop);
    return typeof value === 'function' ? value.bind(currentDdbDocClient) : value;
  }
}) as DynamoDBDocumentClient;

export const lambdaClient = new Proxy({}, {
  get(_target, prop) {
    const value = Reflect.get(currentLambdaClient, prop);
    return typeof value === 'function' ? value.bind(currentLambdaClient) : value;
  }
}) as LambdaClient;

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

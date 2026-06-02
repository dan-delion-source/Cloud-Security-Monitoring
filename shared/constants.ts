/**
 * Shared constants — table names and service endpoints used by both
 * the backend Lambdas and the React dashboard.
 */

export const TABLE_NAMES = {
  SECURITY_ALERTS: 'SecurityAlerts',
} as const;

export const LOCALSTACK_ENDPOINT = 'http://localhost:4566';

export const AWS_REGION = 'us-east-1';

export const BUCKET_NAMES = {
  CLOUDTRAIL_LOGS: 'cloudtrail-logs',
  EXPOSED_TEST_BUCKET: 'exposed-test-bucket',
} as const;

export const SNS_TOPIC_NAME = 'security-alerts';

export const SQS_QUEUE_NAME = 'alert-queue';

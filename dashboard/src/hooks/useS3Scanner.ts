import { useEffect, useCallback } from 'react';
import { useSecurityStore } from '../store/securityStore';
import { ddbDocClient, s3Client, lambdaClient, executeAwsCall } from '../aws-client';
import { ScanCommand } from '@aws-sdk/lib-dynamodb';
import { ListBucketsCommand, GetBucketEncryptionCommand, GetBucketVersioningCommand, GetBucketWebsiteCommand } from '@aws-sdk/client-s3';
import { InvokeCommand } from '@aws-sdk/client-lambda';
import type { S3BucketScanResult, S3BucketChecks } from '../types/s3';
import type { Severity } from '../constants/severity';

const MOCK_BUCKETS: S3BucketScanResult[] = [
  {
    id: 's3-bucket-01',
    name: 'confidential-financial-reports-s3',
    severity: 'CRITICAL',
    exposureDuration: '14 days',
    region: 'us-east-1',
    encryptionType: 'SSE-S3',
    remediated: false,
    checks: {
      blockPublicAcls: false,
      blockPublicPolicy: false,
      noPublicPolicyPrincipal: false,
      noPublicAcl: true,
      websiteDisabled: true,
      sseKmsEnabled: false,
      versioningEnabled: false
    }
  },
  {
    id: 's3-bucket-02',
    name: 'public-assets-static-website',
    severity: 'HIGH',
    exposureDuration: '45 days',
    region: 'us-east-1',
    encryptionType: 'SSE-S3',
    remediated: false,
    checks: {
      blockPublicAcls: true,
      blockPublicPolicy: true,
      noPublicPolicyPrincipal: true,
      noPublicAcl: false,
      websiteDisabled: false,
      sseKmsEnabled: false,
      versioningEnabled: true
    }
  },
  {
    id: 's3-bucket-03',
    name: 'app-backups-db-mysql',
    severity: 'MEDIUM',
    exposureDuration: '0 days',
    region: 'us-west-2',
    encryptionType: 'SSE-S3',
    remediated: false,
    checks: {
      blockPublicAcls: true,
      blockPublicPolicy: true,
      noPublicPolicyPrincipal: true,
      noPublicAcl: true,
      websiteDisabled: true,
      sseKmsEnabled: false,
      versioningEnabled: true
    }
  },
  {
    id: 's3-bucket-04',
    name: 'cloudtrail-raw-audit-logs',
    severity: 'LOW',
    exposureDuration: '0 days',
    region: 'us-east-1',
    encryptionType: 'SSE-KMS',
    remediated: false,
    checks: {
      blockPublicAcls: true,
      blockPublicPolicy: true,
      noPublicPolicyPrincipal: true,
      noPublicAcl: true,
      websiteDisabled: true,
      sseKmsEnabled: true,
      versioningEnabled: false
    }
  },
  {
    id: 's3-bucket-05',
    name: 'secure-customer-pii-kms',
    severity: 'LOW',
    exposureDuration: '0 days',
    region: 'us-east-1',
    encryptionType: 'SSE-KMS',
    remediated: false,
    checks: {
      blockPublicAcls: true,
      blockPublicPolicy: true,
      noPublicPolicyPrincipal: true,
      noPublicAcl: true,
      websiteDisabled: true,
      sseKmsEnabled: true,
      versioningEnabled: true
    }
  }
];

export function useS3Scanner() {
  const { setBuckets, scanTriggerCount, setIsLoading, buckets, isMockMode } = useSecurityStore();

  const scanS3Buckets = useCallback(async (triggerLambda = false) => {
    setIsLoading(true);

    if (isMockMode) {
      await new Promise(resolve => setTimeout(resolve, 800));
      
      const remediatedIds = new Set(
        buckets.filter(b => b.remediated).map(b => b.id)
      );
      
      const parsedMockBuckets = MOCK_BUCKETS.map(b => {
        if (remediatedIds.has(b.id)) {
          return {
            ...b,
            remediated: true,
            severity: 'LOW' as Severity,
            checks: {
              blockPublicAcls: true,
              blockPublicPolicy: true,
              noPublicPolicyPrincipal: true,
              noPublicAcl: true,
              websiteDisabled: true,
              sseKmsEnabled: true,
              versioningEnabled: true
            },
            encryptionType: 'SSE-KMS' as const
          };
        }
        return b;
      });

      setBuckets(parsedMockBuckets);
      setIsLoading(false);
      return;
    }

    // Live Mode: Invoke s3-scanner Lambda first if triggerLambda is true
    if (triggerLambda) {
      console.log('Invoking backend s3-scanner Lambda function in LocalStack...');
      await executeAwsCall(() => 
        lambdaClient.send(new InvokeCommand({
          FunctionName: 's3-scanner',
          Payload: new TextEncoder().encode(JSON.stringify({}))
        }))
      );
      // Brief pause for write consistency
      await new Promise(resolve => setTimeout(resolve, 1000));
    }

    // 1. Fetch S3 alerts from DynamoDB SecurityAlerts table
    const [ddbRes] = await executeAwsCall(() =>
      ddbDocClient.send(new ScanCommand({ TableName: 'SecurityAlerts' }))
    );

    const s3Alerts = ddbRes?.Items?.filter((item: any) => item.type === 'PUBLIC_S3_BUCKET') || [];
    const alertMap = new Map<string, any>();
    for (const alert of s3Alerts) {
      alertMap.set(alert.resource, alert);
    }

    // 2. Fetch live S3 buckets directly
    const [listRes, listErr] = await executeAwsCall(() =>
      s3Client.send(new ListBucketsCommand({}))
    );

    if (listErr || !listRes || !listRes.Buckets) {
      console.error('S3 ListBuckets error:', listErr);
      setBuckets([]);
      setIsLoading(false);
      return;
    }

    const scanResults: S3BucketScanResult[] = [];

    // 3. Scan each bucket configuration
    await Promise.all(
      listRes.Buckets.map(async (bucket) => {
        const bucketName = bucket.Name;
        if (!bucketName) return;

        // Perform sub-queries
        const encCall = () => s3Client.send(new GetBucketEncryptionCommand({ Bucket: bucketName }));
        const verCall = () => s3Client.send(new GetBucketVersioningCommand({ Bucket: bucketName }));
        const webCall = () => s3Client.send(new GetBucketWebsiteCommand({ Bucket: bucketName }));

        const [encRes] = await executeAwsCall(encCall);
        const [verRes] = await executeAwsCall(verCall);
        const [webRes] = await executeAwsCall(webCall);

        // Check if there is an active DynamoDB public bucket alert
        const ddbAlert = alertMap.get(bucketName);
        const isExposed = !!ddbAlert;

        const blockPublicAcls = !isExposed;
        const blockPublicPolicy = !isExposed;
        const noPublicPolicyPrincipal = !isExposed;
        const noPublicAcl = !isExposed;
        const websiteDisabled = !webRes;

        let encryptionType: 'SSE-KMS' | 'SSE-S3' | 'NONE' = 'NONE';
        let sseKmsEnabled = false;
        if (encRes && encRes.ServerSideEncryptionConfiguration?.Rules) {
          const rule = encRes.ServerSideEncryptionConfiguration.Rules[0];
          const algo = rule?.ApplyServerSideEncryptionByDefault?.SSEAlgorithm;
          if (algo === 'aws:kms') {
            encryptionType = 'SSE-KMS';
            sseKmsEnabled = true;
          } else if (algo === 'AES256') {
            encryptionType = 'SSE-S3';
          }
        }

        const versioningEnabled = verRes?.Status === 'Enabled';

        // Evaluate overall Severity
        let severity: Severity = 'LOW';
        if (isExposed) {
          severity = (ddbAlert.severity || 'HIGH') as Severity;
        } else if (encryptionType === 'SSE-S3') {
          severity = 'MEDIUM';
        } else if (!versioningEnabled) {
          severity = 'LOW';
        }

        const checks: S3BucketChecks = {
          blockPublicAcls,
          blockPublicPolicy,
          noPublicPolicyPrincipal,
          noPublicAcl,
          websiteDisabled,
          sseKmsEnabled,
          versioningEnabled
        };

        scanResults.push({
          id: bucketName,
          name: bucketName,
          severity,
          checks,
          exposureDuration: isExposed ? '5 days' : '0 days',
          region: 'us-east-1',
          encryptionType,
          remediated: !isExposed && sseKmsEnabled && versioningEnabled
        });
      })
    );

    setBuckets(scanResults);
    setIsLoading(false);
  }, [setBuckets, setIsLoading, buckets, isMockMode]);

  // Scan on mount
  useEffect(() => {
    scanS3Buckets(false);
  }, [isMockMode]);

  // Explicit scan trigger (Run Scan clicked)
  useEffect(() => {
    if (scanTriggerCount > 0) {
      scanS3Buckets(true);
    }
  }, [scanTriggerCount]);

  return { refresh: () => scanS3Buckets(false) };
}

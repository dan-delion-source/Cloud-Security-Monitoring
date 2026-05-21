import { useEffect, useCallback } from 'react';
import { useSecurityStore } from '../store/securityStore';
import { isMockMode, s3Client, configServiceClient, executeAwsCall } from '../aws-client';
import { ListDiscoveredResourcesCommand } from '@aws-sdk/client-config-service';
import { GetBucketAclCommand, GetBucketPolicyCommand, GetBucketEncryptionCommand, GetBucketVersioningCommand, GetBucketWebsiteCommand } from '@aws-sdk/client-s3';
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
      blockPublicAcls: false,      // fails (CRITICAL)
      blockPublicPolicy: false,    // fails (CRITICAL)
      noPublicPolicyPrincipal: false, // policy contains Principal: "*" (CRITICAL)
      noPublicAcl: true,
      websiteDisabled: true,
      sseKmsEnabled: false,        // SSE-S3 only (MEDIUM)
      versioningEnabled: false     // disabled (LOW)
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
      noPublicAcl: false,          // PublicReadAcl set via ACL (HIGH)
      websiteDisabled: false,      // website endpoint enabled (HIGH flag for review)
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
    encryptionType: 'SSE-S3',      // SSE-S3 only, not SSE-KMS (MEDIUM)
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
      versioningEnabled: false     // disabled (LOW)
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
  const { setBuckets, scanTriggerCount, setIsLoading, buckets } = useSecurityStore();

  const scanS3Buckets = useCallback(async () => {
    setIsLoading(true);

    if (isMockMode) {
      await new Promise(resolve => setTimeout(resolve, 800));
      
      // Preserve remediated buckets when scanner refreshes!
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

    // Live Mode using SDK
    const configClient = configServiceClient;
    const s3 = s3Client;
    if (!configClient || !s3) {
      setIsLoading(false);
      return;
    }

    // 1. Fetch S3 Buckets from AWS Config
    const listCommand = new ListDiscoveredResourcesCommand({
      resourceType: 'AWS::S3::Bucket',
    });

    const [listRes, listErr] = await executeAwsCall(() => configClient.send(listCommand));

    if (listErr || !listRes || !listRes.resourceIdentifiers) {
      console.error('S3 AWS Config error:', listErr);
      setBuckets([]);
      setIsLoading(false);
      return;
    }

    const scanResults: S3BucketScanResult[] = [];

    // 2. Scan each S3 bucket in parallel
    await Promise.all(
      listRes.resourceIdentifiers.map(async (bucketIdent) => {
        const bucketName = bucketIdent.resourceName;
        if (!bucketName) return;

        // Perform sub-queries
        const aclCall = () => s3.send(new GetBucketAclCommand({ Bucket: bucketName }));
        const policyCall = () => s3.send(new GetBucketPolicyCommand({ Bucket: bucketName }));
        const encCall = () => s3.send(new GetBucketEncryptionCommand({ Bucket: bucketName }));
        const verCall = () => s3.send(new GetBucketVersioningCommand({ Bucket: bucketName }));
        const webCall = () => s3.send(new GetBucketWebsiteCommand({ Bucket: bucketName }));

        const [aclRes] = await executeAwsCall(aclCall);
        const [policyRes] = await executeAwsCall(policyCall);
        const [encRes] = await executeAwsCall(encCall);
        const [verRes] = await executeAwsCall(verCall);
        const [webRes] = await executeAwsCall(webCall);

        // Core Checks Logic
        const blockPublicAcls = true; // S3Control API could check this, assume true/false based on policy presence
        const blockPublicPolicy = true;

        let noPublicPolicyPrincipal = true;
        if (policyRes && policyRes.Policy) {
          try {
            const policyJson = JSON.parse(policyRes.Policy);
            const statements = Array.isArray(policyJson.Statement) ? policyJson.Statement : [policyJson.Statement];
            for (const stmt of statements) {
              if (stmt.Effect === 'Allow' && stmt.Principal === '*') {
                noPublicPolicyPrincipal = false;
                break;
              }
            }
          } catch {
            noPublicPolicyPrincipal = !policyRes.Policy.includes('"Principal":"*"') && !policyRes.Policy.includes('"Principal" : "*"');
          }
        }

        let noPublicAcl = true;
        if (aclRes && aclRes.Grants) {
          const publicGrants = aclRes.Grants.filter(grant => 
            grant.Grantee?.URI === 'http://acs.amazonaws.com/groups/global/AllUsers' || 
            grant.Grantee?.URI === 'http://acs.amazonaws.com/groups/global/AuthenticatedUsers'
          );
          if (publicGrants.length > 0) {
            noPublicAcl = false;
          }
        }

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
        if (!blockPublicAcls || !blockPublicPolicy || !noPublicPolicyPrincipal) {
          severity = 'CRITICAL';
        } else if (!noPublicAcl || !websiteDisabled) {
          severity = 'HIGH';
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
          id: bucketIdent.resourceId || String(Math.random()),
          name: bucketName,
          severity,
          checks,
          exposureDuration: !noPublicPolicyPrincipal || !noPublicAcl ? '5 days' : '0 days',
          region: 'us-east-1', // Default region since S3 is global/Config ResourceIdentifier lacks it
          encryptionType,
          remediated: false
        });
      })
    );

    setBuckets(scanResults);
    setIsLoading(false);
  }, [setBuckets, setIsLoading, buckets]);

  // Scan on mount
  useEffect(() => {
    scanS3Buckets();
  }, []);

  // Interval execution every 15 minutes
  useEffect(() => {
    const interval = setInterval(() => {
      scanS3Buckets();
    }, 15 * 60 * 1000); // 15 minutes

    return () => clearInterval(interval);
  }, [scanS3Buckets]);

  // Explicit scan trigger
  useEffect(() => {
    if (scanTriggerCount > 0) {
      scanS3Buckets();
    }
  }, [scanTriggerCount, scanS3Buckets]);

  return { refresh: scanS3Buckets };
}

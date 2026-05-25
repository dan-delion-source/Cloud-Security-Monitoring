import { useEffect, useCallback } from 'react';
import { useSecurityStore } from '../store/securityStore';
import { ddbDocClient, lambdaClient, executeAwsCall } from '../aws-client';
import { ScanCommand } from '@aws-sdk/lib-dynamodb';
import { InvokeCommand } from '@aws-sdk/client-lambda';
import type { IamAnomaly } from '../types/iam';
import type { Severity } from '../constants/severity';

const MOCK_IAM_ANOMALIES: IamAnomaly[] = [
  {
    id: 'iam-anomaly-01',
    severity: 'CRITICAL',
    title: 'Anomalous ConsoleLogin by AWS Account Root',
    detail: 'arn:aws:iam::123456789012:root · Sign-in from unknown subnet 198.51.100.42 (No MFA)',
    actionText: 'Investigate ↗',
    pattern: 'root_login',
    timestamp: new Date(Date.now() - 4 * 60000).toISOString(),
    resourceArn: 'arn:aws:iam::123456789012:root',
    rawEvent: JSON.stringify({
      eventName: 'ConsoleLogin',
      userIdentity: { type: 'Root', arn: 'arn:aws:iam::123456789012:root' },
      sourceIPAddress: '198.51.100.42',
      additionalEventData: { MFAUsed: 'No' },
      timestamp: new Date(Date.now() - 4 * 60000).toISOString()
    }, null, 2)
  },
  {
    id: 'iam-anomaly-02',
    severity: 'CRITICAL',
    title: 'Privilege Escalation: PassRole coupled with CreateFunction',
    detail: 'arn:aws:sts::123456789012:assumed-role/DevOperator · iam:PassRole & lambda:CreateFunction in 5-min session window',
    actionText: 'Investigate ↗',
    pattern: 'passrole_privesc',
    timestamp: new Date(Date.now() - 12 * 60000).toISOString(),
    resourceArn: 'arn:aws:iam::123456789012:role/AdministratorAccessRole',
    rawEvent: JSON.stringify({
      sessionEvents: [
        { eventName: 'PassRole', timestamp: new Date(Date.now() - 14 * 60000).toISOString(), user: 'DevOperator' },
        { eventName: 'CreateFunction20150331', timestamp: new Date(Date.now() - 12 * 60000).toISOString(), user: 'DevOperator', details: 'bypass-backdoor' }
      ]
    }, null, 2)
  },
  {
    id: 'iam-anomaly-03',
    severity: 'HIGH',
    title: 'Cross-Account sts:AssumeRole Delegation Bypass',
    detail: 'sts:AssumeRole called from untrusted external account 999988887777 (ExternalAttacker)',
    actionText: 'Review ↗',
    pattern: 'foreign_sts_assume',
    timestamp: new Date(Date.now() - 150 * 60000).toISOString(),
    resourceArn: 'arn:aws:iam::123456789012:role/OrganizationAccountAccessRole',
    rawEvent: JSON.stringify({
      eventName: 'AssumeRole',
      callerAccountId: '999988887777',
      recipientAccountId: '123456789012',
      roleName: 'OrganizationAccountAccessRole',
      externalId: 'attack-vector-123',
      timestamp: new Date(Date.now() - 150 * 60000).toISOString()
    }, null, 2)
  },
  {
    id: 'iam-anomaly-04',
    severity: 'MEDIUM',
    title: 'Active Access Key exceeds security compliance lifetime (> 90 days)',
    detail: 'AccessKey AKIAIOSFODNN7EXAMPLE for IAM user "junior-developer" is 104 days old (active)',
    actionText: 'Rotate ↗',
    pattern: 'access_key_age',
    timestamp: new Date(Date.now() - 12 * 3600000).toISOString(),
    resourceArn: 'arn:aws:iam::123456789012:user/junior-developer',
    rawEvent: JSON.stringify({
      userName: 'junior-developer',
      accessKeyId: 'AKIAIOSFODNN7EXAMPLE',
      createdDate: new Date(Date.now() - 104 * 24 * 3600000).toISOString(),
      ageDays: 104,
      status: 'Active'
    }, null, 2)
  },
  {
    id: 'iam-anomaly-05',
    severity: 'MEDIUM',
    title: 'Highly privileged policy attached to Service Role',
    detail: 'AdministratorAccess policy attached to Amazon EC2 role "S3BackupExecutionServiceRole"',
    actionText: 'Remediate ↗',
    pattern: 'admin_service_role',
    timestamp: new Date(Date.now() - 18 * 3600000).toISOString(),
    resourceArn: 'arn:aws:iam::123456789012:role/S3BackupExecutionServiceRole',
    rawEvent: JSON.stringify({
      roleName: 'S3BackupExecutionServiceRole',
      policyName: 'AdministratorAccess',
      policyArn: 'arn:aws:iam::aws:policy/AdministratorAccess',
      attachedDate: new Date(Date.now() - 18 * 3600000).toISOString()
    }, null, 2)
  },
  {
    id: 'iam-anomaly-06',
    severity: 'LOW',
    title: 'MFA protection disabled for Console-accessible IAM User',
    detail: 'IAM user account "junior-dev" has no active Virtual or Hardware MFA registered',
    actionText: 'Review ↗',
    pattern: 'mfa_missing',
    timestamp: new Date(Date.now() - 24 * 3600000).toISOString(),
    resourceArn: 'arn:aws:iam::123456789012:user/junior-dev',
    rawEvent: JSON.stringify({
      userName: 'junior-dev',
      mfaActive: 'false',
      passwordEnabled: 'true',
      lastLoginDate: new Date(Date.now() - 1 * 24 * 3600000).toISOString()
    }, null, 2)
  }
];

export function useIamReport() {
  const { setIamAnomalies, scanTriggerCount, setIsLoading, isMockMode } = useSecurityStore();

  const scanIamCompliance = useCallback(async (triggerLambda = false) => {
    setIsLoading(true);

    if (isMockMode) {
      await new Promise(resolve => setTimeout(resolve, 700));
      setIamAnomalies(MOCK_IAM_ANOMALIES);
      setIsLoading(false);
      return;
    }

    // Live Mode: Invoke backend iam-detector Lambda first if triggerLambda is true
    if (triggerLambda) {
      console.log('Invoking backend iam-detector Lambda function in LocalStack...');
      await executeAwsCall(() =>
        lambdaClient.send(new InvokeCommand({
          FunctionName: 'iam-detector',
          Payload: new TextEncoder().encode(JSON.stringify({}))
        }))
      );
      // Brief pause for write consistency
      await new Promise(resolve => setTimeout(resolve, 1000));
    }

    // Scan DynamoDB table for IAM compliance alerts
    const [ddbRes, ddbErr] = await executeAwsCall(() =>
      ddbDocClient.send(new ScanCommand({ TableName: 'SecurityAlerts' }))
    );

    if (ddbErr || !ddbRes || !ddbRes.Items) {
      console.error('DynamoDB IAM Alerts Scan Error:', ddbErr);
      setIamAnomalies([]);
      setIsLoading(false);
      return;
    }

    const iamAlerts = ddbRes.Items.filter((item: any) => item.type === 'IAM_MISUSE');

    const anomalies: IamAnomaly[] = iamAlerts.map((item: any) => {
      const isCritical = item.severity === 'CRITICAL';
      return {
        id: item.alertId || String(Math.random()),
        severity: (item.severity || 'LOW') as Severity,
        title: isCritical 
          ? 'Privilege Escalation: Direct AdministratorAccess Attachment' 
          : 'Console User Lacking Multi-Factor Authentication (MFA)',
        detail: item.detail || `Direct compliance violation on IAM user "${item.resource}"`,
        actionText: isCritical ? 'Remediate ↗' : 'Review ↗',
        pattern: isCritical ? 'admin_policy_exposed' : 'mfa_missing',
        timestamp: item.timestamp || new Date().toISOString(),
        resourceArn: `arn:aws:iam::000000000000:user/${item.resource}`,
        rawJson: JSON.stringify(item, null, 2),
        rawEvent: JSON.stringify(item, null, 2)
      };
    });

    setIamAnomalies(anomalies);
    setIsLoading(false);
  }, [setIamAnomalies, setIsLoading, isMockMode]);

  // Scan on mount
  useEffect(() => {
    scanIamCompliance(false);
  }, [isMockMode]);

  // Explicit scan trigger (Run Scan clicked)
  useEffect(() => {
    if (scanTriggerCount > 0) {
      scanIamCompliance(true);
    }
  }, [scanTriggerCount]);

  return { refresh: () => scanIamCompliance(false) };
}

import { useEffect, useCallback } from 'react';
import { useSecurityStore } from '../store/securityStore';
import { isMockMode, iamClient, executeAwsCall } from '../aws-client';
import { GenerateCredentialReportCommand, GetCredentialReportCommand } from '@aws-sdk/client-iam';
import type { IamAnomaly } from '../types/iam';
import { useGuardDuty } from './useGuardDuty';

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
  const { setIamAnomalies, scanTriggerCount, setIsLoading } = useSecurityStore();
  const { fetchGuardDuty } = useGuardDuty();

  const scanIamCompliance = useCallback(async () => {
    setIsLoading(true);

    if (isMockMode) {
      await new Promise(resolve => setTimeout(resolve, 700));
      
      // Fetch GuardDuty finding to append if critical
      const gdFindings = await fetchGuardDuty();
      const gdCriticals = gdFindings
        .filter(f => f.severity >= 7.0 && f.resource.resourceType === 'AccessKey')
        .map(f => ({
          id: f.id,
          severity: 'CRITICAL' as const,
          title: `GuardDuty Critical Alert: ${f.title}`,
          detail: `${f.resource.accessKeyDetails?.userName || 'AccessKey'} · ${f.description}`,
          actionText: 'Investigate ↗' as const,
          pattern: 'guardduty_iam_threat',
          timestamp: f.createdAt,
          resourceArn: `arn:aws:iam::123456789012:user/${f.resource.accessKeyDetails?.userName || 'unknown'}`,
          rawEvent: f.rawJson || JSON.stringify(f, null, 2)
        }));

      setIamAnomalies([...gdCriticals, ...MOCK_IAM_ANOMALIES]);
      setIsLoading(false);
      return;
    }

    // Narrow down global mutable client for TypeScript strict-null narrowing
    const client = iamClient;
    if (!client) {
      setIsLoading(false);
      return;
    }

    // 1. Generate Credential Report
    const genCommand = new GenerateCredentialReportCommand({});
    await executeAwsCall(() => client.send(genCommand));

    // 2. Fetch Credential Report
    const getCommand = new GetCredentialReportCommand({});
    const [reportRes, reportErr] = await executeAwsCall(() => client.send(getCommand));

    if (reportErr || !reportRes || !reportRes.Content) {
      console.error('IAM Credential Report Error:', reportErr);
      setIamAnomalies([]);
      setIsLoading(false);
      return;
    }

    // Decode base64 CSV report content
    const csvContent = new TextDecoder('utf-8').decode(reportRes.Content);
    const lines = csvContent.split('\n');
    const headers = lines[0].split(',');
    
    // Parse CSV headers
    const userIndex = headers.indexOf('user');
    const arnIndex = headers.indexOf('arn');
    const mfaActiveIndex = headers.indexOf('mfa_active');
    const key1ActiveIndex = headers.indexOf('access_key_1_active');
    const key1CreatedIndex = headers.indexOf('access_key_1_last_rotated');
    const key2ActiveIndex = headers.indexOf('access_key_2_active');
    const key2CreatedIndex = headers.indexOf('access_key_2_last_rotated');

    const anomalies: IamAnomaly[] = [];

    // Skip header, parse users
    for (let i = 1; i < lines.length; i++) {
      if (!lines[i]) continue;
      const row = lines[i].split(',');
      const userName = row[userIndex];
      const arn = row[arnIndex];
      const mfaActive = row[mfaActiveIndex] === 'true';
      const key1Active = row[key1ActiveIndex] === 'true';
      const key2Active = row[key2ActiveIndex] === 'true';

      // Check Rule 1: MFA missing for non-root console accessible users
      if (!mfaActive && userName !== '<root_account>') {
        anomalies.push({
          id: `iam-mfa-${userName}`,
          severity: 'LOW',
          title: 'Console user lacking multi-factor authentication (MFA)',
          detail: `${arn} · Virtual/Hardware MFA registration missing`,
          actionText: 'Review ↗',
          pattern: 'mfa_missing',
          timestamp: new Date().toISOString(),
          resourceArn: arn,
          rawJson: JSON.stringify({ userName, mfaActive, arn }, null, 2)
        });
      }

      // Check Rule 2: Access keys > 90 days active
      const checkKeyAge = (active: boolean, rotatedStr: string, keyNum: number) => {
        if (!active || rotatedStr === 'N/A' || !rotatedStr) return;
        const rotateDate = new Date(rotatedStr);
        const ageMs = Date.now() - rotateDate.getTime();
        const ageDays = Math.floor(ageMs / (24 * 3600000));

        if (ageDays > 90) {
          anomalies.push({
            id: `iam-key-age-${userName}-key${keyNum}`,
            severity: 'MEDIUM',
            title: `Active Access Key ${keyNum} exceeds security lifetime (> 90 days)`,
            detail: `${userName} · Access Key age is ${ageDays} days (active)`,
            actionText: 'Rotate ↗',
            pattern: 'access_key_age',
            timestamp: new Date().toISOString(),
            resourceArn: arn,
            rawJson: JSON.stringify({ userName, keyNum, ageDays, rotateDate }, null, 2)
          });
        }
      };

      checkKeyAge(key1Active, row[key1CreatedIndex], 1);
      checkKeyAge(key2Active, row[key2CreatedIndex], 2);
    }

    setIamAnomalies(anomalies);
    setIsLoading(false);
  }, [setIamAnomalies, fetchGuardDuty, scanTriggerCount, setIsLoading]);

  useEffect(() => {
    scanIamCompliance();
  }, []);

  useEffect(() => {
    if (scanTriggerCount > 0) {
      scanIamCompliance();
    }
  }, [scanTriggerCount, scanIamCompliance]);

  return { refresh: scanIamCompliance };
}

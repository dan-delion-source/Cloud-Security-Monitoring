import { useEffect, useCallback, useState } from 'react';
import { useSecurityStore } from '../store/securityStore';
import { ddbDocClient, lambdaClient, iamClient, executeAwsCall } from '../aws-client';
import { ScanCommand } from '@aws-sdk/lib-dynamodb';
import { InvokeCommand } from '@aws-sdk/client-lambda';
import { ListUsersCommand, ListAttachedUserPoliciesCommand, ListMFADevicesCommand } from '@aws-sdk/client-iam';
import type { IamAnomaly } from '../types/iam';
import type { Severity } from '../constants/severity';

export interface IamUser {
  userName: string;
  arn: string;
  createDate: string;
  attachedPolicies: string[];
  mfaActive: boolean;
  complianceStatus: 'COMPLIANT' | 'NON_COMPLIANT';
  findingsCount: number;
}

const MOCK_LIVE_USERS: IamUser[] = [
  {
    userName: 'junior-dev',
    arn: 'arn:aws:iam::123456789012:user/junior-dev',
    createDate: new Date(Date.now() - 30 * 24 * 3600 * 1000).toISOString(),
    attachedPolicies: ['AdministratorAccess'],
    mfaActive: false,
    complianceStatus: 'NON_COMPLIANT',
    findingsCount: 2
  },
  {
    userName: 'john-doe',
    arn: 'arn:aws:iam::123456789012:user/john-doe',
    createDate: new Date(Date.now() - 15 * 24 * 3600 * 1000).toISOString(),
    attachedPolicies: ['AmazonEC2ReadOnlyAccess'],
    mfaActive: true,
    complianceStatus: 'COMPLIANT',
    findingsCount: 0
  },
  {
    userName: 'sec-auditor',
    arn: 'arn:aws:iam::123456789012:user/sec-auditor',
    createDate: new Date(Date.now() - 40 * 24 * 3600 * 1000).toISOString(),
    attachedPolicies: ['SecurityAudit'],
    mfaActive: true,
    complianceStatus: 'COMPLIANT',
    findingsCount: 0
  }
];

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
  }
];

export function useIamReport() {
  const { setIamAnomalies, scanTriggerCount, setIsLoading, isMockMode } = useSecurityStore();
  const [liveUsers, setLiveUsers] = useState<IamUser[]>([]);

  const scanIamCompliance = useCallback(async (triggerLambda = false) => {
    setIsLoading(true);

    if (isMockMode) {
      await new Promise(resolve => setTimeout(resolve, 700));
      setIamAnomalies(MOCK_IAM_ANOMALIES);
      setLiveUsers(MOCK_LIVE_USERS);
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

    // 1. Fetch live IAM user directory directly from LocalStack IAM
    const [listRes, listErr] = await executeAwsCall(() =>
      iamClient.send(new ListUsersCommand({}))
    );

    const users = listRes?.Users || [];
    const scannedUsers: IamUser[] = [];
    const derivedAnomalies: IamAnomaly[] = [];

    if (!listErr && users.length > 0) {
      for (const u of users) {
        const userName = u.UserName || '';
        if (!userName) continue;

        // Fetch attached policies
        const [policiesRes] = await executeAwsCall(() =>
          iamClient.send(new ListAttachedUserPoliciesCommand({ UserName: userName }))
        );
        const policies = policiesRes?.AttachedPolicies?.map(p => p.PolicyName || '') || [];

        // Fetch MFA status
        const [mfaRes] = await executeAwsCall(() =>
          iamClient.send(new ListMFADevicesCommand({ UserName: userName }))
        );
        const mfaActive = (mfaRes?.MFADevices?.length || 0) > 0;

        const hasAdmin = policies.some(name => name.includes('AdministratorAccess'));
        const isNonCompliant = hasAdmin || !mfaActive;

        if (hasAdmin) {
          derivedAnomalies.push({
            id: `iam-admin-${userName}`,
            severity: 'CRITICAL',
            title: 'Direct Privilege Escalation Vector: AdministratorAccess',
            detail: `Direct attachment of highly privileged system administrative policy on IAM user account "${userName}".`,
            actionText: 'Remediate ↗',
            pattern: 'admin_policy_exposed',
            timestamp: u.CreateDate?.toISOString() || new Date().toISOString(),
            resourceArn: u.Arn || `arn:aws:iam::000000000000:user/${userName}`
          });
        }

        if (!mfaActive) {
          derivedAnomalies.push({
            id: `iam-mfa-${userName}`,
            severity: 'MEDIUM',
            title: 'MFA protection disabled for Console-accessible IAM User',
            detail: `IAM user "${userName}" does not have active Multi-Factor Authentication (MFA) enabled.`,
            actionText: 'Review ↗',
            pattern: 'mfa_missing',
            timestamp: u.CreateDate?.toISOString() || new Date().toISOString(),
            resourceArn: u.Arn || `arn:aws:iam::000000000000:user/${userName}`
          });
        }

        scannedUsers.push({
          userName,
          arn: u.Arn || `arn:aws:iam::000000000000:user/${userName}`,
          createDate: u.CreateDate?.toISOString() || new Date().toISOString(),
          attachedPolicies: policies,
          mfaActive,
          complianceStatus: isNonCompliant ? 'NON_COMPLIANT' : 'COMPLIANT',
          findingsCount: (hasAdmin ? 1 : 0) + (!mfaActive ? 1 : 0)
        });
      }
    }

    // 2. Fetch DynamoDB alerts for IAM anomalies to augment (e.g. historical alerts)
    const [ddbRes, ddbErr] = await executeAwsCall(() =>
      ddbDocClient.send(new ScanCommand({ TableName: 'SecurityAlerts' }))
    );

    if (!ddbErr && ddbRes?.Items) {
      const iamAlerts = ddbRes.Items.filter((item: any) => item.type === 'IAM_MISUSE');
      iamAlerts.forEach((item: any) => {
        // Prevent duplicates
        if (!derivedAnomalies.some(a => a.resourceArn.includes(item.resource))) {
          const isCritical = item.severity === 'CRITICAL';
          derivedAnomalies.push({
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
          });
        }
      });
    }

    setIamAnomalies(derivedAnomalies);
    setLiveUsers(scannedUsers.length > 0 ? scannedUsers : MOCK_LIVE_USERS);
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

  return { refresh: () => scanIamCompliance(false), liveUsers };
}

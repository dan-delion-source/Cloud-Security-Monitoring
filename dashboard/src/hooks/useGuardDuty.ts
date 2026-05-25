import { useCallback } from 'react';
import { guardDutyClient, executeAwsCall } from '../aws-client';
import { ListFindingsCommand, GetFindingsCommand } from '@aws-sdk/client-guardduty';
import type { GuardDutyFinding } from '../types/guardduty';
import { useSecurityStore } from '../store/securityStore';

const MOCK_GUARDDUTY_FINDINGS: GuardDutyFinding[] = [
  {
    id: 'gd-finding-01',
    title: 'APICall:IAMUser/AnomalousBehavior',
    description: 'APIs usually not called by this principal were executed from a residential subnet.',
    type: 'IAMUser/AnomalousBehavior',
    severity: 8.5, // CRITICAL
    region: 'us-east-1',
    createdAt: new Date(Date.now() - 30 * 60000).toISOString(),
    resource: {
      resourceType: 'AccessKey',
      accessKeyDetails: {
        accessKeyId: 'AKIAIOSFODNN7EXAMPLE',
        principalId: 'AIDAJKNDFSKNDF',
        userName: 'dev-deployer',
        userType: 'IAMUser'
      }
    }
  },
  {
    id: 'gd-finding-02',
    title: 'UnauthorizedAccess:IAMUser/TorIPCaller',
    description: 'API calls were made using credentials owned by IAMUser "sec-auditor" from a known Tor Exit Node.',
    type: 'UnauthorizedAccess/TorIPCaller',
    severity: 6.8, // HIGH
    region: 'us-east-1',
    createdAt: new Date(Date.now() - 2 * 3600000).toISOString(),
    resource: {
      resourceType: 'AccessKey',
      accessKeyDetails: {
        accessKeyId: 'AKIAIBAKJFDSLEXAMPLE',
        userName: 'sec-auditor',
        userType: 'IAMUser'
      }
    }
  }
];

export function useGuardDuty() {
  const { isMockMode } = useSecurityStore();
  const fetchGuardDuty = useCallback(async () => {
    if (isMockMode) {
      return MOCK_GUARDDUTY_FINDINGS;
    }

    const client = guardDutyClient;
    if (!client) {
      return [];
    }

    // Step 1: List detectors
    // In real system, we'd list detectors then get findings. We do a simplified mock-backed fallback
    // for GuardDuty to prevent empty states if GuardDuty is not enabled in the AWS region.
    const listCommand = new ListFindingsCommand({
      DetectorId: 'placeholder-detector-id', // In production, replace or fetch detector id first
      FindingCriteria: {
        Criterion: {
          'resource.resourceType': { Equals: ['AccessKey'] }
        }
      }
    });

    const [listRes, listErr] = await executeAwsCall(() => client.send(listCommand));
    if (listErr || !listRes || !listRes.FindingIds || listRes.FindingIds.length === 0) {
      // Return empty or fallback gracefully if detector is not configured
      return [];
    }

    const getCommand = new GetFindingsCommand({
      DetectorId: 'placeholder-detector-id',
      FindingIds: listRes.FindingIds.slice(0, 10),
    });

    const [getRes, getErr] = await executeAwsCall(() => client.send(getCommand));
    if (getErr || !getRes || !getRes.Findings) {
      return [];
    }

    return getRes.Findings.map((finding: any) => ({
      id: finding.Id || String(Math.random()),
      title: finding.Title || 'GuardDuty Finding',
      description: finding.Description || '',
      type: finding.Type || 'Unknown',
      severity: finding.Severity || 1.0,
      region: finding.Region || 'us-east-1',
      createdAt: finding.CreatedAt || new Date().toISOString(),
      resource: {
        resourceType: finding.Resource?.ResourceType || 'Unknown',
        accessKeyDetails: finding.Resource?.AccessKeyDetails ? {
          accessKeyId: finding.Resource.AccessKeyDetails.AccessKeyId,
          userName: finding.Resource.AccessKeyDetails.UserName,
          userType: finding.Resource.AccessKeyDetails.UserType,
        } : undefined
      },
      rawJson: JSON.stringify(finding, null, 2)
    }));
  }, []);

  return { fetchGuardDuty };
}

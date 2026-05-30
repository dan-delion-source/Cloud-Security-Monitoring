import { useState, useEffect, useCallback } from 'react';
import { useSecurityStore } from '../store/securityStore';
import { cloudWatchLogsClient, executeAwsCall } from '../aws-client';
import { DescribeLogGroupsCommand, FilterLogEventsCommand } from '@aws-sdk/client-cloudwatch-logs';

export interface LogGroupInfo {
  logGroupName: string;
  creationTime?: number;
  storedBytes?: number;
}

export interface LogStreamInfo {
  logStreamName: string;
  creationTime?: number;
  lastEventTimestamp?: number;
}

export interface LogEventInfo {
  eventId: string;
  timestamp: number;
  message: string;
}

const MOCK_GROUPS: LogGroupInfo[] = [
  { logGroupName: '/aws/lambda/s3-scanner', creationTime: Date.now() - 1000 * 3600, storedBytes: 1024 },
  { logGroupName: '/aws/lambda/iam-detector', creationTime: Date.now() - 1000 * 3600 * 2, storedBytes: 2048 },
  { logGroupName: '/aws/lambda/suspicious-login', creationTime: Date.now() - 1000 * 3600 * 3, storedBytes: 512 },
  { logGroupName: '/aws/lambda/unauth-detector', creationTime: Date.now() - 1000 * 3600 * 4, storedBytes: 4096 }
];

const MOCK_EVENTS_MAP: Record<string, string[]> = {
  '/aws/lambda/s3-scanner': [
    '2026-05-28T00:10:05.120Z\tINFO\tStarting S3 compliance and access control scan...',
    '2026-05-28T00:10:05.340Z\tINFO\tDescribing all buckets in us-east-1 region...',
    '2026-05-28T00:10:05.780Z\tINFO\tAnalyzing bucket: public-assets-static-website...',
    '2026-05-28T00:10:05.990Z\tWARN\tVULNERABILITY FOUND: Bucket "public-assets-static-website" has a Public Policy allowing global read/write Principal (*).',
    '2026-05-28T00:10:06.110Z\tINFO\tAnalyzing bucket: secure-customer-pii-kms...',
    '2026-05-28T00:10:06.320Z\tINFO\tBucket secure-customer-pii-kms is encrypted with AWS KMS and versioning is enabled. (Compliant)',
    '2026-05-28T00:10:06.450Z\tINFO\tScan complete. 1 critical alert generated and written to DynamoDB:SecurityAlerts.'
  ],
  '/aws/lambda/iam-detector': [
    '2026-05-28T00:12:12.302Z\tINFO\tInitializing IAM User privilege escalation scan...',
    '2026-05-28T00:12:12.510Z\tINFO\tFound 2 IAM Users inside LocalStack IAM directory.',
    '2026-05-28T00:12:12.920Z\tINFO\tAuditing user permissions for: junior-dev...',
    '2026-05-28T00:12:13.150Z\tWARN\tCOMPLIANCE BREACH: User "junior-dev" has policy "AdministratorAccess" directly attached to their user account.',
    '2026-05-28T00:12:13.290Z\tWARN\tCOMPLIANCE BREACH: User "junior-dev" has password login enabled but lacks active Multi-Factor Authentication (MFA).',
    '2026-05-28T00:12:13.410Z\tINFO\tAuditing user permissions for: john-doe...',
    '2026-05-28T00:12:13.720Z\tINFO\tUser john-doe is compliant. Virtual MFA is enabled and no direct admin policies exist.',
    '2026-05-28T00:12:13.880Z\tINFO\tScanning complete. Active anomalies reported to posture controller.'
  ],
  '/aws/lambda/suspicious-login': [
    '2026-05-28T00:14:22.091Z\tINFO\tLaunching ConsoleLogin heuristics engine...',
    '2026-05-28T00:14:22.420Z\tINFO\tConnecting S3 client to bucket: cloudtrail-logs...',
    '2026-05-28T00:14:22.950Z\tINFO\tFetched 1 audit log from bucket path: CloudTrail/us-east-1/2026/05/25/...',
    '2026-05-28T00:14:23.210Z\tWARN\tTHREAT ALERT: Successful ConsoleLogin detected by principal junior-dev from IP 45.227.254.12.',
    '2026-05-28T00:14:23.330Z\tWARN\tTHREAT ALERT: MFA was NOT used for ConsoleLogin by junior-dev. Threat score: 92/100.',
    '2026-05-28T00:14:23.510Z\tINFO\tTriggered security alert for SUSPICIOUS_LOGIN.'
  ],
  '/aws/lambda/unauth-detector': [
    '2026-05-28T00:15:00.010Z\tINFO\tSQS event source trigger received batch of 1 message.',
    '2026-05-28T00:15:00.120Z\tINFO\tProcessing SNS-SQS boundary alert message from security-alerts topic...',
    '2026-05-28T00:15:00.430Z\tWARN\tBOUNDARY BREACH: Detected direct request to Application ALB bypassing CloudFront origin shield checks.',
    '2026-05-28T00:15:00.610Z\tWARN\tSource IP: 185.220.101.5 (Untrusted public subnet). Severity: CRITICAL.',
    '2026-05-28T00:15:00.750Z\tINFO\tWriting incident metrics to DynamoDB and executing webhook notify.',
    '2026-05-28T00:15:00.820Z\tINFO\tMessage batch successfully processed and acknowledged.'
  ]
};

export function useCloudWatch() {
  const { isMockMode } = useSecurityStore();
  const [logGroups, setLogGroups] = useState<LogGroupInfo[]>([]);
  const [isLoading, setIsLoading] = useState(false);
  const [logEvents, setLogEvents] = useState<LogEventInfo[]>([]);

  // Fetch Log Groups
  const fetchLogGroups = useCallback(async () => {
    setIsLoading(true);
    if (isMockMode) {
      setLogGroups(MOCK_GROUPS);
      setIsLoading(false);
      return;
    }

    const [res, err] = await executeAwsCall(() =>
      cloudWatchLogsClient.send(new DescribeLogGroupsCommand({}))
    );

    if (err || !res || !res.logGroups) {
      console.warn('Could not fetch CloudWatch Log Groups:', err);
      // Fallback to mock log groups in case LocalStack is empty/erroring
      setLogGroups(MOCK_GROUPS);
      setIsLoading(false);
      return;
    }

    const groups: LogGroupInfo[] = res.logGroups.map((g) => ({
      logGroupName: g.logGroupName || '',
      creationTime: g.creationTime,
      storedBytes: g.storedBytes
    }));

    // Ensure our standard groups are at least listed
    const existingNames = new Set(groups.map(g => g.logGroupName));
    MOCK_GROUPS.forEach(g => {
      if (!existingNames.has(g.logGroupName)) {
        groups.push(g);
      }
    });

    setLogGroups(groups);
    setIsLoading(false);
  }, [isMockMode]);

  // Fetch Log Events for a specific Log Group
  const fetchLogEvents = useCallback(async (logGroupName: string) => {
    setIsLoading(true);
    if (isMockMode) {
      await new Promise((resolve) => setTimeout(resolve, 400));
      const messages = MOCK_EVENTS_MAP[logGroupName] || ['[INFO] Log stream empty.'];
      const events: LogEventInfo[] = messages.map((msg, idx) => ({
        eventId: `mock-event-${idx}`,
        timestamp: Date.now() - (messages.length - idx) * 5000,
        message: msg
      }));
      setLogEvents(events);
      setIsLoading(false);
      return;
    }

    // Filter events across all streams in the group for ease
    const [res, err] = await executeAwsCall(() =>
      cloudWatchLogsClient.send(new FilterLogEventsCommand({
        logGroupName,
        limit: 100
      }))
    );

    if (err || !res || !res.events) {
      console.warn(`Could not filter events for log group ${logGroupName}:`, err);
      // Fallback to mock logs if live is empty (e.g. Lambda hasn't run yet)
      const messages = MOCK_EVENTS_MAP[logGroupName] || [`[INFO] Live Log stream for ${logGroupName} is currently empty.`];
      const events: LogEventInfo[] = messages.map((msg, idx) => ({
        eventId: `mock-event-${idx}`,
        timestamp: Date.now() - (messages.length - idx) * 5000,
        message: msg
      }));
      setLogEvents(events);
      setIsLoading(false);
      return;
    }

    const events: LogEventInfo[] = res.events.map((e) => ({
      eventId: e.eventId || String(Math.random()),
      timestamp: e.timestamp || Date.now(),
      message: e.message || ''
    }));

    // Sort by timestamp asc for terminal-style flow
    events.sort((a, b) => a.timestamp - b.timestamp);

    setLogEvents(events);
    setIsLoading(false);
  }, [isMockMode]);

  // Automatically fetch groups on mount
  useEffect(() => {
    fetchLogGroups();
  }, [fetchLogGroups]);

  return {
    logGroups,
    logEvents,
    isLoading,
    refreshGroups: fetchLogGroups,
    refreshEvents: fetchLogEvents
  };
}

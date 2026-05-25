import { useEffect, useCallback } from 'react';
import { useSecurityStore } from '../store/securityStore';
import { ddbDocClient, executeAwsCall } from '../aws-client';
import { ScanCommand } from '@aws-sdk/lib-dynamodb';
import type { ParsedLog } from '../types/cloudtrail';
import { evaluateLogSeverity } from '../utils/severity';
import type { Severity } from '../constants/severity';

const MOCK_EVENTS = [
  {
    eventID: 'ct-event-101',
    eventName: 'ConsoleLogin',
    eventSource: 'signin.amazonaws.com',
    eventTime: new Date(Date.now() - 4 * 60000).toISOString(),
    userIdentity: { type: 'Root', arn: 'arn:aws:iam::123456789012:root', userName: 'root', accountId: '123456789012' },
    sourceIPAddress: '198.51.100.42',
    awsRegion: 'us-east-1',
    responseElements: { ConsoleLogin: 'Success' },
    additionalEventData: { MFAUsed: 'No' }
  },
  {
    eventID: 'ct-event-102',
    eventName: 'CreateFunction20150331',
    eventSource: 'lambda.amazonaws.com',
    eventTime: new Date(Date.now() - 12 * 60000).toISOString(),
    userIdentity: { type: 'AssumedRole', arn: 'arn:aws:sts::123456789012:assumed-role/DevOperator/Session1', userName: 'DevOperator', accountId: '123456789012' },
    sourceIPAddress: '203.0.113.85',
    awsRegion: 'us-east-1',
    requestParameters: { functionName: 'auth-bypass-backdoor', runtime: 'nodejs18.x' }
  },
  {
    eventID: 'ct-event-103',
    eventName: 'PassRole',
    eventSource: 'iam.amazonaws.com',
    eventTime: new Date(Date.now() - 14 * 60000).toISOString(),
    userIdentity: { type: 'AssumedRole', arn: 'arn:aws:sts::123456789012:assumed-role/DevOperator/Session1', userName: 'DevOperator', accountId: '123456789012' },
    sourceIPAddress: '203.0.113.85',
    awsRegion: 'us-east-1',
    requestParameters: { roleArn: 'arn:aws:iam::123456789012:role/AdministratorAccessRole' }
  },
  {
    eventID: 'ct-event-104',
    eventName: 'PutBucketPolicy',
    eventSource: 's3.amazonaws.com',
    eventTime: new Date(Date.now() - 32 * 60000).toISOString(),
    userIdentity: { type: 'IAMUser', arn: 'arn:aws:iam::123456789012:user/temp-service-account', userName: 'temp-service-account', accountId: '123456789012' },
    sourceIPAddress: '185.220.101.4',
    awsRegion: 'us-west-2',
    requestParameters: { bucketName: 'prod-finance-reports-s3', bucketPolicy: '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::prod-finance-reports-s3/*"}]}' }
  },
  {
    eventID: 'ct-event-105',
    eventName: 'StartSession',
    eventSource: 'ssm.amazonaws.com',
    eventTime: new Date(Date.now() - 45 * 60000).toISOString(),
    userIdentity: { type: 'IAMUser', arn: 'arn:aws:iam::123456789012:user/sec-auditor', userName: 'sec-auditor', accountId: '123456789012' },
    sourceIPAddress: '198.51.100.99',
    awsRegion: 'us-east-1',
    requestParameters: { target: 'i-0abcd1234efgh5678' }
  },
  {
    eventID: 'ct-event-106',
    eventName: 'AttachUserPolicy',
    eventSource: 'iam.amazonaws.com',
    eventTime: new Date(Date.now() - 1.2 * 3600000).toISOString(),
    userIdentity: { type: 'IAMUser', arn: 'arn:aws:iam::123456789012:user/junior-dev', userName: 'junior-dev', accountId: '123456789012' },
    sourceIPAddress: '12.44.180.201',
    awsRegion: 'us-east-1',
    requestParameters: { userName: 'junior-dev', policyArn: 'arn:aws:iam::aws:policy/AdministratorAccess' }
  },
  {
    eventID: 'ct-event-107',
    eventName: 'DescribeInstances',
    eventSource: 'ec2.amazonaws.com',
    eventTime: new Date(Date.now() - 1.5 * 3600000).toISOString(),
    userIdentity: { type: 'AssumedRole', arn: 'arn:aws:sts::123456789012:assumed-role/ReadOnlySession/operator', userName: 'operator', accountId: '123456789012' },
    sourceIPAddress: '192.168.1.100',
    awsRegion: 'us-east-1'
  },
  {
    eventID: 'ct-event-108',
    eventName: 'ListBuckets',
    eventSource: 's3.amazonaws.com',
    eventTime: new Date(Date.now() - 1.8 * 3600000).toISOString(),
    userIdentity: { type: 'IAMUser', arn: 'arn:aws:iam::123456789012:user/read-only-user', userName: 'read-only-user' },
    sourceIPAddress: '10.0.4.52',
    awsRegion: 'us-east-1'
  },
  {
    eventID: 'ct-event-109',
    eventName: 'AssumeRole',
    eventSource: 'sts.amazonaws.com',
    eventTime: new Date(Date.now() - 2.5 * 3600000).toISOString(),
    userIdentity: { type: 'AssumedRole', arn: 'arn:aws:sts::999988887777:assumed-role/ExternalAttacker/hacking', userName: 'ExternalAttacker', accountId: '999988887777' },
    sourceIPAddress: '45.227.254.12',
    awsRegion: 'us-east-1',
    requestParameters: { roleArn: 'arn:aws:iam::123456789012:role/OrganizationAccountAccessRole', externalId: 'attack-vector-123' }
  },
  {
    eventID: 'ct-event-110',
    eventName: 'GetUser',
    eventSource: 'iam.amazonaws.com',
    eventTime: new Date(Date.now() - 3 * 3600000).toISOString(),
    userIdentity: { type: 'IAMUser', arn: 'arn:aws:iam::123456789012:user/john-doe', userName: 'john-doe' },
    sourceIPAddress: '192.168.15.22',
    awsRegion: 'us-east-1'
  }
];

export function useCloudTrail() {
  const { prependLogs, setLogs, scanTriggerCount, setIsLoading, isMockMode, setActiveAlerts } = useSecurityStore();

  const fetchCloudTrail = useCallback(async (isInitial = false) => {
    setIsLoading(true);
    
    if (isMockMode) {
      // Simulate network delay
      await new Promise(resolve => setTimeout(resolve, 800));
      
      const parsedMockLogs: ParsedLog[] = MOCK_EVENTS.map(event => {
        const userId = event.userIdentity;
        const arn = userId.arn || `arn:aws:iam::123456789012:${userId.type === 'Root' ? 'root' : userId.userName || 'unknown'}`;
        
        return {
          id: event.eventID,
          timestamp: event.eventTime,
          eventName: event.eventName,
          eventSource: event.eventSource.split('.')[0],
          principalArn: arn,
          sourceIP: event.sourceIPAddress,
          severity: evaluateLogSeverity(
            event.eventName,
            userId,
            event.eventSource,
            event.requestParameters
          ),
          rawJson: JSON.stringify(event, null, 2),
          awsRegion: event.awsRegion,
        };
      });
      
      // Sort desc
      parsedMockLogs.sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime());
      
      if (isInitial) {
        setLogs(parsedMockLogs);
      } else {
        // Prepend new simulated logs for polling/scan trigger demonstration
        const pollingTime = new Date().toISOString();
        const demoPollEvent: ParsedLog = {
          id: `ct-poll-${Date.now()}`,
          timestamp: pollingTime,
          eventName: 'ConsoleLogin',
          eventSource: 'signin',
          principalArn: 'arn:aws:iam::123456789012:root',
          sourceIP: '109.112.54.120',
          severity: 'CRITICAL',
          rawJson: JSON.stringify({
            eventID: `ct-poll-${Date.now()}`,
            eventName: 'ConsoleLogin',
            eventSource: 'signin.amazonaws.com',
            eventTime: pollingTime,
            userIdentity: { type: 'Root', arn: 'arn:aws:iam::123456789012:root', userName: 'root' },
            sourceIPAddress: '109.112.54.120',
            awsRegion: 'us-east-1',
            responseElements: { ConsoleLogin: 'Success' },
            additionalEventData: { MFAUsed: 'No', Alert: 'Suspicious IP' }
          }, null, 2),
          awsRegion: 'us-east-1',
        };
        
        prependLogs([demoPollEvent]);
      }
      setIsLoading(false);
      return;
    }

    // Live Mode: Scan SecurityAlerts DynamoDB Table
    const [response, error] = await executeAwsCall(() => 
      ddbDocClient.send(new ScanCommand({ TableName: 'SecurityAlerts' }))
    );

    if (error || !response || !response.Items) {
      console.error('DynamoDB Alerts Scan Error:', error);
      setLogs([]);
      setIsLoading(false);
      return;
    }

    // Map DynamoDB SecurityAlerts items to ParsedLog
    const parsedLogs: ParsedLog[] = response.Items.map((item: any) => {
      let eventSource = 'signin';
      if (item.type === 'PUBLIC_S3_BUCKET') {
        eventSource = 's3';
      } else if (item.type === 'IAM_MISUSE') {
        eventSource = 'iam';
      }
      
      const principalArn = item.type === 'IAM_MISUSE' 
        ? `arn:aws:iam::000000000000:user/${item.resource}` 
        : 'arn:aws:iam::000000000000:root';
        
      return {
        id: item.alertId || String(Math.random()),
        timestamp: item.timestamp || new Date().toISOString(),
        eventName: item.type,
        eventSource,
        principalArn,
        sourceIP: item.type === 'SUSPICIOUS_LOGIN' || item.type === 'UNAUTHORIZED_ACCESS' ? item.resource : '127.0.0.1',
        severity: (item.severity || 'LOW') as Severity,
        rawJson: JSON.stringify(item, null, 2),
        awsRegion: 'us-east-1',
      };
    });

    parsedLogs.sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime());

    // Reset active alerts dynamically so Overview rebuilds them
    setActiveAlerts([]);

    if (isInitial) {
      setLogs(parsedLogs);
    } else {
      prependLogs(parsedLogs);
    }
    
    setIsLoading(false);
  }, [prependLogs, setLogs, setIsLoading, isMockMode, setActiveAlerts]);

  // Initial load
  useEffect(() => {
    fetchCloudTrail(true);
  }, [isMockMode]);

  // Scan triggers
  useEffect(() => {
    if (scanTriggerCount > 0) {
      fetchCloudTrail(false);
    }
  }, [scanTriggerCount, fetchCloudTrail]);

  // Live polling every 30 seconds (faster for local demo)
  useEffect(() => {
    const interval = setInterval(() => {
      fetchCloudTrail(false);
    }, 30000);

    return () => clearInterval(interval);
  }, [fetchCloudTrail]);

  return { refresh: () => fetchCloudTrail(false) };
}

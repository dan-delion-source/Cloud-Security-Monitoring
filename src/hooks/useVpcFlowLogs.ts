import { useEffect, useCallback } from 'react';
import { useSecurityStore } from '../store/securityStore';
import type { UnauthorizedEvent } from '../store/securityStore';
import { isMockMode, cloudWatchLogsClient, executeAwsCall } from '../aws-client';
import { StartQueryCommand, GetQueryResultsCommand } from '@aws-sdk/client-cloudwatch-logs';
import { isPrivateIp } from '../utils/ipUtils';

const MOCK_UNAUTHORIZED_EVENTS: UnauthorizedEvent[] = [
  {
    id: 'unauth-event-01',
    severity: 'CRITICAL',
    description: 'Lambda invocation made without credentials (Anonymous identity)',
    source: 'Anonymous (Public API Gateway)',
    destination: 'arn:aws:lambda:us-east-1:123456789012:function:process-payment',
    timestamp: new Date(Date.now() - 10 * 60000).toISOString(),
    routeType: 'Unauth invoke',
    sourceIP: '198.51.100.72',
    rawJson: JSON.stringify({
      eventVersion: '1.08',
      userIdentity: {
        type: 'Anonymous',
        principalId: 'anonymous',
        arn: 'anonymous'
      },
      eventTime: new Date(Date.now() - 10 * 60000).toISOString(),
      eventSource: 'lambda.amazonaws.com',
      eventName: 'Invoke',
      awsRegion: 'us-east-1',
      sourceIPAddress: '198.51.100.72',
      userAgent: 'PostmanRuntime/7.29.2',
      requestParameters: {
        functionName: 'process-payment',
        invocationType: 'RequestResponse'
      }
    }, null, 2)
  },
  {
    id: 'unauth-event-02',
    severity: 'HIGH',
    description: 'S3 GetObject attempt from untrusted public IP (non-RFC1918 range)',
    source: '45.142.120.9',
    destination: 's3://prod-financials-confidential',
    timestamp: new Date(Date.now() - 25 * 60000).toISOString(),
    routeType: 'Public IP',
    sourceIP: '45.142.120.9',
    rawJson: JSON.stringify({
      bucketName: 'prod-financials-confidential',
      key: 'Q4_2025_earnings.xlsx',
      sourceIPAddress: '45.142.120.9',
      userAgent: 'aws-cli/2.9.2 Python/3.9.11',
      action: 's3:GetObject',
      statusCode: 200,
      byteCount: 4291823,
      requestTime: new Date(Date.now() - 25 * 60000).toISOString()
    }, null, 2)
  },
  {
    id: 'unauth-event-03',
    severity: 'HIGH',
    description: 'Application origin server bypassed: x-origin-verify verification header missing',
    source: '185.220.101.5',
    destination: 'Application ALB (Origin Direct)',
    timestamp: new Date(Date.now() - 50 * 60000).toISOString(),
    routeType: 'CF bypass',
    sourceIP: '185.220.101.5',
    rawJson: JSON.stringify({
      httpRequest: {
        clientIp: '185.220.101.5',
        requestUrl: 'http://alb-production-origin-1982.us-east-1.elb.amazonaws.com/api/admin',
        headers: {
          Host: 'alb-production-origin-1982.us-east-1.elb.amazonaws.com',
          UserAgent: 'curl/7.81.0',
          Accept: '*/*'
        }
      },
      securityCheck: {
        originShieldHeaderPresent: false,
        action: 'FORWARDED_TO_BACKEND'
      },
      timestamp: new Date(Date.now() - 50 * 60000).toISOString()
    }, null, 2)
  },
  {
    id: 'unauth-event-04',
    severity: 'MEDIUM',
    description: 'Sensitive EC2 API call executed without transit gateway or private VPC endpoint',
    source: 'i-0ff2382cdefab9812 (VPC Subnet)',
    destination: 'secretsmanager.amazonaws.com',
    timestamp: new Date(Date.now() - 120 * 60000).toISOString(),
    routeType: 'No VPC endpoint',
    sourceIP: '172.31.42.115',
    rawJson: JSON.stringify({
      eventSource: 'secretsmanager.amazonaws.com',
      eventName: 'GetSecretValue',
      awsRegion: 'us-east-1',
      vpcEndpointId: null, // Critical flag - VPC endpoint is missing!
      sourceIPAddress: '172.31.42.115',
      userIdentity: {
        type: 'AssumedRole',
        arn: 'arn:aws:sts::123456789012:assumed-role/EC2AppInstanceRole/i-0ff2382cdefab9812'
      },
      requestParameters: {
        secretId: 'production/db/password'
      },
      timestamp: new Date(Date.now() - 120 * 60000).toISOString()
    }, null, 2)
  }
];

export function useVpcFlowLogs() {
  const { setUnauthorizedEvents, scanTriggerCount, setIsLoading } = useSecurityStore();

  const fetchUnauthEvents = useCallback(async () => {
    setIsLoading(true);

    if (isMockMode) {
      await new Promise(resolve => setTimeout(resolve, 600));
      
      // Filter out any private IPs or evaluate rules to double-check
      const validatedEvents = MOCK_UNAUTHORIZED_EVENTS.map(evt => {
        // Re-evaluate client side logic for demonstration / validation
        if (evt.routeType === 'Public IP' && isPrivateIp(evt.sourceIP)) {
          // If mock IP changed to private, it wouldn't be unauthorized
          evt.severity = 'LOW';
        }
        return evt;
      });
      
      setUnauthorizedEvents(validatedEvents);
      setIsLoading(false);
      return;
    }

    // Live Mode using @aws-sdk/client-cloudwatch-logs Insights Query
    const client = cloudWatchLogsClient;
    if (!client) {
      setIsLoading(false);
      return;
    }

    // Query 1: S3 Server Access Logs / CloudTrail API calls
    // Query 2: VPC Flow Logs with action REJECT
    const query = `
      fields @timestamp, srcAddr, dstAddr, action, interfaceId
      | filter action = "REJECT"
      | sort @timestamp desc
      | limit 10
    `;

    const startCommand = new StartQueryCommand({
      logGroupName: '/aws/vpc/flowlogs',
      queryString: query,
      startTime: Math.floor((Date.now() - 24 * 3600000) / 1000), // last 24h
      endTime: Math.floor(Date.now() / 1000),
    });

    const [startRes, startErr] = await executeAwsCall(() => client.send(startCommand));

    if (startErr || !startRes || !startRes.queryId) {
      console.warn('VPC Flow Log query failed to start, falling back to empty feed');
      setUnauthorizedEvents([]);
      setIsLoading(false);
      return;
    }

    // Poll for query results (maximum 5 attempts)
    const queryId = startRes.queryId;
    let queryResults: any = null;
    let attempts = 0;
    
    while (attempts < 5) {
      await new Promise(resolve => setTimeout(resolve, 1000));
      const getCommand = new GetQueryResultsCommand({ queryId });
      const [res, err] = await executeAwsCall(() => client.send(getCommand));
      
      if (!err && res && res.status === 'Complete') {
        queryResults = res.results;
        break;
      }
      attempts++;
    }

    if (!queryResults) {
      setUnauthorizedEvents([]);
      setIsLoading(false);
      return;
    }

    const parsedEvents: UnauthorizedEvent[] = queryResults.map((row: any[], index: number) => {
      const getVal = (field: string) => row.find(f => f.field === field)?.value || '';
      const timestamp = getVal('@timestamp');
      const srcAddr = getVal('srcAddr');
      const dstAddr = getVal('dstAddr');
      const interfaceId = getVal('interfaceId');

      // VPC REJECT is high severity in network monitoring
      const severity = 'HIGH';

      return {
        id: `flow-${index}-${timestamp}`,
        severity,
        description: `VPC Network flow REJECT on ENI ${interfaceId}`,
        source: `${srcAddr} (External)`,
        destination: `${dstAddr} (${interfaceId})`,
        timestamp: new Date(timestamp).toISOString(),
        routeType: 'Public IP',
        sourceIP: srcAddr,
        rawJson: JSON.stringify({
          message: 'VPC Flow Log record REJECT action detected',
          timestamp,
          sourceAddress: srcAddr,
          destinationAddress: dstAddr,
          networkInterface: interfaceId,
          action: 'REJECT'
        }, null, 2)
      };
    });

    setUnauthorizedEvents(parsedEvents);
    setIsLoading(false);
  }, [setUnauthorizedEvents, setIsLoading]);

  useEffect(() => {
    fetchUnauthEvents();
  }, []);

  useEffect(() => {
    if (scanTriggerCount > 0) {
      fetchUnauthEvents();
    }
  }, [scanTriggerCount, fetchUnauthEvents]);

  return { refresh: fetchUnauthEvents };
}

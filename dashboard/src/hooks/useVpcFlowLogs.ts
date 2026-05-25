import { useEffect, useCallback } from 'react';
import { useSecurityStore } from '../store/securityStore';
import { ddbDocClient, lambdaClient, executeAwsCall } from '../aws-client';
import { ScanCommand } from '@aws-sdk/lib-dynamodb';
import { InvokeCommand } from '@aws-sdk/client-lambda';
import type { UnauthorizedEvent } from '../store/securityStore';
import type { Severity } from '../constants/severity';

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
      vpcEndpointId: null,
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
  const { setUnauthorizedEvents, scanTriggerCount, setIsLoading, isMockMode } = useSecurityStore();

  const fetchUnauthEvents = useCallback(async (triggerLambda = false) => {
    setIsLoading(true);

    if (isMockMode) {
      await new Promise(resolve => setTimeout(resolve, 600));
      setUnauthorizedEvents(MOCK_UNAUTHORIZED_EVENTS);
      setIsLoading(false);
      return;
    }

    // Live Mode: Invoke detectors if triggerLambda is true
    if (triggerLambda) {
      console.log('Invoking backend unauth-detector and suspicious-login Lambdas in LocalStack...');
      await Promise.all([
        executeAwsCall(() =>
          lambdaClient.send(new InvokeCommand({
            FunctionName: 'unauth-detector',
            Payload: new TextEncoder().encode(JSON.stringify({}))
          }))
        ),
        executeAwsCall(() =>
          lambdaClient.send(new InvokeCommand({
            FunctionName: 'suspicious-login',
            Payload: new TextEncoder().encode(JSON.stringify({}))
          }))
        )
      ]);
      // Brief pause for write consistency
      await new Promise(resolve => setTimeout(resolve, 1000));
    }

    // Scan DynamoDB table for unauthorized/login alert types
    const [ddbRes, ddbErr] = await executeAwsCall(() =>
      ddbDocClient.send(new ScanCommand({ TableName: 'SecurityAlerts' }))
    );

    if (ddbErr || !ddbRes || !ddbRes.Items) {
      console.error('DynamoDB Unauth/Login Alerts Scan Error:', ddbErr);
      setUnauthorizedEvents([]);
      setIsLoading(false);
      return;
    }

    const netAlerts = ddbRes.Items.filter(
      (item: any) => item.type === 'UNAUTHORIZED_ACCESS' || item.type === 'SUSPICIOUS_LOGIN'
    );

    const parsedEvents: UnauthorizedEvent[] = netAlerts.map((item: any) => {
      const isLogin = item.type === 'SUSPICIOUS_LOGIN';
      return {
        id: item.alertId || String(Math.random()),
        severity: (item.severity || 'HIGH') as Severity,
        description: item.detail || `Boundary breach alert of type "${item.type}"`,
        source: item.resource || 'unknown-origin',
        destination: isLogin ? 'AWS Console Sign-in' : 'Application Boundary Gateway',
        timestamp: item.timestamp || new Date().toISOString(),
        routeType: isLogin ? 'CF bypass' : 'Public IP',
        sourceIP: item.resource || '127.0.0.1',
        rawJson: JSON.stringify(item, null, 2)
      };
    });

    setUnauthorizedEvents(parsedEvents);
    setIsLoading(false);
  }, [setUnauthorizedEvents, setIsLoading, isMockMode]);

  // Initial load
  useEffect(() => {
    fetchUnauthEvents(false);
  }, [isMockMode]);

  // Explicit scan trigger (Run Scan clicked)
  useEffect(() => {
    if (scanTriggerCount > 0) {
      fetchUnauthEvents(true);
    }
  }, [scanTriggerCount]);

  return { refresh: () => fetchUnauthEvents(false) };
}

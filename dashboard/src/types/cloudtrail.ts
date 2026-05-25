import type { Severity } from '../constants/severity';

export interface CloudTrailEventIdentity {
  type: string;
  principalId?: string;
  arn?: string;
  userName?: string;
  accountId?: string;
  invokedBy?: string;
}

export interface CloudTrailRawEvent {
  eventVersion?: string;
  userIdentity: CloudTrailEventIdentity;
  eventTime: string;
  eventSource: string;
  eventName: string;
  awsRegion: string;
  sourceIPAddress: string;
  userAgent?: string;
  requestParameters?: Record<string, any>;
  responseElements?: Record<string, any>;
  additionalEventData?: Record<string, any>;
  eventID: string;
  eventType?: string;
  recipientAccountId?: string;
}

export interface ParsedLog {
  id: string;
  timestamp: string;
  eventName: string;
  eventSource: string;
  principalArn: string;
  sourceIP: string;
  severity: Severity;
  rawJson: string; // Keep full raw event JSON string
  awsRegion: string;
  isNew?: boolean; // For highlighting new logs
}

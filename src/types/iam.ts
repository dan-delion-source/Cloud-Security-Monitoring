import type { Severity } from '../constants/severity';

export interface IamAnomaly {
  id: string;
  severity: Severity;
  title: string;
  detail: string; // e.g., "ARN / event source"
  actionText: 'Investigate ↗' | 'Review ↗' | 'Remediate ↗' | 'Rotate ↗';
  pattern: string; // The rule key that was matched
  timestamp: string;
  resourceArn: string;
  rawEvent?: string; // Raw JSON event context
  rawJson?: string; // Standard raw JSON string representation
}

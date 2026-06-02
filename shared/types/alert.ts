/**
 * SecurityAlert — the canonical alert shape used by all backend Lambdas
 * when writing to DynamoDB and consumed by the React dashboard.
 */
export interface SecurityAlert {
  alertId: string;
  timestamp: string;
  type: 'PUBLIC_S3_BUCKET' | 'IAM_MISUSE' | 'UNAUTHORIZED_ACCESS' | 'SUSPICIOUS_LOGIN';
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  resource: string;
  detail: string;
  status: 'OPEN' | 'RESOLVED' | 'DISMISSED';
}

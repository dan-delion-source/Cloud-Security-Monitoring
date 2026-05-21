import type { Severity } from '../constants/severity';

export interface S3BucketChecks {
  blockPublicAcls: boolean;      // true if passing, false if failing
  blockPublicPolicy: boolean;    // true if passing, false if failing
  noPublicPolicyPrincipal: boolean; // true if passing, false if failing (no * principal)
  noPublicAcl: boolean;          // true if passing, false if failing (no PublicRead/PublicReadWrite)
  websiteDisabled: boolean;      // true if passing, false if failing (website disabled)
  sseKmsEnabled: boolean;        // true if using SSE-KMS (medium if SSE-S3, high/critical if none)
  versioningEnabled: boolean;    // true if versioning is on, false if off (low severity)
}

export interface S3BucketScanResult {
  id: string;
  name: string;
  severity: Severity;
  checks: S3BucketChecks;
  exposureDuration: string; // duration of potential exposure or creation age
  creationDate?: Date;
  region: string;
  encryptionType: 'SSE-KMS' | 'SSE-S3' | 'NONE';
  remediated: boolean;
}

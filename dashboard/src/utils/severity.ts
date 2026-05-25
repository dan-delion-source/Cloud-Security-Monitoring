import type { Severity } from '../constants/severity';

/**
 * Maps a GuardDuty severity float (0 - 10) to CloudSentinel's Severity
 */
export function getGuardDutySeverity(score: number): Severity {
  if (score >= 7.0) return 'CRITICAL';
  if (score >= 4.0) return 'HIGH';
  if (score >= 1.5) return 'MEDIUM';
  return 'LOW';
}

/**
 * Evaluates the severity of a CloudTrail event based on the specified detection rules
 */
export function evaluateLogSeverity(
  eventName: string,
  userIdentity: { type: string; arn?: string; accountId?: string } | null,
  eventSource: string,
  requestParams?: Record<string, any>
): Severity {
  const name = eventName || '';
  const source = eventSource || '';
  const identityType = userIdentity?.type || '';
  
  // Rule 1: CRITICAL - ConsoleLogin where userIdentity.type = Root
  if (name === 'ConsoleLogin' && identityType === 'Root') {
    return 'CRITICAL';
  }

  // GuardDuty check (handled elsewhere since GuardDuty outputs have numeric severity directly,
  // but if we receive custom event logs with severity, we map them)

  // Rule 2: HIGH - iam:PassRole + lambda:CreateFunction / ec2:RunInstances in same session is high/critical
  // (We check them individually as HIGH)
  if (name === 'PassRole' && source.includes('iam')) {
    return 'HIGH';
  }
  
  // sts:AssumeRole from unknown external account
  if (name === 'AssumeRole' && source.includes('sts')) {
    const roleArn = requestParams?.roleArn || '';
    const externalId = requestParams?.externalId;
    
    // In live system, we compare recipient account with caller account, if diff it's HIGH
    if (externalId && !roleArn.includes(userIdentity?.accountId || '')) {
      return 'HIGH';
    }
    return 'HIGH';
  }

  // s3:PutBucketPolicy setting public principal
  if (name === 'PutBucketPolicy' && source.includes('s3')) {
    const policy = requestParams?.bucketPolicy || '';
    if (policy.includes('"Principal": "*"') || policy.includes('"Principal":"*"') || policy.includes('*')) {
      return 'HIGH';
    }
  }

  // Rule 3: MEDIUM - iam:AttachUserPolicy, iam:CreatePolicyVersion, ssm:StartSession VPC endpoint absent, Config rule NON_COMPLIANT
  if (
    name === 'AttachUserPolicy' || 
    name === 'CreatePolicyVersion' ||
    name === 'AttachRolePolicy' ||
    name === 'AttachGroupPolicy'
  ) {
    return 'MEDIUM';
  }

  if (name === 'StartSession' && source.includes('ssm')) {
    // If VPC endpoint is absent (simulation or parsed request parameters)
    const hasVpcEndpoint = requestParams?.vpcEndpointId;
    if (!hasVpcEndpoint) {
      return 'MEDIUM';
    }
  }

  if (name.includes('Compliance') || name === 'PutEvaluations') {
    return 'MEDIUM';
  }

  // Rule 4: LOW - ec2:Describe*, s3:List*, iam:Get*, iam:List*
  if (
    name.startsWith('Describe') || 
    name.startsWith('List') || 
    name.startsWith('Get')
  ) {
    return 'LOW';
  }

  // Fallback default
  return 'LOW';
}

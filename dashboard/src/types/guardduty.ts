export interface GuardDutyResource {
  resourceType: string;
  accessKeyDetails?: {
    accessKeyId?: string;
    principalId?: string;
    userName?: string;
    userType?: string;
  };
  instanceDetails?: {
    instanceId?: string;
    instanceType?: string;
    networkInterfaces?: Array<{
      publicIp?: string;
      privateIp?: string;
      subnetId?: string;
      vpcId?: string;
    }>;
  };
}

export interface GuardDutyFinding {
  id: string;
  title: string;
  description: string;
  type: string;
  severity: number; // 0 to 10
  region: string;
  createdAt: string;
  resource: GuardDutyResource;
  rawJson?: string;
}

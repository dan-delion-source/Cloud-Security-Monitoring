export interface AwsRegion {
  id: string;
  name: string;
  location: string;
}

export const AWS_REGIONS: AwsRegion[] = [
  { id: 'us-east-1', name: 'US East (N. Virginia)', location: 'us-east-1' },
  { id: 'us-east-2', name: 'US East (Ohio)', location: 'us-east-2' },
  { id: 'us-west-1', name: 'US West (N. California)', location: 'us-west-1' },
  { id: 'us-west-2', name: 'US West (Oregon)', location: 'us-west-2' },
  { id: 'eu-west-1', name: 'Europe (Ireland)', location: 'eu-west-1' },
  { id: 'ap-southeast-1', name: 'Asia Pacific (Singapore)', location: 'ap-southeast-1' },
];

export const DEFAULT_REGION = 'us-east-1';

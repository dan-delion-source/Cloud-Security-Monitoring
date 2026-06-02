import { create } from 'zustand';
import type { Severity } from '../constants/severity';
import type { ParsedLog } from '../types/cloudtrail';
import type { S3BucketScanResult } from '../types/s3';
import type { IamAnomaly } from '../types/iam';

export interface UnauthorizedEvent {
  id: string;
  severity: Severity;
  description: string;
  source: string;
  destination: string;
  timestamp: string;
  rawJson: string;
  routeType: 'Public IP' | 'No VPC endpoint' | 'CF bypass' | 'Unauth invoke';
  sourceIP: string;
}

export interface SecurityAlert {
  id: string;
  severity: Severity;
  title: string;
  message: string;
  source: string;
  timestamp: string;
  dismissed: boolean;
}

interface SecurityState {
  logs: ParsedLog[];
  unauthorizedEvents: UnauthorizedEvent[];
  buckets: S3BucketScanResult[];
  iamAnomalies: IamAnomaly[];
  activeAlerts: SecurityAlert[];
  
  // Credentials and configuration state
  awsConfig: {
    accessKeyId: string;
    secretAccessKey: string;
    region: string;
  };
  isMockMode: boolean;

  // UI States
  isLoading: boolean;
  isScanning: boolean;
  lastScanTime: string | null;
  selectedEvent: { type: 'log' | 'unauth' | 'iam' | 's3'; data: any } | null;
  
  // Log Filters
  logFilter: 'ALL' | Severity;
  logSearchQuery: string;
  
  // Action triggers
  scanTriggerCount: number;
  
  // Actions
  setLogs: (logs: ParsedLog[]) => void;
  prependLogs: (newLogs: ParsedLog[]) => void;
  setUnauthorizedEvents: (events: UnauthorizedEvent[]) => void;
  setBuckets: (buckets: S3BucketScanResult[]) => void;
  remediateBucket: (bucketId: string) => void;
  setIamAnomalies: (anomalies: IamAnomaly[]) => void;
  setActiveAlerts: (alerts: SecurityAlert[]) => void;
  dismissAlert: (alertId: string) => void;
  
  setIsLoading: (loading: boolean) => void;
  setIsScanning: (scanning: boolean) => void;
  setSelectedEvent: (event: { type: 'log' | 'unauth' | 'iam' | 's3'; data: any } | null) => void;
  setLogFilter: (filter: 'ALL' | Severity) => void;
  setLogSearchQuery: (query: string) => void;
  
  // Connector actions
  updateAwsConfig: (config: { accessKeyId: string; secretAccessKey: string; region: string }) => void;
  toggleMockMode: () => void;
  triggerScan: () => void;
  resetStore: () => void;
  resetAll: () => void;
}

export const useSecurityStore = create<SecurityState>((set) => ({
  logs: [],
  unauthorizedEvents: [],
  buckets: [],
  iamAnomalies: [],
  activeAlerts: [],
  
  awsConfig: {
    accessKeyId: '',
    secretAccessKey: '',
    region: 'us-east-1'
  },
  isMockMode: false, // Sandbox mode active by default

  isLoading: false,
  isScanning: false,
  lastScanTime: null,
  selectedEvent: null,
  
  logFilter: 'ALL',
  logSearchQuery: '',
  
  scanTriggerCount: 0,
  
  setLogs: (logs) => set({ logs }),
  prependLogs: (newLogs) => set((state) => {
    // Prevent duplicates
    const existingIds = new Set(state.logs.map(l => l.id));
    const uniqueNewLogs = newLogs
      .filter(l => !existingIds.has(l.id))
      .map(l => ({ ...l, isNew: true } as ParsedLog));
      
    // Set isNew to false on old logs
    const updatedOldLogs = state.logs.map(l => ({ ...l, isNew: false } as ParsedLog));
    
    // Concat and limit to 1000 logs
    const allLogs = [...uniqueNewLogs, ...updatedOldLogs].slice(0, 1000);
    return { logs: allLogs };
  }),
  
  setUnauthorizedEvents: (unauthorizedEvents) => set({ unauthorizedEvents }),
  
  setBuckets: (buckets) => set({ buckets }),
  
  remediateBucket: (bucketId) => set((state) => ({
    buckets: state.buckets.map(b => 
      b.id === bucketId 
        ? { 
            ...b, 
            remediated: true, 
            severity: 'LOW' as Severity, // Demoted since it is now passing compliance
            checks: {
              blockPublicAcls: true,
              blockPublicPolicy: true,
              noPublicPolicyPrincipal: true,
              noPublicAcl: true,
              websiteDisabled: true,
              sseKmsEnabled: true,
              versioningEnabled: true
            },
            encryptionType: 'SSE-KMS' as const
          }
        : b
    )
  })),
  
  setIamAnomalies: (iamAnomalies) => set({ iamAnomalies }),
  
  setActiveAlerts: (activeAlerts) => set({ activeAlerts }),
  
  dismissAlert: (alertId) => set((state) => ({
    activeAlerts: state.activeAlerts.map(a => 
      a.id === alertId ? { ...a, dismissed: true } : a
    )
  })),
  
  setIsLoading: (isLoading) => set({ isLoading }),
  setIsScanning: (isScanning) => set({ isScanning, lastScanTime: new Date().toISOString() }),
  setSelectedEvent: (selectedEvent) => set({ selectedEvent }),
  
  setLogFilter: (logFilter) => set({ logFilter }),
  setLogSearchQuery: (logSearchQuery) => set({ logSearchQuery }),
  
  updateAwsConfig: (awsConfig) => set({ awsConfig }),
  toggleMockMode: () => set((state) => ({ isMockMode: !state.isMockMode })),
  
  triggerScan: () => set((state) => {
    // Self-healing timeout: automatically reset isScanning state to false after 2 seconds
    setTimeout(() => {
      set({ isScanning: false });
    }, 2000);
    return { 
      scanTriggerCount: state.scanTriggerCount + 1,
      isScanning: true 
    };
  }),
  
  resetStore: () => set({
    logs: [],
    unauthorizedEvents: [],
    buckets: [],
    iamAnomalies: [],
    activeAlerts: [],
    lastScanTime: null,
    selectedEvent: null,
    awsConfig: {
      accessKeyId: '',
      secretAccessKey: '',
      region: 'us-east-1'
    },
    isMockMode: true
  }),

  resetAll: () => set({
    logs: [],
    unauthorizedEvents: [],
    buckets: [],
    iamAnomalies: [],
    activeAlerts: [],
    lastScanTime: null,
    selectedEvent: null
  })
}));

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
  
  // Firewall / Remediation State
  blockedIps: string[];
  mutedEvents: string[];
  suspendedUsers: string[];
  remediatedAnomalies: string[];
  remediationLogs: Array<{ id: string; timestamp: string; action: string; target: string; status: 'SUCCESS' | 'FAILED' }>;

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
  selectedEvent: { type: 'log' | 'unauth' | 'iam' | 's3'; data: Record<string, unknown> } | null;
  
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
  setSelectedEvent: (event: { type: 'log' | 'unauth' | 'iam' | 's3'; data: Record<string, unknown> } | null) => void;
  setLogFilter: (filter: 'ALL' | Severity) => void;
  setLogSearchQuery: (query: string) => void;
  
  // Countermeasure actions
  blockIpAddress: (ip: string) => void;
  unblockIpAddress: (ip: string) => void;
  muteEventName: (eventName: string) => void;
  unmuteEventName: (eventName: string) => void;
  suspendIamUser: (userName: string) => void;
  unsuspendIamUser: (userName: string) => void;
  remediateAnomaly: (anomalyId: string) => void;
  addRemediationLog: (action: string, target: string, status: 'SUCCESS' | 'FAILED') => void;

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
  
  blockedIps: [],
  mutedEvents: [],
  suspendedUsers: [],
  remediatedAnomalies: [],
  remediationLogs: [],

  awsConfig: {
    accessKeyId: '',
    secretAccessKey: '',
    region: 'us-east-1'
  },
  isMockMode: true, // Sandbox mode active by default

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

  // Countermeasure implementation
  blockIpAddress: (ip) => set((state) => {
    if (state.blockedIps.includes(ip)) return {};
    const newLogs = [
      {
        id: `remedy-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`,
        timestamp: new Date().toISOString(),
        action: 'BLOCK_IP',
        target: ip,
        status: 'SUCCESS' as const
      },
      ...state.remediationLogs
    ];
    return {
      blockedIps: [...state.blockedIps, ip],
      remediationLogs: newLogs
    };
  }),

  unblockIpAddress: (ip) => set((state) => {
    const newLogs = [
      {
        id: `remedy-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`,
        timestamp: new Date().toISOString(),
        action: 'UNBLOCK_IP',
        target: ip,
        status: 'SUCCESS' as const
      },
      ...state.remediationLogs
    ];
    return {
      blockedIps: state.blockedIps.filter(item => item !== ip),
      remediationLogs: newLogs
    };
  }),

  muteEventName: (eventName) => set((state) => {
    if (state.mutedEvents.includes(eventName)) return {};
    const newLogs = [
      {
        id: `remedy-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`,
        timestamp: new Date().toISOString(),
        action: 'MUTE_EVENT',
        target: eventName,
        status: 'SUCCESS' as const
      },
      ...state.remediationLogs
    ];
    return {
      mutedEvents: [...state.mutedEvents, eventName],
      remediationLogs: newLogs
    };
  }),

  unmuteEventName: (eventName) => set((state) => {
    const newLogs = [
      {
        id: `remedy-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`,
        timestamp: new Date().toISOString(),
        action: 'UNMUTE_EVENT',
        target: eventName,
        status: 'SUCCESS' as const
      },
      ...state.remediationLogs
    ];
    return {
      mutedEvents: state.mutedEvents.filter(item => item !== eventName),
      remediationLogs: newLogs
    };
  }),

  suspendIamUser: (userName) => set((state) => {
    if (state.suspendedUsers.includes(userName)) return {};
    const newLogs = [
      {
        id: `remedy-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`,
        timestamp: new Date().toISOString(),
        action: 'SUSPEND_IAM_USER',
        target: userName,
        status: 'SUCCESS' as const
      },
      ...state.remediationLogs
    ];
    return {
      suspendedUsers: [...state.suspendedUsers, userName],
      remediationLogs: newLogs
    };
  }),

  unsuspendIamUser: (userName) => set((state) => {
    const newLogs = [
      {
        id: `remedy-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`,
        timestamp: new Date().toISOString(),
        action: 'RESTORE_IAM_USER',
        target: userName,
        status: 'SUCCESS' as const
      },
      ...state.remediationLogs
    ];
    return {
      suspendedUsers: state.suspendedUsers.filter(item => item !== userName),
      remediationLogs: newLogs
    };
  }),

  remediateAnomaly: (anomalyId) => set((state) => {
    if (state.remediatedAnomalies.includes(anomalyId)) return {};
    const newLogs = [
      {
        id: `remedy-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`,
        timestamp: new Date().toISOString(),
        action: 'REMEDIATE_ANOMALY',
        target: anomalyId,
        status: 'SUCCESS' as const
      },
      ...state.remediationLogs
    ];
    return {
      remediatedAnomalies: [...state.remediatedAnomalies, anomalyId],
      remediationLogs: newLogs
    };
  }),

  addRemediationLog: (action, target, status) => set((state) => ({
    remediationLogs: [
      {
        id: `remedy-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`,
        timestamp: new Date().toISOString(),
        action,
        target,
        status
      },
      ...state.remediationLogs
    ]
  })),
  
  updateAwsConfig: (awsConfig) => set({ awsConfig }),
  toggleMockMode: () => set((state) => {
    const next = !state.isMockMode;
    console.log(`[securityStore] toggleMockMode: ${state.isMockMode ? 'SANDBOX' : 'LIVE'} → ${next ? 'SANDBOX' : 'LIVE'}`);
    // Clear stale data so hooks re-populate from the correct source
    return {
      isMockMode: next,
      logs: [],
      unauthorizedEvents: [],
      buckets: [],
      iamAnomalies: [],
      activeAlerts: [],
    };
  }),
  
  triggerScan: () => {
    // Self-healing timeout: automatically reset isScanning state to false after 2 seconds
    // (Moved outside set() to avoid side-effects inside Zustand state setter)
    setTimeout(() => {
      useSecurityStore.setState({ isScanning: false });
    }, 2000);
    set((state) => ({
      scanTriggerCount: state.scanTriggerCount + 1,
      isScanning: true,
    }));
  },
  
  resetStore: () => set({
    logs: [],
    unauthorizedEvents: [],
    buckets: [],
    iamAnomalies: [],
    activeAlerts: [],
    blockedIps: [],
    mutedEvents: [],
    suspendedUsers: [],
    remediatedAnomalies: [],
    remediationLogs: [],
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
    blockedIps: [],
    mutedEvents: [],
    suspendedUsers: [],
    remediatedAnomalies: [],
    remediationLogs: [],
    lastScanTime: null,
    selectedEvent: null
  })
}));
